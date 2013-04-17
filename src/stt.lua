-- An experimental implementation of Stateless Transport Tunnel as described 
-- here: http://tools.ietf.org/html/draft-davie-stt-02

module(...,package.seeall)

local memory = require("memory")
local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
local lib = require("lib")
local bits, bitset, protected, unprotected, table_copy = lib.bits, lib.bitset, lib.protected, lib.unprotected, lib.table_copy
local crc = require("crc")

ffi.cdef[[

/* STT frame header */
struct stt_frame_hdr
{
	uint8_t  ver;    
	uint8_t  flags;    
	uint8_t  l4_ofs;    
	uint8_t  reserved;    
	uint16_t mss;    
	uint16_t vlan;    
	uint64_t ctx_id;    
	uint16_t padding;    
	//       data;       /* encapsulated Ethernet Frame */
} __attribute__((packed));  


/* STT segment header */
struct stt_seg_hdr
{
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t frag_ofs;    /* used by STT (TCP seq_num_L)*/
	uint16_t frame_len;   /* used by STT (TCP seq_num_H)*/
	uint32_t ack_num;     /* used by STT (const for each segment of an STT frame)*/
	uint8_t  data_ofs;    /* lower nibble */
	uint8_t  flags;       /* upper 6 bits (only? -XXX) */
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
	//       options;     /* variable size */
	//       data;        /* variable size */
} __attribute__((packed));


/* IPv6 header */
struct ipv6_hdr
{
	uint32_t ver_traf_flow;        
	uint16_t pay_len;        
	uint8_t  next_hdr;        
	uint8_t  hop_limit;        
	uint8_t  src_addr [16];        
	uint8_t  dst_addr [16];        
} __attribute__((packed));

/* 802.3 Ethernet frame header (without 802.1Q tag and FCS).
Note: use NIC's vlan tagging, FCS facility :-) */
struct eth_hdr
{
	uint8_t  dst_mac [6];
	uint8_t  src_mac [6];
	uint16_t type;
} __attribute__((packed));

/* [Ethernet + IPv6 + STT ("TCP-like")] frame headers */
struct frame_hdr
{
	struct eth_hdr      eth;
	struct ipv6_hdr     ipv6;
	struct stt_seg_hdr  seg;

} __attribute__((packed));

/* stt_tx_frame - for 1st descriptor */
struct stt_tx_frame
{
	struct frame_hdr     hdr;
	struct stt_frame_hdr stt_hdr;
} __attribute__((packed));

]]

function new()

	local M = {}

	---------------
	-- VARIABLES --
	---------------

	local STT_DST_PORT = 2013 --temporary; this will change as the draft evolves
	local HASH_ALGOS = { crc.crc14 } --XXX Add other hash functions as necessary

	M.ack = nil --current acknowledgement number (serves as identification)
	M.nic = nil --nic object from driver's new()
	M.tx  = { desc=nil, phy=nil, next=nil, total=nil, type="struct stt_tx_frame" } --[Eth+IP+TCP+STT frame header]
	M.opt = { eth = { src=nil, dst=nil }, 
			  ip  = { src=nil, dst=nil, vtf=nil, next=nil, hop=nil }, --vtf = ver + traffic + flow; next = next header
			  stt = { flag=nil, mss=nil, vlan=nil, ctx=nil } 
		    }
	M.flow = nil --'encapsulated' packet flow
	M.get_random_hash = nil --see init()

	---------------
	-- FUNCTIONS --
	---------------

	--Initialization function
	--options: dictionary containing default values for Eth/IP/STT headers, tx/rx descriptor count
	function M.init(options)
		assert(options, "Need options dic")
		M.ack = 0
		M.nic = options.nic or assert(false, "stt.lua:: init: options.nic required")

		M.tx.total = options.tx_total or 10 --total num of descriptors
		M.tx.desc, M.tx.phy = memory.dma_alloc(M.tx.total * ffi.sizeof(M.tx.type))
		M.tx.desc = protected(M.tx.type, M.tx.desc, 0, M.tx.total)
		M.tx.next = 0

		local opt_eth, opt_ip, opt_stt = options.eth or {}, options.ip or {}, options.stt or {}

		M.opt.eth.src  = opt_eth.src 
		M.opt.eth.dst  = opt_eth.dst 
		M.opt.ip.src   = opt_ip.src  
		M.opt.ip.dst   = opt_ip.dst  
		M.opt.ip.vtf   = opt_ip.vtf  
		M.opt.ip.next  = opt_ip.next
		M.opt.ip.hop   = opt_ip.hop
		M.opt.stt.flag = opt_stt.flag  
		M.opt.stt.mss  = opt_stt.mss    
		M.opt.stt.vlan = opt_stt.vlan   
		M.opt.stt.ctx  = opt_stt.ctx 

		M.flow = {}
		math.randomseed( tonumber(tostring(os.time()):reverse():sub(1,6)) ) --http://lua-users.org/wiki/MathLibraryTutorial
		M.get_random_hash = HASH_ALGOS[ math.random(1, #HASH_ALGOS) ] --transmit() needs the same hash fn between calls
	   																  --to maintain correct 'encapsulated' packet flow
	end

	--M.init()

	-- Transmit the given packet using STT
	-- pkt: encapsulated packet options - dictionary containing following:
	--      mem: is of type ffi.cast("uint8_t *", ..., size); -- Read-only
	--      phy: is the physical address of the packet buffer (passed to nic)
	--      size: is the size of the packet
	-- options: [optional if configured in init()] 
	function M.transmit(pkt, options)
		assert(pkt and pkt.mem and pkt.phy and pkt.size, "pkt is invalid")
		assert(pkt.size <= 65444, "pkt.size must be <= 65444") --max supported pkt.size is (2^16) - (14 + 40 + 20 + 18)

		local opt_eth, opt_ip, opt_stt = options.eth or {}, options.ip or {}, options.stt or {}

		M.opt.eth.src  = opt_eth.src  or M.opt.eth.src  or assert(false, "opt_eth.src invalid")
		M.opt.eth.dst  = opt_eth.dst  or M.opt.eth.dst  or assert(false, "opt_eth.dst invalid")
		M.opt.ip.src   = opt_ip.src   or M.opt.ip.src   or assert(false, "opt_ip.src invalid")
		M.opt.ip.dst   = opt_ip.dst   or M.opt.ip.dst   or assert(false, "opt_ip.dst invalid")
		M.opt.ip.vtf   = opt_ip.vtf   or M.opt.ip.vtf   or 0x60 --version
		M.opt.ip.next  = opt_ip.next  or M.opt.ip.next  or 0x06
		M.opt.ip.hop   = opt_ip.hop   or M.opt.ip.hop   or 0x40
		M.opt.stt.flag = opt_stt.flag or M.opt.stt.flag or bits{cs_partial=1} --if TSO used, set cs_partial bit
		M.opt.stt.mss  = opt_stt.mss  or M.opt.stt.mss  or 1422 --1500 - (14 + 40 + 20) - 4
		M.opt.stt.vlan = opt_stt.vlan or M.opt.stt.vlan 
		M.opt.stt.ctx  = opt_stt.ctx  or M.opt.stt.ctx  or 0
		print("DBG: transmit: vtf = "..bit.tohex(tonumber(M.opt.ip.vtf)))
		assert(M.opt.eth.src:len() == 6, "eth.src should have length 6")
		assert(M.opt.eth.dst:len() == 6, "eth.dst should have length 6")
		assert(M.opt.ip.src:len() == 16, "ip.src should have length 16") 
		assert(M.opt.ip.dst:len() == 16, "ip.dst should have length 16") 

		local pm = protected("uint8_t", pkt.mem, 0, 78) --14 + 60 + 4 [Max: eth + ipv4 + tcp/udp ports] 
--		for i=0, 77 do print("DBG: transmit: pm["..tostring(i).."] = "..bit.tohex(tonumber(pm[i]))) end
		local ver = bit.band(pm[14], 0x60) --version 14 + 0
		local proto = nil
		local ip_hdr_len = nil
		local src_addr_off = nil
		local addr_len  = nil
		local hash = M.get_random_hash()

		for i=1, 6 do
		  M.tx.desc[M.tx.next].hdr.eth.dst_mac[i-1] = M.opt.eth.dst:byte(i) 
		  M.tx.desc[M.tx.next].hdr.eth.src_mac[i-1] = M.opt.eth.src:byte(i) 
		end

		M.tx.desc[M.tx.next].hdr.ipv6.ver_traf_flow = M.opt.ip.vtf
		M.tx.desc[M.tx.next].hdr.ipv6.next_hdr   = M.opt.ip.next
		M.tx.desc[M.tx.next].hdr.ipv6.hop_limit     = M.opt.ip.hop

		for i=1, 16 do
		  M.tx.desc[M.tx.next].hdr.ipv6.dst_addr[i-1] = M.opt.ip.dst:byte(i) 
		  M.tx.desc[M.tx.next].hdr.ipv6.src_addr[i-1] = M.opt.ip.src:byte(i) 
		end
		
		M.tx.desc[M.tx.next].stt_hdr.flags  = M.opt.stt.flag 
		M.tx.desc[M.tx.next].stt_hdr.mss    = M.opt.stt.mss
		if M.opt.stt.vlan then
			M.tx.desc[M.tx.next].stt_hdr.vlan   = bit.band( bit.bor(bit.lshift(M.opt.stt.vlan.pcp, 13), 
																	bit.lshift(M.opt.stt.vlan.cfi, 12),
																	M.opt.stt.vlan.vid),
															0xffff)
		else
			M.tx.desc[M.tx.next].stt_hdr.vlan = 0
		end
		M.tx.desc[M.tx.next].stt_hdr.ctx_id = M.opt.stt.ctx 

		print("DBG: transmit: ver = 0x"..bit.tohex(tonumber(ver)))

		if ver == 0x40 then      --IPv4
			proto = pm[23]     --14 + 9
			M.tx.desc[M.tx.next].stt_hdr.flags  = bits({ipv4=2}, M.tx.desc[M.tx.next].stt_hdr.flags)
			ip_hdr_len = 14 + 4 * bit.band(pm[14], 0x0f) --IHL field
			src_addr_off = 12 --octets
			addr_len = 4 --octets

		elseif ver == 0x60 then  --IPv6
			proto = pm[20]        --14 + 6
			ip_hdr_len = 54       --14 + 40
			src_addr_off = 8 --octets
			addr_len = 16 --octets
		else
			assert(false, "Invalid encapsulated packet")
		end

		M.tx.desc[M.tx.next].stt_hdr.l4_ofs = ip_hdr_len

		if proto == 0x06 then --TCP
			M.tx.desc[M.tx.next].stt_hdr.flags = bits({tcp=3}, M.tx.desc[M.tx.next].stt_hdr.flags)
		--else hopefully some other valid protocol
		end

		for i=0, 3 do
			hash.add_byte(pm[ip_hdr_len + i]) --TCP/UDP source and dest ports (first 4 bytes of IP payload)
		end
		
		for i=0, 2*addr_len-1 do --IP source, dest addresses
			hash.add_byte(pm[src_addr_off + i])
		end

		M.tx.desc[M.tx.next].hdr.seg.src_port = 49152 + hash.generate() --generate a 14-bit hash
		M.tx.desc[M.tx.next].hdr.seg.dst_port = STT_DST_PORT
		M.tx.desc[M.tx.next].hdr.seg.frame_len = 18 + pkt.size --stt frame header + encapsulated packet
		M.tx.desc[M.tx.next].hdr.seg.ack_num = M.ack
		M.tx.desc[M.tx.next].hdr.seg.data_ofs = 0x50 --5 words(20 bytes)
		M.tx.desc[M.tx.next].hdr.seg.flags = bits{ack=4}

		M.tx.desc[M.tx.next].hdr.ipv6.pay_len = 20 + 18 + pkt.size --TCP-like header + stt frame header + encapsulated packet

		local descriptors = { { address = M.tx.phy, size = ffi.sizeof(M.tx.type) }, --Eth + IPv6 + TCP + STT frame header
						 	  { address = pkt.phy,  size = pkt.size }               --Encapsulated packet
					  		}
		local size = descriptors[1].size + descriptors[2].size
		local context = M.tx.desc._ptr + M.tx.next * descriptors[1].size

		M.nic.add_txbuf_tso( descriptors, size, M.opt.stt.mss, context, M.opt.stt.vlan )

		M.nic.flush_tx()
		C.usleep(2000000) -- 2 sec wait
		--M.nic.wait_tx(size) --wait for transmission
		M.nic.clear_tx()

		M.ack = (M.ack + 1) % 0x10000 --2^16
		M.tx.next = (M.tx.next + 1) % M.tx.total
	end

	--Receive a "big" packet using STT
	--Return an array of completed STT frames. 
	-- for e,g,: { {  { addrs={ phy=0x1234ABCD, mem=0xDCBA4321 }, size=1234 },  
	-- 				  { addrs={...}, size=...} 
	-- 				  --chunks that make up stt_frame_header + encapsulated packet
	-- 			   },
	-- 			   {  { addrs={...}, size=... }, 
	-- 			      { addrs={...}, size=... }
	-- 			   }
	-- 			 }
	local function receive_fn()
		while true do
			local frames = {}
			while nic.rx_unread() do --if there are unread packets
				local addr, wb = nic.receive()--read an unread rx packet
				assert(addr and wb, "Expected a packet -- check driver code?")

				if wb.valid and wb.ipv6 and wb.tcp and wb.eop then --XXX non-eop (multi desc)
					local pkt = unprotected("struct frame_hdr", addr.mem)
					assert(pkt.eth.type == 0x86DD and 
						   bit.band(pkt.ipv6.ver_traf_flow, 0xf0000000) == 0x60000000 and
						   pkt.ipv6.next_hdr == 0x06,
						   "Only Eth + IPv6 + TCP(STT) supported -- invalid wb.status check driver code?")

					local dst=true
					local i=1
					--check destination MAC
					while dst do
						if pkt.eth.dst_mac[i-1] ~= M.opt.eth.src:byte(i) then dst = false end
						i = i + 1
					end
					--check destination IP
					i=1
					while dst do
						if pkt.ipv6.dst_addr[i-1] ~= M.opt.ip.src:byte(i) then dst = false end
						i = i + 1
					end
					--check destination TCP port
					dst = dst and (pkt.seg.dst_port == STT_DST_PORT)

					--XXX gotta trust other fields for the time being
					
					if dst then
						local key = {}
						for i=1, 4 do
							key[1 + #key] = bit.tohex( unprotected("uint32_t", pkt.ipv6.src_addr)[i-1] )
						end
						key[1 + #key] = "|" --seperator
						key[1 + #key] = bit.tohex(pkt.seg.src_port)
						key = table.concat(key) --generate the final string

						local ack = pkt.seg.ack_num
						local new_flow = false

						if M.flow[key] ~= nil then
							if M.flow[key].ack ~= ack then --discard old flow and generate a new one
								M.flow[key] = nil
								new_flow = true
							end
						else
							new_flow = true	
						end --else M.flow[key]	

						local hsize = ffi.sizeof("struct frame_hdr")
						local psize = wb.length - hsize
						local pkt_added = false

						if new_flow then
							if pkt.seg.frag_ofs == 0 then --otherwise some packets presumed lost
								M.flow[key] = { ack=ack,
												total_len=pkt.seg.frame_len,
												cur_len=psize,
												chunks={ { addrs={ phy=addr.phy + hsize, mem=addr.mem + hsize },
														   size=psize
														 }
													   }
											  }
								pkt_added = true
							end
						else --add chunk
							if (M.flow[key].cur_len + psize <= M.flow[key].total_len) and
							   (M.flow[key].total_len == pkt.seg.frame_len) and
							   (M.flow[key].cur_len == pkt.seg.frag_ofs) then
								M.flow[key].chunks[1 + #(M.flow[key].chunks)] = { addrs={ phy=addr.phy + hsize, 
																						  mem=addr.mem + hsize 
																						},
																				  size=psize
																				}
								M.flow[key].cur_len = M.flow[key].cur_len + psize
								pkt_added = true
							end
						end --else new_flow
						
						if pkt_added and (M.flow[key].total_len == M.flow[key].cur_len) then --complete STT frame
							frames[1 + #frames] = table_copy(M.flow[key].chunks)
							M.flow[key] = nil
						end
					end--if dst
				end --if wb.valid
			end --while nic.rx_unread()

			coroutine.yield(frames)

		end --while true
	end --function receive_fn()
	M.receive = coroutine.wrap(receive_fn)

	-- A simple STT selftest
	function M.selftest()
		assert(M.nic)
		test.waitfor("linkup", M.nic.linkup, 20, 250000)
		M.nic.enable_mac_loopback()
		local size = 4096	--4KB packet
		local buf, buf_phy = memory.dma_alloc(size) 
		buf = protected("uint8_t", buf, 0, size)

		                    --Ethernet+IPv6+TCP headers
		local tx_header = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x86, 0xDD, 0x60, 0x00,
						    0x00, 0x00, 0x0F, 0xCA, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xE4, 0x2B, 0x00, 0x00 }
		
		for i=1, #tx_header do
			buf[i-1] = tx_header[i] --byte copy
		end

		for j=#tx_header, size-1 do
			buf[j] = 0x41 --char 'A'
		end

		local pkt = { mem=buf._ptr, phy=buf_phy, size=size }
		local options = { eth={ src="\x01\x01\x01\x01\x01\x01", 
								dst="\x02\x02\x02\x02\x02\x02" 
							  },
						   ip={ src="\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03",
						   	    dst="\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04" 
						      } 
						}

		print("stt.selftest - Before Transmit - nic statistics")
		M.nic.print_stats()
		M.transmit(pkt, options)
		M.nic.update_stats()
		print("stt.selftest - After Transmit - nic statistics")
		M.nic.print_stats()

	end --function M.selftest()
	return M

end --function new
----------------------------------------------------------------------------------------------------------------------------
--					local pkt_count = 0 --num of rx packets that make up the "big" packet
--					local buf_used = 0
--					local big_pkt = nil
--					local start_addr = nil
--					local big_pkt_paylen = 0 -- payload length of "big" packet
--
--					if not (wb.valid and wb.ipv6 and wb.tcp and wb.eop) then --invalid status for Eth+IPv6+TCP --XXX non-eop
--						coroutine.yield(nil, "skipping invalid packet") --skip this packet
--
--					else
--						local pkt = unprotected("struct frame_hdr", addr.mem)
--						assert(pkt.eth.type == 0x86DD and 
--							   bit.band(pkt.ipv6.ver_traf_flow, 0xf0000000) == 0x60000000 and
--							   pkt.ipv6.next_hdr == 0x06,
--							   "Only Eth + IPv6 + TCP(STT) supported -- invalid wb.status check in driver?")
--						
--						local cp_offset, cp_length = 0, 0 --copy parameters
--						
--						if pkt_count = 0 then --first rx packet
--							start_addr = nic.rxbuffers[nic.rxnext]
--							cp_length = nic.rxdesc[nic.rxnext].wb.length
--							big_pkt = unprotected("struct frame_hdr", buf_address)
--
--						elseif not match_packets(pkt, big_pkt, big_pkt_paylen) then
--							break --out of while loop
--
--						else
--							cp_offset = ffi.sizeof(ffi.typeof("struct frame_hdr")) --skip the current packet's headers
--							assert(pkt.ipv6.pay_len == (nic.rxdesc[nic.rxnext].wb.length - cp_offset),
--								   "payload lengths are not matching")
--							cp_length = nic.rxdesc[nic.rxnext].wb.length - cp_offset
--						end
--
--						assert( (buf_size - buf_used -1) >= cp_length, "Insufficient buffer size") --1 byte for padding
--						ffi.copy(buf_address + buf_used, nic.rxbuffers[nic.rxnext] + cp_offset, cp_length)
--						buf_used = buf_used + cp_length
--
--						big_pkt_paylen = big_pkt_paylen + pkt.ipv6.pay_len
--						nic.rxnext = (nic.rxnext + 1) % nic.num_descriptors
--						pkt_count = pkt_count + 1
--					end --if else nic.rxdesc[nic.rxnext].wb.status
--				end --while loop
--
--				pkt = unprotected("struct frame_hdr", start_addr) --access big packet
--				pkt.ipv6.pay_len = big_pkt_paylen --set its payload length
--				pkt.seg.checksum = 0
--
--				---- CHECKSUM ---
--
--				local wpkt  = unprotected("uint16_t", start_addr, frame_len) --16-bit word access for checksum calculation
--				local addrs = unprotected("uint16_t", start_addr, 8) --16-bit word access to addresses
--				local checksum = 0
--				
--				for i=0, 15 do --src and dest addrs
--					checksum = checksum + addrs[i]
--				end
--
--				checksum = checksum + pkt.ipv6.next_hdr + pkt.ipv6.pay_len
--			
--				unprotected("uint8_t", start_addr, frame_len + 40 + pkt.ipv6.paylen)[0] = 0x00 --padding if seg len is odd
--
--				for i=0, math.ceil(pkt.ipv6.pay_len / 2) do --TCP header + text
--					checksum = checksum + wpkt[i]
--				end
--				
--				checksum = bit.bor(bit.rshift(checksum, 16), bit.band(checksum, 0xffff))
--				checksum = checksum + bit.rshift(checksum, 16)
--				pkt.seg.checksum = checksum
--
--				return buf_used, pkt_count
--			end --if (nic.rx_empty) else
--	end
--	M.receive = coroutine.wrap(receive_fn)
--
--	return M
--
--end --function new
--
--	--match two Eth + IPv6 + TCP packet headers
--	--Parameters: a, b of type: unprotected("struct frame_hdr", ...)
--	--            exp_frame_len: expected value in a's frame_len TCP(STT) header
--	--Returns: true if relevant headers match
--	--         false otherwise
--	function M.match_headers(a, b, exp_frame_len)
--		
--		--check ethernet headers --XXX alternatively use memcmp?
--		for i=0, 5 do
--			if (a.eth.dst_mac[i] ~= b.eth.dst_mac[i]) or (a.eth.src_mac[i] ~= b.eth.src_mac[i]) then
--				return false
--			end
--		end
--		if a.eth.type ~= b.eth.type then return false end 
--
--		--check ipv6 headers
--		if a.ipv6.ver_traf_flow ~= b.ipv6.ver_traf_flow or
--		   a.ipv6.next_hdr      ~= b.ipv6.next_hdr      or --skip ipv6.pay_len
--		   a.ipv6.hop_limit     ~= b.ipv6.hop_limit     then
--		   return false
--		end
--
--		for i=0, 15 do
--			if (a.ipv6.src_addr[i] ~= b.ipv6.src_addr[i]) or (a.ipv6.dst_addr[i] ~= b.ipv6.dst_addr[i]) then
--				return false
--			end
--		end
--
--		--check TCP headers
--		if a.seg.src_port  ~= b.seg.src_port or
--		   a.seg.dst_port  ~= b.seg.dst_port or
--		   a.seg.frag_ofs  ~= b.seg.frag_ofs or
--		   a.seg.frame_len ~= exp_frame_len  or
--		   a.seg.ack_num   ~= b.seg.ack_num  then
--		   return false
--		end
--
--		return true --all "relevant" headers matched :-)
--	end


