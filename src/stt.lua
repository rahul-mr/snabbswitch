-- An experimental implementation of Stateless Transport Tunnel as described 
-- here: http://tools.ietf.org/html/draft-davie-stt-02

module(...,package.seeall)

local memory = require("memory")
local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
local lib = require("lib")
local bits, bitset, protected, unprotected = lib.bits, lib.bitset, lib.protected, lib.unprotected 
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
	uint16_t frame_len;   /* used by STT (TCP seq_num_H)*/
	uint16_t frag_ofs;    /* used by STT (TCP seq_num_L)*/
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
		M.get_random_hash = HASH_ALGOS[ math.random(1, #HASH_ALGOS) ] --enqueue() needs the same hash fn between calls
	   																  --to maintain correct 'encapsulated' packet flow
	end

	--M.init()
	local function bswap16(n)
		return bit.bor( bit.lshift(bit.band(n, 0xff), 8), 
				 		bit.rshift(bit.band(n, 0xff00), 8) )
	end

	-- Enqueue the given packet for transmission
	-- pkt: encapsulated packet options - dictionary containing following:
	--      mem: is of type ffi.cast("uint8_t *", ..., size); -- Read-only
	--      phy: is the physical address of the packet buffer (passed to nic)
	--      size: is the size of the packet
	-- options: [optional if configured in init()] 
	function M.enqueue(pkt, options)
		assert(pkt and pkt.mem and pkt.phy and pkt.size, "pkt is invalid")
		assert(pkt.size <= 65444, "pkt.size must be <= 65444") --max supported pkt.size is (2^16) - (14 + 40 + 20 + 18)

		local opt_eth, opt_ip, opt_stt = options.eth or {}, options.ip or {}, options.stt or {}

		M.opt.eth.src  = opt_eth.src  or M.opt.eth.src  or assert(false, "opt_eth.src invalid")
		M.opt.eth.dst  = opt_eth.dst  or M.opt.eth.dst  or assert(false, "opt_eth.dst invalid")
		M.opt.ip.src   = opt_ip.src   or M.opt.ip.src   or assert(false, "opt_ip.src invalid")
		M.opt.ip.dst   = opt_ip.dst   or M.opt.ip.dst   or assert(false, "opt_ip.dst invalid")
		M.opt.ip.vtf   = opt_ip.vtf   or M.opt.ip.vtf   or { ver=0x6, tc=0x00, fl=0x00 }
		M.opt.ip.next  = opt_ip.next  or M.opt.ip.next  or 0x06
		M.opt.ip.hop   = opt_ip.hop   or M.opt.ip.hop   or 0x40
		M.opt.stt.flag = opt_stt.flag or M.opt.stt.flag or bits{cs_partial=1} --if TSO used, set cs_partial bit
		M.opt.stt.mss  = opt_stt.mss  or M.opt.stt.mss  or 1422 --1500 - (14 + 40 + 20) - 4
		M.opt.stt.vlan = opt_stt.vlan or M.opt.stt.vlan 
		M.opt.stt.ctx  = opt_stt.ctx  or M.opt.stt.ctx  or 0
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

		M.tx.desc[M.tx.next].hdr.eth.type = bswap16(0x86dd)

		M.tx.desc[M.tx.next].hdr.ipv6.ver_traf_flow = bit.bswap( bit.bor( bit.lshift(M.opt.ip.vtf.ver, 28),
																    	  bit.lshift(M.opt.ip.vtf.tc,  20),
																		  M.opt.ip.vtf.fl ) )
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

		print("DBG: src_port = "..tostring(49152 + hash.generate()).." AKA 0x"..bit.tohex(49152 + hash.generate()))
		print("DBG: frame_len = "..tostring(18 + pkt.size).." AKA 0x"..bit.tohex(18 + pkt.size))
		M.tx.desc[M.tx.next].hdr.seg.src_port = bswap16(49152 + hash.generate()) --generate a 14-bit hash
		M.tx.desc[M.tx.next].hdr.seg.dst_port = bswap16(STT_DST_PORT)
		M.tx.desc[M.tx.next].hdr.seg.frame_len = bswap16(18 + pkt.size) --stt frame header + encapsulated packet
		M.tx.desc[M.tx.next].hdr.seg.ack_num = bit.bswap(M.ack)
		M.tx.desc[M.tx.next].hdr.seg.data_ofs = 0x50 --5 words(20 bytes)
		M.tx.desc[M.tx.next].hdr.seg.flags = bits{ack=4}

		M.tx.desc[M.tx.next].hdr.ipv6.pay_len = bswap16(20 + 18 + pkt.size) --TCP-like header + stt frame header + encapsulated packet

		local descriptors = { { address = M.tx.phy + (M.tx.next * ffi.sizeof(M.tx.type)), --XXX correct mapping to phy?
								size = ffi.sizeof(M.tx.type) --Eth + IPv6 + TCP + STT frame header
							  }, 
						 	  { address = pkt.phy,  size = pkt.size }               --Encapsulated packet
					  		}
		local size = descriptors[1].size + descriptors[2].size
		--local context = M.tx.desc._ptr + (M.tx.next * descriptors[1].size)

		print("DBG: stt: transmit: size = "..tostring(size))
		print("DBG: stt: transmit: descriptors[1].size = "..tostring(descriptors[1].size))
		--local dctx = protected("uint8_t", context, 0, descriptors[1].size)
		local context = unprotected("uint8_t", M.tx.desc._ptr, (M.tx.next * descriptors[1].size ) )
		print("context = ", context)
		print("M.tx.next = ", M.tx.next)
		print("M.tx.desc._ptr = ", M.tx.desc._ptr)
--		print("M.tx.desc._ptr + descriptors[1].size = ", M.tx.desc._ptr + descriptors[1].size)
--		print("M.tx.desc._ptr + 2*descriptors[1].size = ", M.tx.desc._ptr + 2*descriptors[1].size)
--
--		--print("dctx1 = ", dctx + descriptors[1].size)
--		--print("dctx2 = ", dctx + descriptors[2].size)
--
--		print()
--		for i=0,  descriptors[1].size - 1 do
--			io.write("0x"..bit.tohex(tonumber(context[i]))..", ")
--			--if((i+1)%(descriptors[1].size)==0) then print(); print(); end
--		end
--		print()

		M.nic.add_txbuf_tso( descriptors, size, M.opt.stt.mss, context, M.opt.stt.vlan )

		M.ack = (M.ack + 1) % 0x10000 --2^16
		M.tx.next = (M.tx.next + 1) % M.tx.total
	end

	--transmit (flush) the queued packets and wait for 'usecs' microseconds
	function M.transmit(usecs)
		usecs = usecs or 250000 --250ms
		M.nic.flush_tx()
		C.usleep(usecs)
		--M.nic.wait_tx(size) --wait for transmission
		M.nic.clear_tx()
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
			while M.nic.rx_unread() do --if there are unread packets
				print("DBG: receive_fn: Enter while M.nic.rx_unread()")
				local addr, wb = M.nic.receive()--read an unread rx packet
				assert(addr and wb, "Expected a packet -- check driver code?")

				if wb.valid and wb.ipv6 and wb.tcp and wb.eop then --XXX non-eop (multi desc)
					print("DBG: receive_fn: Enter if wb.valid and wb.ipv6 and wb.tcp and wb.eop")
					local pkt = unprotected("struct frame_hdr", addr.mem)
					assert(bswap16(pkt.eth.type) == 0x86DD and 
						   bit.band(bit.bswap(pkt.ipv6.ver_traf_flow), 0xf0000000) == 0x60000000 and
						   pkt.ipv6.next_hdr == 0x06,
						   "Only Eth + IPv6 + TCP(STT) supported -- invalid wb.status check driver code?")

					local dst=true
					local i=1
					--check destination MAC
					while dst and i<=6 do
--						print("pkt.eth.dst_mac[i-1]", pkt.eth.dst_mac[i-1], "M.opt.eth.src:byte(i)", M.opt.eth.src:byte(i))
						if pkt.eth.dst_mac[i-1] ~= M.opt.eth.src:byte(i) then dst = false end
						i = i + 1
					end
					--check destination IP
					i=1
					while dst and i<=16 do
--						print("pkt.ipv6.dst_addr[i-1]", pkt.ipv6.dst_addr[i-1], "M.opt.ip.src:byte(i)",M.opt.ip.src:byte(i))
						if pkt.ipv6.dst_addr[i-1] ~= M.opt.ip.src:byte(i) then dst = false end
						i = i + 1
					end
					--check destination TCP port
					dst = dst and (bswap16(pkt.seg.dst_port) == STT_DST_PORT)

					--XXX gotta trust other fields for the time being
					print("DBG: receive_fn: dst => ", dst)
					
					if dst then
						print("DBG: receive_fn: if dst")
						local key = {}
						local src_addr = unprotected("uint32_t", pkt.ipv6.src_addr)
						for i=0, 3 do
							key[1 + #key] = bit.tohex( bit.bswap(src_addr[i]) )
						end
						key[1 + #key] = "|" --seperator
						key[1 + #key] = bit.tohex( bswap16(pkt.seg.src_port) )
						key = table.concat(key) --generate the final string

						local ack = bit.bswap(pkt.seg.ack_num)
						local new_flow = false

						if M.flow[key] ~= nil then
							if M.flow[key].ack ~= ack then --discard old flow and generate a new one
								print("DBG: receive_fn: discarding old flow")
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
							print("DBG: receive_fn: if new_flow")
							if pkt.seg.frag_ofs == 0 then --otherwise some packets presumed lost
								print("DBG: receive_fn: if pkt.seg.frag_ofs == 0")
								M.flow[key] = { ack=ack,
												total_len=bswap16(pkt.seg.frame_len),
												cur_len=psize,
												chunks={ { addrs={ phy=addr.phy + hsize, mem=addr.mem + hsize },
														   size=psize
														 }
													   }
											  }
								pkt_added = true
							end
						else --add chunk
							print("DBG: receive_fn: oldflow")

							if (M.flow[key].cur_len + psize <= M.flow[key].total_len) and
							   (M.flow[key].total_len == bswap16(pkt.seg.frame_len)) and
							   (M.flow[key].cur_len == bswap16(pkt.seg.frag_ofs)) then
								M.flow[key].chunks[1 + #(M.flow[key].chunks)] = { addrs={ phy=addr.phy + hsize, 
																						  mem=addr.mem + hsize 
																						},
																				  size=psize
																				}
								print("DBG: receive_fn: add chunk (pkt_added = true)")

								M.flow[key].cur_len = M.flow[key].cur_len + psize
								pkt_added = true
							end
						end --else new_flow
						
						if pkt_added and (M.flow[key].total_len == M.flow[key].cur_len) then --complete STT frame
							print("DBG: receive_fn: completed stt frame")
							frames[1 + #frames] = M.flow[key].chunks
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
		local tx_size = 4096	--4KB packets
		local rx_size = 4096
		local chunk_count = 3 --num of expected chunks for each "big" packet
		local repetitions = 5 --num of times the "big" packet is transmitted during this selftest
		local tx_buf, tx_buf_phy = memory.dma_alloc(tx_size) 
		local rx_buf, rx_buf_phy = memory.dma_alloc(rx_size * chunk_count * repetitions) 
		tx_buf = protected("uint8_t", tx_buf, 0, tx_size)

		print("DBG: rx_buf_phy => ", rx_buf_phy, rx_buf_phy==false)
		print("DBG: rx_buf => ", rx_buf, rx_buf==nil)

		local rx_buf_tail = 0
		for i=1, chunk_count * repetitions do
			print("DBG: rx: phy =>", rx_buf_phy + rx_buf_tail, "buf =>", rx_buf + rx_buf_tail)
			M.nic.add_rxbuf( rx_buf_phy + rx_buf_tail, rx_buf + rx_buf_tail )
			rx_buf_tail = rx_buf_tail + rx_size
		end
		M.nic.flush_rx()

		                    --Ethernet+IPv6+TCP headers
		local tx_header = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x86, 0xDD, 0x60, 0x00,
						    0x00, 0x00, 0x0F, 0xCA, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xE4, 0x2B, 0x00, 0x00 }
		
		for i=1, #tx_header do
			tx_buf[i-1] = tx_header[i] --byte copy
		end

		for j=#tx_header, tx_size-1 do
			tx_buf[j] = 0x41 --char 'A'
		end

		local pkt = { mem=tx_buf._ptr, phy=tx_buf_phy, size=tx_size }
		local options = { eth={ src="\x01\x02\x03\x04\x05\x06", 
								dst="\x01\x02\x03\x04\x05\x06" 
							  },
						   ip={ src="\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 
						   	    dst="\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff" 
						      } 
						} --Note: src and dst are same since this is a loopback test

		for t=1, repetitions do
			M.enqueue(pkt, options)
		end

		M.transmit(1000000) --block
		M.nic.update_stats()
		print("stt.selftest - After Transmitting : "..tostring(repetitions).." big packets - nic statistics")
		M.nic.print_stats()

		local frames = M.receive()
		print("frames = ", frames)
		print("#frames = ", #frames)

		assert(#frames == repetitions)
		
		for f=1, repetitions do
			assert(#(frames[f]) == chunk_count)
			for c=1, chunk_count-1 do
				assert(frames[f][c].size == 1422)
			end
			assert(frames[f][chunk_count].size == 18 + tx_size - (chunk_count-1)*1422 ) --last chunk
		end

		for f=1, #frames do --each frame

			local cur_pos = -18 --to skip the STT frame header

			for c=1, #(frames[f])	do --each chunk
				print("\nDBG: frame #"..tostring(f).." chunk #"..tostring(c))
				print("addrs.phy = ", frames[f][c].addrs.phy)
				print("addrs.mem = ", frames[f][c].addrs.mem)
				print("size = ", frames[f][c].size)

				local mem = unprotected("uint8_t", frames[f][c].addrs.mem)
				for m=0, (frames[f][c].size)-1 do
					--io.write("0x"..bit.tohex(mem[m])..", ")
					if cur_pos >= 0 then
						if cur_pos < #tx_header then
							assert(mem[m] == tx_header[1 + cur_pos], "cur_pos = "..tostring(cur_pos))
						else
							assert(mem[m] == 0x41)
						end
					end

					cur_pos = cur_pos + 1
				end
			end
			print("\nDBG: cur_pos = "..tostring(cur_pos))
	--		assert(cur_pos == tx_size) --all transmitted bytes covered
		end


	end --function M.selftest()
	return M

end --function new

