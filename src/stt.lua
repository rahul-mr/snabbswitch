-- An experimental implementation of Stateless Transport Tunnel as described 
-- here: http://tools.ietf.org/html/draft-davie-stt-02

module(...,package.seeall)

local memory = require("memory")
local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
local lib = require("lib")
local bits, bitset, protected = lib.bits, lib.bitset, lib.protected
local crc = require("crc")

require("stt_h") --all header definitions moved to stt.h

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
	M.rx  = { desc=nil, phy=nil, next=nil, total=nil, type="struct stt_rx_frame" } --[STT frame header + 64K packet]
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
		M.ack = 0
		M.nic = options.nic or assert(false, "stt.lua:: init: options.nic required")

		M.tx.total = options.tx_total or 10 --total num of descriptors
		M.rx.total = options.rx_total or 10
		M.tx.desc, M.tx.phy = memory.dma_alloc(M.tx.total * ffi.sizeof(M.tx.type))
		M.rx.desc, M.rx.phy = memory.dma_alloc(M.rx.total * ffi.sizeof(M.rx.type))
		M.tx.desc = protected(M.tx.type, M.tx.desc, 0, M.tx.total)
		M.rx.desc = protected(M.rx.type, M.rx.desc, 0, M.rx.total)
		M.tx.next = 0
		M.rx.next = 0

		M.opt.eth.src  = options.eth.src 
		M.opt.eth.dst  = options.eth.dst 
		M.opt.ip.src   = options.ip.src  
		M.opt.ip.dst   = options.ip.dst  
		M.opt.ip.vtf   = options.ip.vtf  
		M.opt.ip.next  = options.ip.next
		M.opt.ip.hop   = options.ip.hop
		M.opt.stt.flag = options.stt.flag  
		M.opt.stt.mss  = options.stt.mss    
		M.opt.stt.vlan = options.stt.vlan   
		M.opt.stt.ctx  = options.stt.ctx 

		M.flow = {}
		math.randomseed( tonumber(tostring(os.time()):reverse():sub(1,6)) ) --http://lua-users.org/wiki/MathLibraryTutorial
		M.get_random_hash = HASH_ALGOS[ math.random(1, #HASH_ALGOS) ] --transmit() needs the same hash fn between calls
	   																  --to maintain correct 'encapsulated' packet flow
	end

	M.init()

	-- Transmit the given packet using STT
	-- pkt: encapsulated packet options - dictionary containing following:
	--      mem: is of type ffi.cast("uint8_t *", ..., size); -- Read-only
	--      phy: is the physical address of the packet buffer (passed to nic)
	--      size: is the size of the packet
	-- options: [optional if configured in init()] 
	function M.transmit(pkt, options)
		assert(pkt and pkt.mem and pkt.phy and pkt.size, "pkt is invalid")
		assert(pkt.size <= 65444, "pkt.size must be <= 65444") --max supported pkt.size is (2^16) - (14 + 40 + 20 + 18)

		M.opt.eth.src  = options.eth.src  or M.opt.eth.src  or assert(false, "options.eth.src invalid")
		M.opt.eth.dst  = options.eth.dst  or M.opt.eth.dst  or assert(false, "options.eth.dst invalid")
		M.opt.ip.src   = options.ip.src   or M.opt.ip.src   or assert(false, "options.ip.src invalid")
		M.opt.ip.dst   = options.ip.dst   or M.opt.ip.dst   or assert(false, "options.ip.dst invalid")
		M.opt.ip.vtf   = options.ip.vtf   or M.opt.ip.vtf   or 0x06
		M.opt.ip.next  = options.ip.next  or M.opt.ip.next  or 0x06
		M.opt.ip.hop   = options.ip.hop   or M.opt.ip.hop   or 0x40
		M.opt.stt.flag = options.stt.flag or M.opt.stt.flag or bits{cs_partial=1} --if TSO used, set cs_partial bit
		M.opt.stt.mss  = options.stt.mss  or M.opt.stt.mss  or 1422 --1500 - (14 + 40 + 20) - 4
		M.opt.stt.vlan = options.stt.vlan or M.opt.stt.vlan or { pcp=0x00, cfi=0x00, id=0x00 }
		M.opt.stt.ctx  = options.stt.ctx  or M.opt.stt.ctx  or 0

		assert(M.opt.eth.src:len() == 6, "eth.src should have length 6")
		assert(M.opt.eth.dst:len() == 6, "eth.dst should have length 6")
		assert(M.opt.ip.src:len() == 16, "ip.src should have length 16") 
		assert(M.opt.ip.dst:len() == 16, "ip.dst should have length 16") 

		local pm = protected("uint8_t", pkt.mem, 0, 78) --14 + 60 + 4 [Max: eth + ipv4 + tcp/udp ports] 
		local ver = bit.band(pm[0], 0x60)
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
		M.tx.desc[M.tx.next].hdr.ipv6.next_header   = M.opt.ip.next
		M.tx.desc[M.tx.next].hdr.ipv6.hop_limit     = M.opt.ip.hop

		for i=1, 16 do
		  M.tx.desc[M.tx.next].hdr.ipv6.dst_ip[i-1] = M.opt.ip.dst:byte(i) 
		  M.tx.desc[M.tx.next].hdr.ipv6.src_ip[i-1] = M.opt.ip.src:byte(i) 
		end
		
		M.tx.desc[M.tx.next].stt_hdr.flags  = M.opt.stt.flag 
		M.tx.desc[M.tx.next].stt_hdr.mss    = M.opt.stt.mss
		M.tx.desc[M.tx.next].stt_hdr.vlan   = bit.band( bit.bor(bit.lshift(M.opt.stt.vlan.pcp, 13), 
													  			bit.lshift(M.opt.stt.vlan.cfi, 12),
																M.opt.stt.vlan.id),
														0xffff)
		M.tx.desc[M.tx.next].stt_hdr.ctx_id = M.opt.stt.ctx 

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
		M.tx.desc[M.tx.next].hdr.seg.flags = bits{ack=4}

		M.tx.desc[M.tx.next].hdr.ipv6.paylen = 20 + 18 + pkt.size --TCP-like header + stt frame header + encapsulated packet

		local descriptors = { { address = M.tx.phy, size = ffi.sizeof(M.tx.type) }, --Eth + IPv6 + TCP + STT frame header
						 	  { address = pkt.phy,  size = pkt.size }               --Encapsulated packet
					  		}
		local size = descriptors[1].size + descriptors[2].size
		local context = M.tx.desc._ptr + M.tx.next * descriptors[1].size

		nic.add_txbuf_tso( descriptors, size, M.opt.stt.mss, context, M.opt.stt.vlan )

		nic.flush_tx()
		nic.wait_tx(size) --wait for transmission
		nic.clear_tx()

		M.ack = (M.ack + 1) % 0x10000 --2^16
		M.tx.next = (M.tx.next + 1) % M.tx.total
	end

	--returns pointer to element of 'type' located at 'base'+'offset' address (without any protection ;-))
	local function unprotected(type, base, offset)
		offset = offset or 0
		return ffi.cast( ffi.typeof("$ *", ffi.typeof(type)),
						 ffi.cast("uint8_t *", base) + offset)
	end

	--match two Eth + IPv6 + TCP packet headers
	--Parameters: a, b of type: unprotected("struct frame_hdr", ...)
	--            exp_frame_len: expected value in a's frame_len TCP(STT) header
	--Returns: true if relevant headers match
	--         false otherwise
	function M.match_headers(a, b, exp_frame_len)
		
		--check ethernet headers --XXX alternatively use memcmp?
		for i=0, 5 do
			if (a.eth.dst_mac[i] ~= b.eth.dst_mac[i]) or (a.eth.src_mac[i] ~= b.eth.src_mac[i]) then
				return false
			end
		end
		if a.eth.type ~= b.eth.type then return false end 

		--check ipv6 headers
		if a.ipv6.ver_traf_flow ~= b.ipv6.ver_traf_flow or
		   a.ipv6.next_hdr      ~= b.ipv6.next_hdr      or --skip ipv6.pay_len
		   a.ipv6.hop_limit     ~= b.ipv6.hop_limit     then
		   return false
		end

		for i=0, 15 do
			if (a.ipv6.src_addr[i] ~= b.ipv6.src_addr[i]) or (a.ipv6.dst_addr[i] ~= b.ipv6.dst_addr[i]) then
				return false
			end
		end

		--check TCP headers
		if a.seg.src_port  ~= b.seg.src_port or
		   a.seg.dst_port  ~= b.seg.dst_port or
		   a.seg.frag_ofs  ~= b.seg.frag_ofs or
		   a.seg.frame_len ~= exp_frame_len  or
		   a.seg.ack_num   ~= b.seg.ack_num  then
		   return false
		end

		return true --all "relevant" headers matched :-)
	end


	--XXX 1.convert assert()s to return nil, "error message" ?
	--    2. maintain the "flow"
	--Receive a "big" packet using STT
	--Returns: Tuple (length, num_of_packets) [Note: length bytes of given buffer that got used]
	--            OR (nil, "Error message")
	function M.receive(buf_address, buf_size)
		if nic.rx_empty() then 
			return nil, "Empty rx ring"
		else
			local pkt_count = 0 --num of rx packets that make up the "big" packet
			local buf_used = 0
			local big_pkt = nil
			local start_addr = nil
			local big_pkt_paylen = 0 -- payload length of "big" packet

			while nic.rxnext < nic.regs[RDH] do --read the newly written rx packets
			
				--handle packets with nic.rxdesc[nic.rxnext].wb.status showing invalid IP/TCP checksums
				if nic.rxdesc[nic.rxnext].wb.status ~= 0x060023 then --in-correct status for Eth+IPv6+TCP
					nic.rxnext = (nic.rxnext + 1) % nic.num_descriptors --skip this packet

				else
					local pkt = unprotected("struct frame_hdr", nic.rxbuffers[nic.rxnext])
					assert(pkt.eth.type == 0x86DD and 
						   bit.band(pkt.ipv6.ver_traf_flow, 0xf0000000) == 0x60000000 and
						   pkt.ipv6.next_hdr == 0x06,
						   "NYI: Only Eth + IPv6 + TCP(STT) supported ATM")
					
					local cp_offset, cp_length = 0, 0 --copy parameters
					
					if pkt_count = 0 then --first rx packet
						start_addr = nic.rxbuffers[nic.rxnext]
						cp_length = nic.rxdesc[nic.rxnext].wb.length
						big_pkt = unprotected("struct frame_hdr", buf_address)

					elseif not match_packets(pkt, big_pkt, big_pkt_paylen) then
						break --out of while loop

					else
						cp_offset = ffi.sizeof(ffi.typeof("struct frame_hdr")) --skip the current packet's headers
						assert(pkt.ipv6.pay_len == (nic.rxdesc[nic.rxnext].wb.length - cp_offset),
			 				   "payload lengths are not matching")
						cp_length = nic.rxdesc[nic.rxnext].wb.length - cp_offset
					end

					assert( (buf_size - buf_used -1) >= cp_length, "Insufficient buffer size") --1 byte for padding
					ffi.copy(buf_address + buf_used, nic.rxbuffers[nic.rxnext] + cp_offset, cp_length)
					buf_used = buf_used + cp_length

					big_pkt_paylen = big_pkt_paylen + pkt.ipv6.pay_len
					nic.rxnext = (nic.rxnext + 1) % nic.num_descriptors
					pkt_count = pkt_count + 1
				end --if else nic.rxdesc[nic.rxnext].wb.status
			end --while loop

			pkt = unprotected("struct frame_hdr", start_addr) --access big packet
			pkt.ipv6.pay_len = big_pkt_paylen --set its payload length
			pkt.seg.checksum = 0

			---- CHECKSUM ---

			local wpkt  = unprotected("uint16_t", start_addr, frame_len) --16-bit word access for checksum calculation
			local addrs = unprotected("uint16_t", start_addr, 8) --16-bit word access to addresses
			local checksum = 0
			
			for i=0, 15 do --src and dest addrs
				checksum = checksum + addrs[i]
			end

			checksum = checksum + pkt.ipv6.next_hdr + pkt.ipv6.pay_len
		
			unprotected("uint8_t", start_addr, frame_len + 40 + pkt.ipv6.paylen)[0] = 0x00 --padding if seg len is odd

			for i=0, math.ceil(pkt.ipv6.pay_len / 2) do --TCP header + text
				checksum = checksum + wpkt[i]
			end
			
			checksum = bit.bor(bit.rshift(checksum, 16), bit.band(checksum, 0xffff))
			checksum = checksum + bit.rshift(checksum, 16)
			pkt.seg.checksum = checksum

			return buf_used, pkt_count
		end --if (nic.rx_empty) else
	end

	return M

end --function new
