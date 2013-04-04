-- An experimental implementation of Stateless Transport Tunnel as described 
-- here: http://tools.ietf.org/html/draft-davie-stt-02

module(...,package.seeall)

local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
local lib = require("lib")
local bits, bitset = lib.bits, lib.bitset
local crc = require("crc")

require("stt_h")

ffi.cdef[[
//moved to stt.h
]]

---------
function new()

	local M = {}

	---------------
	-- VARIABLES --
	---------------

	local STT_DST_PORT = 2013 --temporary; this will change as the draft evolves
	local HASH_ALGOS = { crc.crc14 } --XXX Add other hash functions as necessary

	local ACK_NUM = 0 --current acknowledgement number (serves as identification)
	local get_random_hash = nil --see init()

	---------------
	-- FUNCTIONS --
	---------------

	function M.init()
		ACK_NUM = 0
		math.randomseed( tonumber(tostring(os.time()):reverse():sub(1,6)) ) --http://lua-users.org/wiki/MathLibraryTutorial
		get_random_hash = HASH_ALGOS[ math.random(1, #HASH_ALGOS) ] --gen_stt_frame() needs the same hash fn between calls 
	end

	M.init()

	--XXX 1. pass the nic object as argument so that we can call add_txbuf_tso() and other plumbing here (reduces the 
	-- complexity of using this function)		
	--    2. allocate memory for the required buffers ("struct frame0*"), txdesc,  rxdesc in M.init()
	--    3. new function M.set_defaults() to set default values for stt options.
	--
	--Generate an IPv6+STT frame in the given pre-allocated buffer 
	-- stt: stt options - dictionary containing following:
	--      mem, dst_mac, src_mac, src_ip, dst_ip, flags, mss, vlan, ctx_id
	--      mem is of type ffi.cast("struct frame0 *", ...)
	--      {src,dst}_{mac,ip} are strings;
	--      ctx_id is of type: uint64_t
	-- pkt: encapsulated packet options - dictionary containing following:
	--      mem, size
	--      mem is of type ffi.cast("uint8_t *", ..., size); -- Read-only
	function M.gen_stt_frame(stt, pkt)
		assert(stt and pkt, "stt and pkt cannot be nil")

		local pm = protected("uint8_t", pkt.mem, 0, 78) --14 + 60 + 4
		local ver = bit.band(pm[0], 0x60)
		local proto = nil
		local ip_hdr_len = nil
		local hash = get_random_hash()
		local src_addr_off = nil
		local addr_len  = nil

		assert(stt.mem ~= nil, "stt.mem cannot be nil")
		assert(stt.dst_mac:len() == 6, "dst_mac should have length 6")
		assert(stt.src_mac:len() == 6, "src_mac should have length 6")
		
		for i=1, 6 do
		  stt.mem.hdr.eth.dst_mac[i-1] = stt.dst_mac:byte(i) 
		  stt.mem.hdr.eth.src_mac[i-1] = stt.src_mac:byte(i) 
		end

		stt.mem.hdr.ipv6.ver_traf_flow = stt.ver_traf_flow or 0x06
		stt.mem.hdr.ipv6.next_header   = stt.next_header   or 0x06
		stt.mem.hdr.ipv6.hop_limit     = stt.hop_limit     or 0x40

		assert(stt.src_ip:len() == 16, "src_ip should have length 16") 
		assert(stt.dst_ip:len() == 16, "dst_ip should have length 16") 

		for i=1, 16 do
		  stt.mem.hdr.ipv6.dst_ip[i-1] = stt.dst_ip:byte(i) 
		  stt.mem.hdr.ipv6.src_ip[i-1] = stt.src_ip:byte(i) 
		end
		
		stt.mem.stt_hdr.flags  = stt.flags or bits({cs_partial=1}) --if TSO used, set cs_partial bit
		stt.mem.stt_hdr.mss    = stt.mss or assert(false, "stt.mss must be given")
		stt.mem.stt_hdr.vlan   = stt.vlan or assert(false, "stt.vlan must be given")
		stt.mem.stt_hdr.ctx_id = stt.ctx_id or assert(false, "stt.ctx_id must be given")

		if ver == 0x40 then      --IPv4
			proto = pm[23]     --14 + 9
			stt.mem.stt_hdr.flags  = bits({ipv4=2}, stt.mem.stt_hdr.flags)
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

		stt.mem.stt_hdr.l4_ofs = ip_hdr_len

		if proto == 0x06 then --TCP
			stt.mem.stt_hdr.flags = bits({tcp=3}, stt.mem.stt_hdr.flags)
		--else hopefully some other valid protocol
		end

		for i=0, 3 do
			hash.add_byte(pm[ip_hdr_len + i]) --TCP/UDP source and dest ports (first 4 bytes of IP payload)
		end
		
		for i=0, 2*addr_len-1 do --IP source, dest addresses
			hash.add_byte(pm[src_addr_off + i])
		end

		stt.mem.hdr.seg.src_port = 49152 + hash.generate() --generate a 14-bit hash
		stt.mem.hdr.seg.dst_port = STT_DST_PORT
		stt.mem.hdr.seg.frame_len = 18 + pkt.size --stt frame header + encapsulated packet
		stt.mem.hdr.seg.ack_num = ACK_NUM
		stt.mem.hdr.seg.flags = bits({ack=4})

		stt.mem.hdr.ipv6.paylen = 20 + 18 + pkt.size --"TCP-like" header + stt frame header + encapsulated packet

		ACK_NUM  = (ACK_NUM + 1) % (2^16)

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
		local i = 0
		--check ethernet headers --XXX alternatively use memcmp?
		while i<=5 do
			if (a.eth.dst_mac[i] ~= b.eth.dst_mac[i]) or (a.eth.src_mac[i] ~= b.eth.src_mac[i]) then
				return false
			end
			i = i + 1
		end
		if a.eth.type ~= b.eth.type then return false end 

		--check ipv6 headers
		if a.ipv6.ver_traf_flow ~= b.ipv6.ver_traf_flow or
		   a.ipv6.next_hdr      ~= b.ipv6.next_hdr      or --skip ipv6.pay_len
		   a.ipv6.hop_limit     ~= b.ipv6.hop_limit     then
		   return false
		end

		i = 0
		while i<=15 do
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


	--XXX convert assert()s to return nil, "error message" ?
	--Receive a "big" packet using STT
	--Parameters: buf_address - memory address to copy the received packet
	--            buf_size    - size of the buffer
	--Returns: Tuple (length, num_of_packets) [Note: length bytes of given buffer that got used]
	--            OR (nil, "Error message")
	function M.receive_stt(nic, buf_address, buf_size)
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
