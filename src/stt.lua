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

		stt.mem.hdr.ipv6.paylen = 20 + 18 + pkt.size --"TCP-like" header + stt frame header + encapsulated packet

		ACK_NUM  = (ACK_NUM + 1) % (2^16)

	end

	return M

end --function new
