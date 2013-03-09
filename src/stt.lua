-- An experimental implementation of Stateless Transport Tunnel as described 
-- here: http://tools.ietf.org/html/draft-davie-stt-02

local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
local lib = require("lib")
local bits, bitset = lib.bits, lib.bitset

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

    /* frame0 - for 1st descriptor -- XXX better naming?*/
    struct frame0
    {
        struct frame_hdr     hdr;
        struct stt_frame_hdr stt_hdr;
    } __attribute__((packed));
]]

---------

--XXX Move to lib.lua?

--CRC-14 
--Reference: http://www.w3.org/TR/PNG/#D-CRCAppendix

local CRC14_MAX = 0x3FFF
-- CRC14_POLY = 0x21E8 -- HD=4, MaxLen=2048 http://www.ece.cmu.edu/~koopman/roses/dsn04/koopman04_crc_poly_embedded.pdf
                       -- Note: for current usage: Max Data length = (2*16 + 2*128) = 288 bits
--pre-computed hash values (note: index range = 1 to 256)
crc14_table = { 

0x0000 , 0x3562 , 0x2915 , 0x1c77 , 0x11fb , 0x2499 , 0x38ee , 0x0d8c ,
0x23f6 , 0x1694 , 0x0ae3 , 0x3f81 , 0x320d , 0x076f , 0x1b18 , 0x2e7a ,
0x043d , 0x315f , 0x2d28 , 0x184a , 0x15c6 , 0x20a4 , 0x3cd3 , 0x09b1 ,
0x27cb , 0x12a9 , 0x0ede , 0x3bbc , 0x3630 , 0x0352 , 0x1f25 , 0x2a47 ,
0x087a , 0x3d18 , 0x216f , 0x140d , 0x1981 , 0x2ce3 , 0x3094 , 0x05f6 ,
0x2b8c , 0x1eee , 0x0299 , 0x37fb , 0x3a77 , 0x0f15 , 0x1362 , 0x2600 ,
0x0c47 , 0x3925 , 0x2552 , 0x1030 , 0x1dbc , 0x28de , 0x34a9 , 0x01cb ,
0x2fb1 , 0x1ad3 , 0x06a4 , 0x33c6 , 0x3e4a , 0x0b28 , 0x175f , 0x223d ,
0x10f4 , 0x2596 , 0x39e1 , 0x0c83 , 0x010f , 0x346d , 0x281a , 0x1d78 ,
0x3302 , 0x0660 , 0x1a17 , 0x2f75 , 0x22f9 , 0x179b , 0x0bec , 0x3e8e ,
0x14c9 , 0x21ab , 0x3ddc , 0x08be , 0x0532 , 0x3050 , 0x2c27 , 0x1945 ,
0x373f , 0x025d , 0x1e2a , 0x2b48 , 0x26c4 , 0x13a6 , 0x0fd1 , 0x3ab3 ,
0x188e , 0x2dec , 0x319b , 0x04f9 , 0x0975 , 0x3c17 , 0x2060 , 0x1502 ,
0x3b78 , 0x0e1a , 0x126d , 0x270f , 0x2a83 , 0x1fe1 , 0x0396 , 0x36f4 ,
0x1cb3 , 0x29d1 , 0x35a6 , 0x00c4 , 0x0d48 , 0x382a , 0x245d , 0x113f ,
0x3f45 , 0x0a27 , 0x1650 , 0x2332 , 0x2ebe , 0x1bdc , 0x07ab , 0x32c9 ,
0x21e8 , 0x148a , 0x08fd , 0x3d9f , 0x3013 , 0x0571 , 0x1906 , 0x2c64 ,
0x021e , 0x377c , 0x2b0b , 0x1e69 , 0x13e5 , 0x2687 , 0x3af0 , 0x0f92 ,
0x25d5 , 0x10b7 , 0x0cc0 , 0x39a2 , 0x342e , 0x014c , 0x1d3b , 0x2859 ,
0x0623 , 0x3341 , 0x2f36 , 0x1a54 , 0x17d8 , 0x22ba , 0x3ecd , 0x0baf ,
0x2992 , 0x1cf0 , 0x0087 , 0x35e5 , 0x3869 , 0x0d0b , 0x117c , 0x241e ,
0x0a64 , 0x3f06 , 0x2371 , 0x1613 , 0x1b9f , 0x2efd , 0x328a , 0x07e8 ,
0x2daf , 0x18cd , 0x04ba , 0x31d8 , 0x3c54 , 0x0936 , 0x1541 , 0x2023 ,
0x0e59 , 0x3b3b , 0x274c , 0x122e , 0x1fa2 , 0x2ac0 , 0x36b7 , 0x03d5 ,
0x311c , 0x047e , 0x1809 , 0x2d6b , 0x20e7 , 0x1585 , 0x09f2 , 0x3c90 ,
0x12ea , 0x2788 , 0x3bff , 0x0e9d , 0x0311 , 0x3673 , 0x2a04 , 0x1f66 ,
0x3521 , 0x0043 , 0x1c34 , 0x2956 , 0x24da , 0x11b8 , 0x0dcf , 0x38ad ,
0x16d7 , 0x23b5 , 0x3fc2 , 0x0aa0 , 0x072c , 0x324e , 0x2e39 , 0x1b5b ,
0x3966 , 0x0c04 , 0x1073 , 0x2511 , 0x289d , 0x1dff , 0x0188 , 0x34ea ,
0x1a90 , 0x2ff2 , 0x3385 , 0x06e7 , 0x0b6b , 0x3e09 , 0x227e , 0x171c ,
0x3d5b , 0x0839 , 0x144e , 0x212c , 0x2ca0 , 0x19c2 , 0x05b5 , 0x30d7 ,
0x1ead , 0x2bcf , 0x37b8 , 0x02da , 0x0f56 , 0x3a34 , 0x2643 , 0x1321 

}


function crc14()

    local M = {}
    M.crc = CRC14_MAX
 
    function M.add_byte(byte)
        assert(byte, "byte can't be nil")
   	M.crc = bit.bxor(crc14_table[1 + bit.band(bit.bxor(M.crc, byte), 0xFF)], --crc14_table indices 1 to 256
                         bit.rshift(M.crc, 8))
    end

    function M.generate()
	return bit.bxor(CRC14_MAX, M.crc)
    end

    return M
end

---------------
-- CONSTANTS --
---------------

STT_DST_PORT = 2013 --temporary; this will change as the draft evolves
ACK_NUM = 0 --current acknowledgement number (serves as identification)

HASH_ALGOS = { crc14 } --XXX Add other hash functions as necessary

get_random_hash = nil --see init()

---------------
-- FUNCTIONS --
---------------

function init()
  ACK_NUM = 0
  math.randomseed( tonumber(tostring(os.time()):reverse():sub(1,6)) ) --http://lua-users.org/wiki/MathLibraryTutorial
  get_random_hash = HASH_ALGOS[ math.random(1, #HASH_ALGOS) ] --gen_stt_frame() should use the same hash fn between calls 
end

--Generate an IPv6+STT frame in the given pre-allocated buffer 
-- stt: stt options - dictionary containing following:
--      mem, dst_mac, src_mac, src_ip, dst_ip, flags, mss, vlan, ctx_id
--      mem is of type ffi.cast("struct frame0 *", ...)
--      {src,dst}_{mac,ip} are strings;
--      ctx_id is of type: uint64_t
-- pkt: encapsulated packet options - dictionary containing following:
--      mem, size
--      mem is of type ffi.cast("uint8_t *", ..., size); -- Read-only
function gen_stt_frame(stt, pkt)
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
    stt.mem.hdr.seg.frame_len = 18 + pkt.size
    stt.mem.hdr.seg.ack_num = ACK_NUM

    stt.mem.hdr.ipv6.paylen = 20 + 18 + pkt.size

    ACK_NUM  = (ACK_NUM + 1) % (2^16)

end
