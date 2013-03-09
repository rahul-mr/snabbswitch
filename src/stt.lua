-- An experimental implementation of Stateless Transport Tunnel as described 
-- here: http://tools.ietf.org/html/draft-davie-stt-02

module(...,package.seeall)

local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
local lib = require("lib")
local bits, bitset = lib.bits, lib.bitset
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

    /* frame0 - for 1st descriptor -- XXX better naming?*/
    struct frame0
    {
        struct frame_hdr     hdr;
        struct stt_frame_hdr stt_hdr;
    } __attribute__((packed));
]]

---------

---------------
-- CONSTANTS --
---------------

STT_DST_PORT = 2013 --temporary; this will change as the draft evolves
ACK_NUM = 0 --current acknowledgement number (serves as identification)

HASH_ALGOS = { crc.crc14 } --XXX Add other hash functions as necessary

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
    stt.mem.hdr.seg.frame_len = 18 + pkt.size --stt frame header + encapsulated packet
    stt.mem.hdr.seg.ack_num = ACK_NUM

    stt.mem.hdr.ipv6.paylen = 20 + 18 + pkt.size --"TCP-like" header + stt frame header + encapsulated packet

    ACK_NUM  = (ACK_NUM + 1) % (2^16)

end
