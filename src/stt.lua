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

    /* [Ethernet + IPv6 + STT] frame headers */
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

STT_DEST_PORT = 2013 --temporary; this will change as the draft evolves

--Generate a random source port in the range [49152,65535]
--Note1: the source port should be constant for each flow
--       in the virtual network, e.g. a single TCP connection
--Note2: ip_ptr is the pointer to encapsulated IP packet header
--       addr_size is the size of IP address field
--       other args are field offets in the packet header
function gen_src_port(ip_ptr, addr_size, src_port_off, dst_port_off, src_addr_off, dst_addr_off) 
  --XXX select a random hash algo at init

  -- return 49152 + (CRC-14 of args) 
end

SEQ_NUM = 0 --current sequence number
ACK_NUM = 0 --current acknowledgement number

function init()
  SEQ_NUM = 0
  ACK_NUM = 0
end

--determine if given packet is {IPv4,IPv6}/{TCP,UDP}
--returns nil if invalid (ie, not IPv4/v6)
--mem is protected("uint8_t", mem_addrs, ..., size) where size == 23 (14 + 9)
function check_packet(mem)

    local ret = { }

    local ver = bit.band(mem[0], 0x60)
    local proto = nil

    if ver == 0x40 then      --IPv4
        proto = mem[23]     --14 + 9
    elseif ver == 0x60 then  --IPv6
        proto = mem[20]        --14 + 6
        ret["ipv6"] = true
    else
        return nil --invalid packet
    end

    if proto == 0x06 then
        ret["tcp"] = true
    elseif proto == 0x11 then
        ret["udp"] = true
    --else hopefully some other valid protocol
    end 

    return ret 
end

--Generate an IPv6+STT frame 
-- stt: stt options - dictionary containing following:
--      mem, dst_mac, src_mac, src_ip, dst_ip, mss, vlan, ctx_id
--      mem is of type ffi.cast("struct frame0 *", ...)
--      {src,dst}_{mac,ip} are strings;
--      ctx_id is of type: uint64_t
-- pkt: encapsulated packet options - dictionary containing following:
--      mem, size
--      mem is of type ffi.cast("uint8_t *", ..., size)
function gen_stt_frame(stt, pkt)
    assert(stt and pkt, "stt and pkt cannot be nil")
    assert(pkt.size > 23, "pkt_size should be >23")

    local pm = protected("uint8_t", pkt.mem, 0, 23)
    local ver = bit.band(pm[0], 0x60)
    local proto = nil
    local hdr_len  = nil -- IP header length

    assert(stt.mem ~= nil, "stt.mem cannot be nil")
    assert(stt.dst_mac:len() == 6, "dst_mac should have length 6")
    assert(stt.src_mac:len() == 6, "src_mac should have length 6")
    
    for i=1, 6 do
      stt.mem.hdr.eth.dst_mac[i-1] = stt.dst_mac:ubyte(i) 
      stt.mem.hdr.eth.src_mac[i-1] = stt.src_mac:ubyte(i) 
    end

    assert(stt.src_ip:len() == 16, "src_ip should have length 16") 
    assert(stt.dst_ip:len() == 16, "dst_ip should have length 16") 

    for i=1, 16 do
      stt.mem.hdr.ipv6.dst_ip[i-1] = stt.dst_ip:ubyte(i) 
      stt.mem.hdr.ipv6.src_ip[i-1] = stt.src_ip:ubyte(i) 
    end

    stt.mem.stt_hdr.flags  = bits({cs_partial=1}) --gonna be using TSO
    stt.mem.stt_hdr.mss    = stt.mss or assert(false, "stt.mss must be given")
    stt.mem.stt_hdr.vlan   = stt.vlan or assert(false, "stt.vlan must be given")
    stt.mem.stt_hdr.ctx_id = stt.ctx_id or assert(false, "stt.ctx_id must be given")

    if ver == 0x40 then      --IPv4
        proto = pm[23]     --14 + 9
        stt.mem.stt_hdr.flags  = bits({ipv4=2}, stt.mem.stt_hdr.flags)
	stt.mem.stt_hdr.l4_ofs = 14 + 4 * bit.band(pm[14], 0x0f) --IHL field
    elseif ver == 0x60 then  --IPv6
        proto = pm[20]        --14 + 6
	stt.mem.stt_hdr.l4_ofs = 14 + 40
    else
        assert(false, "Invalid encapsulated packet")
    end

    if proto == 0x06 then --TCP
        stt.mem.stt_hdr.flags = bits({tcp=3}, stt.mem.stt_hdr.flags)
    --else hopefully some other valid protocol
    end

end
