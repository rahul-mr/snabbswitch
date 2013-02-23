-- An experimental implementation of Stateless Transport Tunnel as described 
-- here: http://tools.ietf.org/html/draft-davie-stt-02

local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
local lib = require("lib")
local bits, bitset = lib.bits, lib.bitset

ffi.cdef[[

    /* STT frame format */
    struct stt_frame
    {
        uint8_t  version;    
        uint8_t  flags;    
        uint8_t  l4_offset;    
        uint8_t  reserved;    
        uint16_t mss;    
        uint16_t vlan;    
        uint64_t context_id;    
        uint16_t padding;    
        //       data;       /* encapsulated Ethernet Frame */
    } __attribute__((packed));  

    /* STT segment format */
    struct stt_segment
    {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t frag_offset; /* used by STT (TCP seq_num_L)*/
        uint16_t frame_len;   /* used by STT (TCP seq_num_H)*/
        uint32_t ack_num;     /* used by STT (const for each segment of an STT frame)*/
        uint8_t  data_offset; /* lower nibble */
        uint8_t  flags;       /* upper 6 bits (only??) */
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent_ptr;
        //       options;     /* variable size */
        //       data;        /* variable size */
    } __attribute__((packed));


    /* IPv6 header */
    struct ipv6_header
    {
        uint32_t ver_traf_flow;        
        uint16_t pay_len;        
        uint8_t  next_hdr;        
        uint8_t  hop_limit;        
        uint8_t src_addr [16];        
        uint8_t dst_addr [16];        
    } __attribute__((packed));

    /* 802.3 Ethernet frame header (without 802.1Q tag and FCS).
    Note: use NIC's vlan tagging, FCS facility :-) */
    struct ethernet_header
    {
        uint8_t dst_mac [6];
        uint8_t src_mac [6];
        uint16_t type;
    } __attribute__((packed));

]]

STT_DEST_PORT = 2013 --temporary; this will change as the draft evolves

--Generate a random source port in the range [49152,65535]
--Note1: the source port should be constant for each flow
--       in the virtual network, e.g. a single TCP connection
--Note2: arguments are values in the encapsulated IP/{TCP,UDP}
function gen_src_port(src_port, dst_port, src_addr, dst_addr) 
  --XXX select random hash algo at init

  -- return 49152 + (CRC-14 of args) 
end

SEQ_NUM = 0 --current sequence number
ACK_NUM = 0 --current acknowledgement number
CTX_ID  = 0 --current context id

function init()
  SEQ_NUM = 0
  ACK_NUM = 0
  CTX_ID  = 0
end

