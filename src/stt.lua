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
    } __attribute__((packed));  

    /* STT segment format */
    struct stt_segment
    {
        uint16_t src_port;
        uint16_t dest_port;
        uint32_t seq_num;     /* used by STT */
        uint32_t ack_num;     /* used by STT */
        uint8_t  data_offset; /* lower nibble */
        uint8_t  flags;       /* upper 6 bits (?) */
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent_ptr;
        //       options;     /* variable size */
        //       data;        /* variable size */
    } __attribute__((packed));
]]

STT_DEST_PORT = 2013 --this will change as the draft evolves

--Generate a random source port in the range [49152,65535]
function gen_src_port() 
  return math.random(49152, 65535) --better seeding?
end


