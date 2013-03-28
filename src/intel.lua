-- intel.lua -- Intel 82574L driver with Linux integration
-- Copyright 2012 Snabb GmbH. See the file LICENSE.

-- This is a device driver for the Intel 82574L gigabit ethernet controller.
-- The chip is very well documented in Intel's data sheet:
-- http://ark.intel.com/products/32209/Intel-82574L-Gigabit-Ethernet-Controller

module(...,package.seeall)

-- Notes:
-- PSP (pad short packets to 64 bytes)

local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
local pci = require("pci")
local lib = require("lib")
local bits, bitset = lib.bits, lib.bitset

require("stt_h")
require("clib_h")
require("snabb_h")

ffi.cdef[[
         // RX descriptor written by software.
         struct rx_desc {
            uint64_t address;    // 64-bit address of receive buffer
            uint64_t dd;         // low bit must be 0, otherwise reserved
         } __attribute__((packed));

         // RX writeback descriptor written by hardware.
         struct rx_desc_wb {
            uint32_t mrq;
            uint16_t id;
            uint16_t checksum;
            uint32_t status;
            uint16_t length;
            uint16_t vlan;
         } __attribute__((packed));

         union rx {
            struct rx_desc data;
            struct rx_desc_wb wb;
         } __attribute__((packed));

   ]]

ffi.cdef[[
         // TX Extended Data Descriptor written by software.
         struct tx_desc {
            uint64_t address;
            uint32_t optionsL;
            uint32_t optionsH;
         } __attribute__((packed));


       /********************************
        * Not used (only for reference)
        ********************************
         struct tx_context_desc {
            unsigned int tucse:16,
                         tucso:8,
                         tucss:8,
                         ipcse:16,
                         ipcso:8,
                         ipcss:8,
                         mss:16,
                         hdrlen:8,
                         rsv:2,
                         sta:4,
                         tucmd:8,
                         dtype:4,
                         paylen:20;
         } __attribute__((packed));
       ********************************/

         struct tx_context_desc {
             uint8_t  ipcss;
             uint8_t  ipcso;
             uint16_t ipcse;
             uint8_t  tucss;
             uint8_t  tucso;
             uint16_t tucse;

             uint32_t tucmd_dtype_paylen;
             uint8_t  rsv_sta;
             uint8_t  hdrlen;
             uint16_t mss;

         } __attribute__((packed));

         union tx {
            struct tx_desc data;
            struct tx_context_desc ctx;
         };
   ]]


function new (pciaddress)

   -- Method dictionary for Intel NIC objects.
   local M = {}

   -- Return a table for protected (bounds-checked) memory access.
   -- 
   -- The table can be indexed like a pointer. Index 0 refers to address
   -- BASE+OFFSET, index N refers to address BASE+OFFSET+N*sizeof(TYPE),
   -- and access to indices >= SIZE is prohibited.
   --
   -- Examples:
   --   local mem =  protected("uint32_t", 0x1000, 0x0, 0x080)
   --   mem[0x000] => <word at 0x1000>
   --   mem[0x001] => <word at 0x1004>
   --   mem[0x07F] => <word at 0x11FC>
   --   mem[0x080] => ERROR <address out of bounds: 0x1200>
   --   mem._ptr   => cdata<uint32_t *>: 0x1000 (get the raw pointer)
   local function protected (type, base, offset, size)
      type = ffi.typeof(type)
      local bound = ((size * ffi.sizeof(type)) + 0ULL) / ffi.sizeof(type) 
      local tptr = ffi.typeof("$ *", type)
      local wrap = ffi.metatype(ffi.typeof("struct { $ _ptr; }", tptr), {
                                   __index = function(w, idx)
                                                assert(idx < bound)
                                                return w._ptr[idx]
                                             end,
                                   __newindex = function(w, idx, val)
                                                   assert(idx < bound)
                                                   w._ptr[idx] = val
                                                end,
                                })
      return wrap(ffi.cast(tptr, ffi.cast("uint8_t *", base) + offset))
   end

   local num_descriptors = 32 * 1024
   local buffer_count = 2 * 1024 * 1024

   local rxdesc, rxdesc_phy
   local txdesc, txdesc_phy
   local buffers, buffers_phy

   local pci_config_fd = nil

   -- Register addresses as 32-bit word offsets.
   local CTRL   = 0x00000 / 4 -- Device Control Register (RW)
   local STATUS = 0x00008 / 4 -- Device Status Register (RO)
   local PBA    = 0x01000 / 4 -- Packet Buffer Allocation
   local IMC    = 0x000D8 / 4 -- Interrupt Mask Clear (W)
   local RCTL   = 0x00100 / 4 -- Receive Control Register (RW)
   local RFCTL  = 0x05008 / 4 -- Receive Filter Control Register (RW)
   local RXDCTL = 0x02828 / 4 -- Receive Descriptor Control (RW)
   local RXCSUM = 0x05000 / 4 -- Receive Checksum Control (RW)
   local RDBAL  = 0x02800 / 4 -- Receive Descriptor Base Address Low (RW)
   local RDBAH  = 0x02804 / 4 -- Receive Descriptor Base Address High (RW)
   local RDLEN  = 0x02808 / 4 -- Receive Descriptor Length (RW)
   local RDH    = 0x02810 / 4 -- Receive Descriptor Head (RW)
   local RDT    = 0x02818 / 4 -- Receive Descriptor Tail (RW)
   local RADV   = 0x0282C / 4 -- Receive Interrupt Absolute Delay Timer (RW)
   local RDTR   = 0x02820 / 4 -- Rx Interrupt Delay Timer [Packet Timer] (RW)
   local TXDCTL = 0x03828 / 4 -- Transmit Descriptor Control (RW)
   local TCTL   = 0x00400 / 4 -- Transmit Control Register (RW)
   local TIPG   = 0x00410 / 4 -- Transmit Inter-Packet Gap (RW)
   local TDBAL  = 0x03800 / 4 -- Transmit Descriptor Base Address Low (RW)
   local TDBAH  = 0x03804 / 4 -- Transmit Descriptor Base Address High (RW)
   local TDLEN  = 0x03808 / 4 -- Transmit Descriptor Length (RW)
   local TDH    = 0x03810 / 4 -- Transmit Descriptor Head (RW)
   local TDT    = 0x03818 / 4 -- Transmit Descriptor Tail (RW)
   local TARC   = 0x03840 / 4 -- Transmit Arbitration Count - TARC (RW)
   local MDIC   = 0x00020 / 4 -- MDI Control Register (RW)
   local EXTCNF_CTRL = 0x00F00 / 4 -- Extended Configuration Control (RW)
   local POEMB  = 0x00F10 / 4 -- PHY OEM Bits Register (RW)
   local RDFH   = 0x02410 / 4 -- Receive Data FIFO Head Register (RW)
   local RDFT   = 0x02418 / 4 -- Receive Data FIFO Tail Register (RW)
   local RDFHS  = 0x02420 / 4 -- Receive Data FIFO Head Saved Register (RW)
   local RDFTS  = 0x02428 / 4 -- Receive Data FIFO Tail Saved Register (RW)
   local RDFPC  = 0x02430 / 4 -- Receive Data FIFO Packet Count (RW)
   local TDFH   = 0x03410 / 4 -- Transmit Data FIFO Head Register (RW)
   local TDFT   = 0x03418 / 4 -- Transmit Data FIFO Tail Register (RW)
   local TDFHS  = 0x03420 / 4 -- Transmit Data FIFO Head Saved Register (RW)
   local TDFTS  = 0x03428 / 4 -- Transmit Data FIFO Tail Saved Register (RW)
   local TDFPC  = 0x03430 / 4 -- Transmit Data FIFO Packet Count (RW)
   local PBM    = 0x10000 / 4 -- Packet Buffer Memory (RW)
   local PBS    = 0x01008 / 4 -- Packet Buffer Size (RW)
   local ICR    = 0x000C0 / 4 -- Interrupt Cause Register (RW)

   local regs = ffi.cast("uint32_t *", pci.map_pci_memory(pciaddress, 0))

   -- Initialization

   function M.init ()
      reset()
      init_pci()
      init_dma_memory()
      init_link()
      init_statistics()
      init_receive()
      init_transmit()
   end

   function reset ()
      regs[IMC] = 0xffffffff                 -- Disable interrupts
      pcie_master_reset()
      regs[CTRL] = bits({FD=0,SLU=6,RST=26,PHY_RST=31}) -- Global reset [ will (hopefully!) clear GIO Master Disable ]
      C.usleep(10); assert( not bitset(regs[CTRL],26) )
      regs[IMC] = 0xffffffff                 -- Disable interrupts
      regs[CTRL] = bits({VME=30}) -- Enable vlan tagging
   end

   function pcie_master_reset()
      regs[CTRL] = bit.bor(regs[CTRL], bits({GMD=2})) -- Set GIO Master Disable
      C.usleep(1000) -- wait 1ms
      --print("DBG: reset: GIO Master Enable Status: "..tostring(bitset(regs[STATUS], 19)) ) --GIO Master Enable Status 
      regs[CTRL] = bit.band(regs[CTRL], bit.bnot(bits({GMD=2})) ) -- Clear GIO Master Disable
   end

   function init_pci ()
      -- PCI bus mastering has to be enabled for DMA to work.
      pci_config_fd = pci.open_config(pciaddress)
      pci.set_bus_master(pci_config_fd, true)
   end

   function init_dma_memory ()
      --local descriptor_bytes = 1024 * 1024
      --local buffers_bytes = 2 * 1024 * 1024
      rxdesc, rxdesc_phy = memory.dma_alloc(num_descriptors * ffi.sizeof("union rx"))
      txdesc, txdesc_phy = memory.dma_alloc(num_descriptors * ffi.sizeof("union tx"))
      buffers, buffers_phy = memory.dma_alloc(buffer_count * ffi.sizeof("uint8_t"))
      -- Add bounds checking
      rxdesc  = protected("union rx", rxdesc, 0, num_descriptors)
      txdesc  = protected("union tx", txdesc, 0, num_descriptors)
      buffers = protected("uint8_t", buffers, 0, buffer_count)
   end

   function init_link ()
      reset_phy()
      -- phy_write(9, bit.bor(bits({Adv1GFDX=9})))
      -- force_autoneg()
   end

   function init_statistics ()
      -- Statistics registers initialize themselves within 1ms of a reset.
      C.usleep(1000)
   end

   function M.print_status ()
      local status, tctl, rctl = regs[STATUS], regs[TCTL], regs[RCTL]
      print("MAC status")
      print("  STATUS      = " .. bit.tohex(status))
      print("  Full Duplex = " .. yesno(status, 0))
      print("  Link Up     = " .. yesno(status, 1))
      print("  PHYRA       = " .. yesno(status, 10))
      speed = (({10,100,1000,1000})[1+bit.band(bit.rshift(status, 6),3)])
      print("  Speed       = " .. speed .. ' Mb/s')
      print("Transmit status")
      print("  TCTL        = " .. bit.tohex(tctl))
      print("  TXDCTL      = " .. bit.tohex(regs[TXDCTL]))
      print("  TX Enable   = " .. yesno(tctl, 1))
      print("  TDH         = " .. regs[TDH])
      print("  TDT         = " .. regs[TDT])
      print("  TDBAH       = " .. bit.tohex(regs[TDBAH]))
      print("  TDBAL       = " .. bit.tohex(regs[TDBAL]))
      print("  TDLEN       = " .. regs[TDLEN])
      print("  TARC        = " .. bit.tohex(regs[TARC]))
      print("  TIPG        = " .. bit.tohex(regs[TIPG]))
      print("Receive status")
      print("  RCTL        = " .. bit.tohex(rctl))
      print("  RXDCTL      = " .. bit.tohex(regs[RXDCTL]))
      print("  RX Enable   = " .. yesno(rctl, 1))
      print("  RX Loopback = " .. yesno(rctl, 6))
      print("  RDH         = " .. regs[RDH])
      print("  RDT         = " .. regs[RDT])
      print("  RDBAH       = " .. bit.tohex(regs[RDBAH]))
      print("  RDBAL       = " .. bit.tohex(regs[RDBAL]))
      print("  RDLEN       = " .. regs[RDLEN])
      print("  RADV        = " .. regs[RADV])
      print("PHY status")
      local phystatus, phyext, copperstatus = phy_read(1), phy_read(15), phy_read(17)
      print("  Autonegotiate state    = " .. (bitset(phystatus,5) and 'complete' or 'not complete'))
      print("  Remote fault detection = " .. (bitset(phystatus,4) and 'remote fault detected' or 'no remote fault detected'))
      print("  Copper Link Status     = " .. (bitset(copperstatus,3) and 'copper link is up' or 'copper link is down'))
      print("  Speed and duplex resolved = " .. yesno(copperstatus,11))
      physpeed = (({10,100,1000,'(reserved)'})[1+bit.band(bit.rshift(status, 6),3)])
      print("  Speed                  = " .. physpeed .. 'Mb/s')
      print("  Duplex                 = " .. (bitset(copperstatus,13) and 'full-duplex' or 'half-duplex'))
      local autoneg, autoneg1G = phy_read(4), phy_read(9)
      print("  Advertise 1000 Mb/s FD = " .. yesno(autoneg1G,9))
      print("  Advertise 1000 Mb/s HD = " .. yesno(autoneg1G,8))
      print("  Advertise  100 Mb/s FD = " .. yesno(autoneg,8))
      print("  Advertise  100 Mb/s HD = " .. yesno(autoneg,7))
      print("  Advertise   10 Mb/s FD = " .. yesno(autoneg,6))
      print("  Advertise   10 Mb/s HD = " .. yesno(autoneg,5))
      local partner, partner1G = phy_read(5), phy_read(10)
      print("  Partner   1000 Mb/s FD = " .. yesno(partner1G,11)) -- reg 10
      print("  Partner   1000 Mb/s HD = " .. yesno(partner1G,10))
      print("  Partner    100 Mb/s FD = " .. yesno(partner,8))
      print("  Partner    100 Mb/s HD = " .. yesno(partner,7))
      print("  Partner     10 Mb/s FD = " .. yesno(partner,6))
      print("  Partner     10 Mb/s HD = " .. yesno(partner,5))
      --   print("Power state              = D"..bit.band(regs[PMCSR],3))
   end

   function yesno (value, bit)
      return bitset(value, bit) and 'yes' or 'no'
   end

   -- Receive functionality

   
   local rxnext = 0
   local rxbuffers = {}
   local rdt = 0

   function init_receive ()
      -- Disable RX and program all the registers
      regs[RCTL] = bits({UPE=3, MPE=4, -- Unicast & Multicast promiscuous mode
            LPE=5,        -- Long Packet Enable (over 1522 bytes)
            BSIZE1=17, BSIZE0=16, BSEX=25, -- 4KB buffers
            SECRC=26,      -- Strip Ethernet CRC from packets
            BAM=15         -- Broadcast Accept Mode
         })
      regs[RFCTL] = bits({EXSTEN=15})  -- Extended RX writeback descriptor format
      regs[RXDCTL] = bits({ GRAN=24, PTHRESH1=1, HTHRESH1=9, WTHRESH1=17 })
      regs[RXCSUM] = bits({ IPOFLD=8, TUOFLD=9, CRCOFL=11, IPCSE=12 })          --ENABLE 
      regs[RADV] = 1     --  1 * 1us rx interrupt absolute delay
      regs[RDTR] = 10    -- 10 * 1us rx interrupt delay timer
      regs[RDLEN] = num_descriptors * ffi.sizeof("union rx")
      --print("DBG: rxdesc_phy = "..tostring(rxdesc_phy))
      regs[RDBAL] = rxdesc_phy % (2^32)
      --print("DBG: regs[RDBAL] = "..tostring(regs[RDBAL]))
      regs[RDBAH] = rxdesc_phy / (2^32) 
      --print("DBG: regs[RDBAH] = "..tostring(regs[RDBAH]))
      regs[RDH] = 0
      regs[RDT] = 0
      rxnext = 0
      rdt = 0
      -- Enable RX
      regs[RCTL] = bit.bor(regs[RCTL], bits{EN=1})
   end

   -- Enqueue a receive descriptor to receive a packet.
   local function add_rxbuf (address)
      -- NOTE: RDT points to the next unused descriptor
      rxdesc[rdt].data.address = address
      rxdesc[rdt].data.dd = 0
      rxbuffers[rdt] = address
      rdt = (rdt + 1) % num_descriptors
      return true
   end M.add_rxbuf = add_rxbuf

   local function flush_rx ()
      regs[RDT] = rdt
   end M.flush_rx = flush_rx

   local function clear_rx()
      rdt = 0
	  rxnext = 0
      regs[RDT] = 0
      regs[RDH] = 0
      C.usleep(1000) -- wait for 1 ms
   end M.clear_rx = clear_rx

   local function ring_pending(head, tail)
      if head == tail then return 0 end
      if head <  tail then return tail - head
      else                 return num_descriptors + tail - head end
   end M.ring_pending = ring_pending

   function M.rx_full ()
      return regs[RDH] == (regs[RDT] + 1) % num_descriptors
   end

   function M.rx_empty ()
      return regs[RDH] == regs[RDT]
   end

   local function rx_pending ()
      return ring_pending(regs[RDH], regs[RDT])
   end M.rx_pending = rx_pending

   local function rx_available ()
      return num_descriptors - rx_pending() - 1
   end M.rx_available = rx_available

   function M.rx_load ()
      return rx_pending() / num_descriptors
   end

   -- Return the next available packet as two values: buffer, length.
   -- If no packet is available then return nil.
   function M.receive ()
      if regs[RDH] ~= rxnext then
         local wb = rxdesc[rxnext].wb
         local index = rxnext
         local length = wb.length
         rxnext = (rxnext + 1) % num_descriptors
         return rxbuffers[index], length
      end
   end

   function M.ack ()
   end

   -- Transmit functionality

      -- Locally cached copy of the Transmit Descriptor Tail (TDT) register.
   -- Updates are kept locally here until flush_tx() is called.
   -- That's because updating the hardware register is relatively expensive.
   local tdt = 0

   function init_transmit ()
      regs[TCTL]        = 0x3103f0f8
      regs[TXDCTL]      = 0x01410000
      regs[TIPG] = 0x00602006 -- Suggested value in data sheet
      init_transmit_ring()
      -- Enable transmit
      regs[TDH] = 0
      regs[TDT] = 0
      regs[TXDCTL]      = 0x01410000
      regs[TCTL]        = 0x3103f0fa
      tdt = 0
   end

   function init_transmit_ring ()
      --print("DBG: txdesc_phy = "..tostring(txdesc_phy))
      regs[TDBAL] = txdesc_phy % (2^32)
      --print("DBG: regs[TDBAL] = "..tostring(regs[TDBAL]))
      regs[TDBAH] = txdesc_phy / (2^32) 
      --print("DBG: regs[TDBAH] = "..tostring(regs[TDBAH]))
      -- Hardware requires the value to be 128-byte aligned
      assert( num_descriptors * ffi.sizeof("union tx") % 128 == 0 )
      regs[TDLEN] = num_descriptors * ffi.sizeof("union tx")
   end


   -- Flags for transmit descriptors.
   local txdesc_flags = bits({dtype=20, eop=24, ifcs=25, dext=29})

   -- Enqueue a transmit descriptor to send a packet.
   local function add_txbuf (address, size)
      txdesc[tdt].data.address = address
      txdesc[tdt].data.optionsL = bit.bor(size, txdesc_flags)
      txdesc[tdt].data.optionsH = 0
      tdt = (tdt + 1) % num_descriptors
   end M.add_txbuf = add_txbuf

   local function flush_tx()
      regs[TDT] = tdt
   end M.flush_tx = flush_tx

   local function clear_tx()
      tdt = 0
      regs[TDT] = 0
      regs[TDH] = 0
      C.usleep(1000) -- wait for 1 ms
   end M.clear_tx = clear_tx

   local function tx_diagnostics()
      print ("DBG: regs[TDFH]  = "..bit.tohex(regs[TDFH]))
      print ("DBG: regs[TDFT]  = "..bit.tohex(regs[TDFT]))
      print ("DBG: regs[TDFHS] = "..bit.tohex(regs[TDFHS]))
      print ("DBG: regs[TDFTS] = "..bit.tohex(regs[TDFTS]))
      print ("DBG: regs[TDFPC] = "..bit.tohex(regs[TDFPC]))
      print ("DBG: regs[PBM]   = "..bit.tohex(regs[PBM]))
      print ("DBG: regs[PBS]   = "..bit.tohex(regs[PBS]))
   end M.tx_diagnostics = tx_diagnostics

   --Note: descriptors = Array of { address, size } elements. Each element must be a data descriptor forming part of packet
   --      size = ethernet frame size (excluding CRC) ; mss = TCP/UDP payload size (excluding headers)
   --      context = uint8_t* ptr (ffi.cast) to context descriptor ; vlan (optional) = Dictionary: { pcp, cfi, vid }
   --Note: when using multiple data descriptors, try to have all headers (Ethernet+IP+TCP) in 1st descriptor (pg 177 of DS)
   local function add_txbuf_tso (descriptors, size, mss, context, vlan)
      assert(descriptors and size and mss and context, "All arguments (except vlan) must be non-nil")
      local ctx = { }
      ctx.tucse  = 0    --TCP/UDP CheckSum End
      ctx.tucso  = 0    --TCP/UDP CheckSum Offset
      ctx.tucss  = 0    --TCP/UDP CheckSum Start
      ctx.ipcse  = 0    --IP CheckSum End
      ctx.ipcso  = 0    --IP CheckSum Offset
      ctx.ipcss  = 0    --IP CheckSum Start
      ctx.mss    = mss  --Maximum Segment Size (TCP/UDP payload size not including headers)
      ctx.hdrlen = 0    --Header Length
      ctx.sta    = 0    --Status  -- bits({rsv2=3, rsv1=2, rsv0=1, dd=0})
      ctx.tucmd  = bits({dext=5, tse=2}) --Command --dext: ctxt desc fmt ; tse: TCP Segmentation Enable
                -- bits({ide=7, snap=6, dext=5, rsv=4, rs=3, tse=2, ip=1, tcp=0})
      ctx.dtype  = 0    --Descriptor Type --Must be 0x0000 for context desc fmt
      ctx.paylen = 0    --Payload Length

      local frame_len = 14 -- Ethernet frame length
      local mem = protected("uint8_t", context, frame_len, 60 + 60) --for accessing IP/TCP header fields
      local ver = bit.band(mem[0], 0x60)
      local ipcs_off = nil -- IP checksum field offset
      local hdr_len  = nil -- IP header length
      local plen_off = nil -- IP payload length field offset
      local prot_off = nil -- IP protocol field offset
      local pkt_len  = nil -- IP packet length 
      local addrs_offset = nil --IP source address field offset
      local addrs_bytes  = nil --Total number of bytes used by IP address fields
      local cs_proto = nil -- protocol field used in checksum calculation

      if ver == 0x40 then --IPv4
        ctx.tucmd = bits({ip=1}, ctx.tucmd) --IPv4 flag
        ipcs_off = 10
        mem[ipcs_off]     = 0   --clear IP header checksum field H
        mem[ipcs_off + 1] = 0   --clear IP header checksum field L
        hdr_len = 4 * bit.band(mem[0], 0x0f) --read IHL field
        assert(hdr_len >= 20, "Invalid value for IPv4 IHL field")
        ctx.ipcse = frame_len + hdr_len - 1
        plen_off = 2
        prot_off = 9
        pkt_len  = bit.bor( bit.lshift(mem[plen_off], 8), mem[plen_off+1] )
        addrs_offset = 12
        addrs_bytes  = 8

      elseif ver == 0x60 then--IPv6
        ipcs_off = 2 -- this will be ignored when flags are set (hopefully) otherwise IP Flow label field will get corrupted
        hdr_len  = 40
        plen_off = 4
        prot_off = 6
        pkt_len  = 40 + bit.bor( bit.lshift(mem[plen_off], 8), mem[plen_off+1] )
        addrs_offset = 8
        addrs_bytes = 32

      else
        assert(false, "Invalid IP version/Unknown format")
      end --ver

      --print("DBG: pkt_len = " .. bit.tohex(pkt_len).." ("..tostring(pkt_len)..")")
      mem[plen_off], mem[plen_off+1] = 0, 0 --reset IP packet length

      ctx.ipcss = frame_len     
      ctx.ipcso = frame_len + ipcs_off

      ctx.tucss = frame_len + hdr_len  -- IP payload (TCP/UDP payload) start
      ctx.tucse = frame_len + pkt_len - 1 -- IP payload (TCP/UDP payload) end

      local protocol = mem[prot_off]

      if protocol == 0x06 then -- TCP specific
        ctx.tucso = frame_len + hdr_len + 16 --TCP checksum offset
        ctx.tucmd = bits({tcp=0}, ctx.tucmd) --set TCP flag

        local tcp_len = 4 * bit.rshift( bit.band( mem[hdr_len+12], 0xF0 ), 4 ) --read Data Offset field 
        --print("DBG: tcp_len = " .. bit.tohex(tcp_len)) --TCP header length
        assert(tcp_len >= 20 , "Invalid value for TCP data offset field")
        ctx.hdrlen = frame_len + hdr_len + tcp_len
        ctx.paylen = pkt_len - hdr_len - tcp_len
        cs_proto = 0x0600

      elseif protocol == 0x11 then --UDP specific
        ctx.tucso  = frame_len + hdr_len + 6 --UDP checksum offset
        ctx.hdrlen = frame_len + hdr_len + 8
        ctx.paylen = pkt_len - hdr_len - 8
        cs_proto = 0x1100

      else
        assert(false, "Invalid/Unimplemented IP data protocol")
      end
       
      local checksum = 0     
 
      for i=addrs_offset, addrs_offset + addrs_bytes - 2, 2 do
        --print("DBG: checksum: Adding: 0x"..bit.tohex(tonumber( bit.bor(bit.lshift(mem[i+1], 8), mem[i]) )))
        checksum = checksum + bit.bor(bit.lshift(mem[i+1], 8), mem[i])
      end
 
      checksum = checksum + cs_proto
      --print("DBG: checksum = "..bit.tohex(tonumber(checksum)))
      checksum = bit.bor(bit.rshift(checksum, 16), bit.band(checksum, 0xffff))
 
      checksum = checksum + bit.rshift(checksum, 16)
 
      --print("DBG: mem[0] = 0x"..bit.tohex(tonumber(bit.band(checksum, 0xff))))
      --print("DBG: mem[1] = 0x"..bit.tohex(tonumber(bit.band(bit.rshift(checksum,8), 0xff))))
     
      mem[ctx.tucso - frame_len]   = bit.band(checksum, 0xff) 
      mem[ctx.tucso - frame_len+1] = bit.band(bit.rshift(checksum,8), 0xff)

      txdesc[tdt].ctx.tucse = ctx.tucse
      txdesc[tdt].ctx.tucso = ctx.tucso
      txdesc[tdt].ctx.tucss = ctx.tucss
      txdesc[tdt].ctx.ipcse = ctx.ipcse
      txdesc[tdt].ctx.ipcso = ctx.ipcso
      txdesc[tdt].ctx.ipcss = ctx.ipcss

      txdesc[tdt].ctx.mss    = ctx.mss
      txdesc[tdt].ctx.hdrlen = ctx.hdrlen
      txdesc[tdt].ctx.rsv_sta = ctx.sta
      
      txdesc[tdt].ctx.tucmd_dtype_paylen = bit.bor( bit.lshift(ctx.tucmd,  24),
                                                    bit.lshift(ctx.dtype,  20),
                                                               ctx.paylen      )

--      print("ctx.tucse = " ..  bit.tohex(tonumber(ctx.tucse)) .." | ".. tonumber(ctx.tucse))
--      print("ctx.tucso = " ..  bit.tohex(tonumber(ctx.tucso)) .." | ".. tonumber(ctx.tucso))
--      print("ctx.tucss = " ..  bit.tohex(tonumber(ctx.tucss)) .." | ".. tonumber(ctx.tucss))
--      print("ctx.ipcse = " ..  bit.tohex(tonumber(ctx.ipcse)) .." | ".. tonumber(ctx.ipcse))
--      print("ctx.ipcso = " ..  bit.tohex(tonumber(ctx.ipcso)) .." | ".. tonumber(ctx.ipcso))
--      print("ctx.ipcss = " ..  bit.tohex(tonumber(ctx.ipcss)) .." | ".. tonumber(ctx.ipcss))
--                                      
--      print("ctx.mss   = " ..  bit.tohex(tonumber(ctx.mss)) .." | ".. tonumber(ctx.mss))
--      print("ctx.hdrlen= " ..  bit.tohex(tonumber(ctx.hdrlen)) .." | ".. tonumber(ctx.hdrlen))
--      print("ctx.sta   = " ..  bit.tohex(tonumber(ctx.sta)) .." | ".. tonumber(ctx.sta))
--                  
--      print("ctx.tucmd = " ..  bit.tohex(tonumber(ctx.tucmd)) .." | ".. tonumber(ctx.tucmd))
--      print("ctx.dtype = " ..  bit.tohex(tonumber(ctx.dtype)) .." | ".. tonumber(ctx.dtype))
--      print("ctx.paylen= " ..  bit.tohex(tonumber(ctx.paylen)) .." | ".. tonumber(ctx.paylen))
--
--      print("DBG: (64) txdesc[tdt] (0) = "..bit.tohex(tonumber(txdesc[tdt].data.address / (2^32))).." "..bit.tohex(tonumber(txdesc[tdt].data.address % (2^32))) )
--      print("DBG: (64) txdesc[tdt] (1) = "..bit.tohex(tonumber(txdesc[tdt].data.optionsH))).." "..bit.tohex(tonumber(txdesc[tdt].data.optionsL )) )
--

      tdt = (tdt + 1) % num_descriptors --next for data descriptors

      assert(#descriptors > 0, "need atleast 1 descriptor")

      for i = 1, #descriptors do

        txdesc[tdt].data.address = descriptors[i].address or assert(false, "descriptor address not given")
        
        local dsize = descriptors[i].size or assert(false, "descriptor size not given")
        local doptionsL = 0
        local doptionsH = 0
  
        if i == #descriptors then --set EOP for last descriptor
          doptionsL = bits({eop=24})
        end

        if ctx.paylen < mss then --why did you even call this function :-P
          doptionsL = bit.bor(dsize, txdesc_flags, doptionsL)
        elseif ver == 0x40 then --IPv4
          doptionsL = bit.bor(dsize, bits({dtype=20, ifcs=25, tse=26, dext=29}), doptionsL)
          doptionsH = bit.bor(bits({ ixsm = 40-32, txsm = 41-32 }), doptionsH)
        elseif ver == 0x60 then --IPv6
          doptionsL = bit.bor(dsize, bits({dtype=20, ifcs=25, tse=26, dext=29}), doptionsL) --ixsm ignored 
          doptionsH = bit.bor(bits({ txsm = 41-32 }), doptionsH)
           
        else
          assert(false, "something's wrong ;-)")
        end

        --print("DBG: CTRL.VME bit = "..bit.tohex( bit.band(regs[CTRL], bits({VME=30})) ))

        --set vlan field, vle bit for all data descriptors (DS says they are valid only for 1st desc)
        --But testing shows 3000 TOTC instead of correct TOTC if the fields are not set for descs > 1
        if vlan ~= nil then
          doptionsL = bit.bor(bits({vle=30}), doptionsL)
          doptionsH = bit.bor(bit.lshift(bit.bor( bit.lshift(vlan.pcp, 13), bit.lshift(vlan.cfi, 12), vlan.vid ), 16),
                              doptionsH)
        end

        --print("DBG: dsize = "..tostring(dsize).." (0x"..bit.tohex(dsize)..")")
       
        --print("DBG: doptions = 0x "..bit.tohex(tonumber(doptionsH)).." "..bit.tohex(tonumber(doptionsL)))

        txdesc[tdt].data.optionsL = doptionsL
        txdesc[tdt].data.optionsH = doptionsH

 --      print("DBG: (64) txdesc[tdt] (0) = "..bit.tohex(tonumber(txdesc[tdt].data.address / (2^32))).." "..bit.tohex(tonumber(txdesc[tdt].data.address % (2^32))) )
--      print("DBG: (64) txdesc[tdt] (1) = "..bit.tohex(tonumber(txdesc[tdt].data.optionsH)).." "..bit.tohex(tonumber(txdesc[tdt].data.optionsL )) )
     
        tdt = (tdt + 1) % num_descriptors
      end

   end M.add_txbuf_tso = add_txbuf_tso
 
   function M.tx_full  () return M.tx_pending() == num_descriptors - 1 end
   function M.tx_empty () return M.tx_pending() == 0 end

   local function tx_pending ()
      return ring_pending(regs[TDH], regs[TDT])
   end M.tx_pending = tx_pending

   local function tx_available ()
      return num_descriptors - tx_pending() - 1
   end M.tx_available = tx_available

   local function tx_load ()
      return tx_pending() / num_descriptors
   end M.tx_load = tx_load

   -- Read a PHY register.
   function phy_read (phyreg)
      regs[MDIC] = bit.bor(bit.lshift(phyreg, 16), bits({OP1=27,PHYADD0=21}))
      phy_wait_ready()
      local mdic = regs[MDIC]
      -- phy_unlock_semaphore()
      assert(bit.band(mdic, bits({ERROR=30})) == 0)
      return bit.band(mdic, 0xffff)
   end

   -- Write to a PHY register.
   function phy_write (phyreg, value)
      regs[MDIC] = bit.bor(value, bit.lshift(phyreg, 16), bits({OP0=26,PHYADD0=21}))
      phy_wait_ready()
      return bit.band(regs[MDIC], bits({ERROR=30})) == 0
   end

   function phy_wait_ready ()
      while bit.band(regs[MDIC], bits({READY=28,ERROR=30})) == 0 do
         ffi.C.usleep(2000)
      end
   end

   function reset_phy ()
      phy_write(0, bits({AutoNeg=12,Duplex=8,RestartAutoNeg=9}))
      ffi.C.usleep(1)
      phy_write(0, bit.bor(bits({RST=15}), phy_read(0)))
   end

   function force_autoneg ()
      ffi.C.usleep(1)
      regs[POEMB] = bit.bor(regs[POEMB], bits({reautoneg_now=5}))
   end

   -- Lock and unlock the PHY semaphore. This is used to avoid race
   -- conditions between software and hardware both accessing the PHY.

   function phy_lock ()
      regs[EXTCNF_CTRL] = bits({MDIO_SW=5})
      while bit.band(regs[EXTCNF_CTRL], bits({MDIO_SW=5})) == 0 do
         ffi.C.usleep(2000)
      end
   end

   function phy_unlock ()
      regs[EXTCNF_CTRL] = 0
   end

   -- Link control.

   function M.linkup ()
      return bit.band(phy_read(17), bits({CopperLink=10})) ~= 0
   end

   function M.enable_phy_loopback ()
      phy_write(0x01, bit.bor(phy_read(0x01), bits({LOOPBACK=14})))
   end

   function M.enable_mac_loopback ()
      regs[RCTL] = bit.bor(bits({LBM0=6}, regs[RCTL]))
   end

   -- Statistics

   local statistics_regs = {
      {"CRCERRS",  0x04000, "CRC Error Count"},
      {"ALGNERRC", 0x04004, "Alignment Error Count"},
      {"RXERRC",   0x0400C, "RX Error Count"},
      {"MPC",      0x04010, "Missed Packets Count"},
      {"SCC",      0x04014, "Single Collision Count"},
      {"ECOL",     0x04018, "Excessive Collision Count"},
      {"MCC",      0x0401C, "Multiple Collision Count"},
      {"LATECOL",  0x04020, "Late Collisions Count"},
      {"COLC",     0x04028, "Collision Count"},
      {"DC",       0x04030, "Defer Count"},
      {"TNCRS",    0x04034, "Transmit with No CRS"},
      {"CEXTERR",  0x0403C, "Carrier Extension Error Count"},
      {"RLEC",     0x04040, "Receive Length Error Count"},
      {"XONRXC",   0x04048, "XON Received Count"},
      {"XONTXC",   0x0403C, "XON Transmitted Count"},
      {"XOFFRXC",  0x04050, "XOFF Received Count"},
      {"XOFFTXC",  0x04054, "XOFF Transmitted Count"},
      {"FCRUC",    0x04058, "FC Received Unsupported Count"},
      {"PRC64",    0x0405C, "Packets Received [64 Bytes] Count"},
      {"PRC127",   0x04060, "Packets Received [65-127 Bytes] Count"},
      {"PRC255",   0x04064, "Packets Received [128-255 Bytes] Count"},
      {"PRC511",   0x04068, "Packets Received [256-511 Bytes] Count"},
      {"PRC1023",  0x0406C, "Packets Received [512-1023 Bytes] Count"},
      {"PRC1522",  0x04070, "Packets Received [1024 to Max Bytes] Count"},
      {"GPRC",     0x04074, "Good Packets Received Count"},
      {"BPRC",     0x04078, "Broadcast Packets Received Count"},
      {"MPRC",     0x0407C, "Multicast Packets Received Count"},
      {"GPTC",     0x04080, "Good Packets Transmitted Count"},
      {"GORCL",    0x04088, "Good Octets Received Count"},
      {"GORCH",    0x0408C, "Good Octets Received Count"},
      {"GOTCL",    0x04090, "Good Octets Transmitted Count"},
      {"GOTCH",    0x04094, "Good Octets Transmitted Count"},
      {"RNBC",     0x040A0, "Receive No Buffers Count"},
      {"RUC",      0x040A4, "Receive Undersize Count"},
      {"RFC",      0x040A8, "Receive Fragment Count"},
      {"ROC",      0x040AC, "Receive Oversize Count"},
      {"RJC",      0x040B0, "Receive Jabber Count"},
      {"MNGPRC",   0x040B4, "Management Packets Received Count"},
      {"MPDC",     0x040B8, "Management Packets Dropped Count"},
      {"MPTC",     0x040BC, "Management Packets Transmitted Count"},
      {"TORL",     0x040C0, "Total Octets Received (Low)"},
      {"TORH",     0x040C4, "Total Octets Received (High)"},
      {"TOTL",     0x040C8, "Total Octets Transmitted (Low)"},
      {"TOTH",     0x040CC, "Total Octets Transmitted (High)"},
      {"TPR",      0x040D0, "Total Packets Received"},
      {"TPT",      0x040D4, "Total Packets Transmitted"},
      {"PTC64",    0x040D8, "Packets Transmitted [64 Bytes] Count"},
      {"PTC127",   0x040DC, "Packets Transmitted [65-127 Bytes] Count"},
      {"PTC255",   0x040E0, "Packets Transmitted [128-255 Bytes] Count"},
      {"PTC511",   0x040E4, "Packets Transmitted [256-511 Bytes] Count"},
      {"PTC1023",  0x040E8, "Packets Transmitted [512-1023 Bytes] Count"},
      {"PTC1522",  0x040EC, "Packets Transmitted [Greater than 1024 Bytes] Count"},
      {"MPTC",     0x040F0, "Multicast Packets Transmitted Count"},
      {"BPTC",     0x040F4, "Broadcast Packets Transmitted Count"},
      {"TSCTC",    0x040F8, "TCP Segmentation Context Transmitted Count"},
      {"TSCTFC",   0x040FC, "TCP Segmentation Context Transmit Fail Count"},
      {"IAC",      0x04100, "Interrupt Assertion Count"}
     }

   M.stats = {}

   function M.update_stats ()
      for _,reg in ipairs(statistics_regs) do
         name, offset, desc = reg[1], reg[2], reg[3]
         M.stats[name] = (M.stats[name] or 0) + regs[offset/4]
      end
   end

   function M.reset_stats ()
      M.stats = {}
   end

   function M.print_stats ()
      print("Statistics for PCI device " .. pciaddress .. ":")
      for _,reg in ipairs(statistics_regs) do
         name, desc = reg[1], reg[3]
         if M.stats[name] > 0 then
            print(("%20s %-10s %s"):format(lib.comma_value(M.stats[name]), name, desc))
         end
      end
   end

   -- Self-test diagnostics

   function M.selftest (options)
      options = options or {}
      io.write("intel selftest: pciaddr="..pciaddress)
      for key,value in pairs(options) do
         io.write(" "..key.."="..tostring(value))
      end
      print()
      local secs = options.secs or 10
      local receive = options.receive or false
      local randomsize = options.randomsize or false
      if options.loopback then
         M.enable_mac_loopback()
      end
      if not options.nolinkup then
         test.waitfor("linkup", M.linkup, 20, 250000)
      end
      if not options.skip_transmit then
         local secs = (options.secs or 10)
         print("Generating traffic for "..tostring(secs).." second(s)...")
         local deadline = C.get_time_ns() + secs * 1000000000LL
         local done = function () return C.get_time_ns() > deadline end
         repeat
            while not done() and tx_load() > 0.75 do C.usleep(10000) end
            if receive then
               for i = 1, rx_available() do
                  add_rxbuf(buffers_phy + 4096)
               end
               flush_rx()
            end
            for i = 1, tx_available() do
               if randomsize then
                  add_txbuf(buffers_phy, math.random(32, 1496))
               else
                  add_txbuf(buffers_phy, 32)
               end
            end
            flush_tx()
            --C.usleep(10000) --10ms ought to be enough for every NIC :-P
         until done()
         M.update_stats()
         M.print_stats()
      end
   end

   -- Test that TCP Segmentation Optimization (TSO) works.
   function M.selftest_tso (options)
      print "selftest: TCP Segmentation Offload (TSO)"
      options = options or {}
      local size    = options.size or 58 --4096
      local mss     = options.mss  or 1442
      local ipv6    = options.ipv6
      local udp     = options.udp
      local receive = options.receive or false
      local multi   = options.multi or 1
      local vlan    = options.vlan

      local txtcp = 1 -- Total number of TCP segments allocated
      local txeth = 0 -- Expected number of ethernet packets sent

      if options.loopback then
         M.enable_mac_loopback()
      end


      --print "waiting for old traffic to die out ..."
      --C.usleep(100000) -- Wait for old traffic from previous tests to die out

      pcie_master_reset() -- will force clearing of pending descriptors

      test.waitfor("linkup", M.linkup, 20, 250000)

      M.update_stats()
      local txhardware_start = M.stats.GPTC
      print("[Before]")
      M.print_stats()
      --M.print_status()
      --M.tx_diagnostics()
     
      txeth = txeth + math.ceil(size / mss)

      if receive then
         --print "adding receive buffers..."
         for i = 1, txeth do --rx_available() do
            add_rxbuf(buffers_phy + 8192 + 5000*(i-1) ) --shouldn't overlap with tx's buffer ;-)
         end
         flush_rx()
      end

      --print "adding tso test buffer..."
      -- Transmit a packet with TSO and count expected ethernet transmits.
      M.add_tso_test_buffer(size, mss, ipv6, udp, multi, vlan)
      
      --print "waiting for packet transmission..."
      -- Wait a safe time and check hardware count
      C.usleep(100000) -- wait for 100ms transmit --WARNING: if the delay is reduced(say, 10ms) will cause NIC lockup
      M.clear_tx()
      --M.clear_rx()
      M.update_stats()
      local txhardware = M.stats.GPTC - txhardware_start 
      print("[After]")
      M.print_stats()
      --M.print_status()

      -- Check results
      print("size", "mss", "txtcp", "txeth", "txhw")
      print(size, mss, txtcp, txeth, txhardware)
      if txeth ~= txhardware then
         print("Expected "..txeth.." packet(s) transmitted but measured "..txhardware)
      end

      local num_pkts = txhardware
      local hdr_len  = nil

      if udp==nil and ipv6==nil then     --TCP + IPv4
         hdr_len = 54
      elseif udp~=nil and ipv6==nil then --UDP + IPv4
         hdr_len = 42
      elseif udp==nil and ipv6~=nil then --TCP + IPv6
         hdr_len = 74
      elseif udp~=nil and ipv6~=nil then --UDP + IPv6
         hdr_len = 62
      end

        print "DBG: verifying received packet data :"

--        assert(rdt > 0 and rdt < num_descriptors, "0 < rdt < num_descriptors")
--        print("rxdesc[rdt-1].wb.mrq = 0x"..bit.tohex(tonumber(rxdesc[rdt-1].wb.mrq)))
--        print("rxdesc[rdt-1].wb.id  = 0x"..bit.tohex(tonumber(rxdesc[rdt-1].wb.id)))
--        print("rxdesc[rdt-1].wb.CS  = 0x"..bit.tohex(tonumber(rxdesc[rdt-1].wb.checksum)))
--        print("rxdesc[rdt-1].wb.STA = 0x"..bit.tohex(tonumber(rxdesc[rdt-1].wb.status)))
--        print("rxdesc[rdt-1].wb.LEN = 0x"..bit.tohex(tonumber(rxdesc[rdt-1].wb.length)))
--        print("rxdesc[rdt-1].wb.VLN = 0x"..bit.tohex(tonumber(rxdesc[rdt-1].wb.vlan)))


		print "Writebacks:\n"

		for pkt=1, num_pkts do
			print("rxdesc["..tostring(pkt-1).."].wb.mrq = 0x"..bit.tohex(tonumber(rxdesc[pkt-1].wb.mrq)))
			print("rxdesc["..tostring(pkt-1).."].wb.id  = 0x"..bit.tohex(tonumber(rxdesc[pkt-1].wb.id)))
			print("rxdesc["..tostring(pkt-1).."].wb.CS  = 0x"..bit.tohex(tonumber(rxdesc[pkt-1].wb.checksum)))
			print("rxdesc["..tostring(pkt-1).."].wb.STA = 0x"..bit.tohex(tonumber(rxdesc[pkt-1].wb.status)))
			print("rxdesc["..tostring(pkt-1).."].wb.LEN = 0x"..bit.tohex(tonumber(rxdesc[pkt-1].wb.length)))
			print("rxdesc["..tostring(pkt-1).."].wb.VLN = 0x"..bit.tohex(tonumber(rxdesc[pkt-1].wb.vlan)))
			print("")
		end
        --print "pkt headers(78) = ["
        print "packets1 = ["
        for pkt=1, num_pkts do
          --print("\nDBG: rx packet "..tostring(pkt).." : ")
          io.write("[ ")
          --local mem = protected("uint8_t", buffers._ptr, 8192 + 5000*(pkt-1), hdr_len+mss)
		  local pkt_size = rxdesc[pkt-1].wb.length
          local mem = protected("uint8_t", buffers._ptr, 8192 + 5000*(pkt-1), pkt_size)
          --local r = M.receive()
          --print(r)
          --for i=0, 78-1 do --hdr_len+mss-1 do
		  for i=0, pkt_size-1 do
--            io.write("buffers["..tostring(i).."] = "..bit.tohex(tonumber(buffers[i])).." | ")
--            io.write("mem["..tostring(i).."] = "..bit.tohex(tonumber(mem[i])).."\n")
           io.write("0x"..bit.tohex(tonumber(mem[i]))..", ")
          end
          io.write(" ],\n")
        end
        print " ]"

      M.clear_rx()

      pcie_master_reset() --force clearing of pending descriptors
      --M.tx_diagnostics()
      --M.init()
   end

   function M.add_tso_test_buffer (size, mss, ipv6, udp, multi, vlan)
      -- Construct a TCP packet of 'size' total bytes (excluding CRC) and transmit with TSO (with TCP MSS = mss bytes)
    
    local packet = nil --packet headers only
    local hdr_len = nil -- IP + TCP/UDP header length

    if size == 58 and ipv6 == nil and udp == nil then --TCP/IPv4 with size 4
      --simple tcp/ip packet header with payload data = "AAAA" (size=4)
      packet = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x08, 0x00, 0x45, 0x00,
                0x00, 0x2C, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x7C, 0xC9, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00,
                0x00, 0x01, 0x00, 0x14, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
                0x20, 0x00, 0x0E, 0xF6, 0x00, 0x00}
      hdr_len = 54

    elseif size == 4096 and ipv6 == nil and udp == nil then --TCP/IPv4 with size 4096
      packet = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x08, 0x00, 0x45, 0x00,
                 0x0F, 0xF2, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x6D, 0x03, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00,
                 0x00, 0x01, 0x00, 0x14, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
                 0x20, 0x00, 0x59, 0x8A, 0x00, 0x00 } --orig
                 --0x20, 0x00, 0xFE, 0x08, 0x00, 0x00 }
      hdr_len = 54

    elseif size == 4096 and ipv6 == nil and udp ~= nil then --UDP/IPv4 with size 4096
      packet = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x08, 0x00, 0x45, 0x00,
                 0x0F, 0xF2, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x6C, 0xF8, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00,
                 0x00, 0x01, 0x03, 0xE7, 0x03, 0xE7, 0x0F, 0xDE, 0x2A, 0xB2 }
      hdr_len = 42

    elseif size == 4096 and ipv6 ~= nil and udp == nil then --TCP/IPv6 with size 4096
      packet = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x86, 0xDD, 0x60, 0x00,  
                 0x00, 0x00, 0x0F, 0xCA, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
                 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xE4, 0x2B, 0x00, 0x00 }
      hdr_len = 74

    elseif size == 4096 and ipv6 ~= nil and udp ~= nil then --UDP/IPv6 with size 4096
      packet = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x86, 0xDD, 0x60, 0x00,
                 0x00, 0x00, 0x0F, 0xCA, 0x11, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0xE7, 0x03, 0xE7, 0x0F, 0xCA, 0xB5, 0x67 }
      hdr_len = 62

--    elseif size == 2922 and ipv6 ~= nil and udp ~= nil then --UDP/IPv6 with size 2922 
--     packet = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0xDD, 0x60, 0x00,
--                0x00, 0x00, 0x0B, 0x34, 0x11, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
--                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
--                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0xE7, 0x03, 0xE7, 0x0B, 0x34, 0x5F, 0x34 } 
--     hdr_len = 62

    else
      assert(false, "Not Implemented Yet ;-)")
    end

    --all headers
    for i = 0, (hdr_len - 1), 1 do
        buffers[i] = packet[i+1]
      --print (buffers[i])
    end

    --generate tcp/udp payload
    for i = 0, (size - hdr_len -1), 1 do
        buffers[hdr_len + i] = 0x41 --char 'A'
    end


    --M.add_txbuf(buffers_phy, 58)
    local descriptors = nil

    if multi == 1 then
      descriptors = { {address = buffers_phy, size = size} }
    elseif multi == 2 then
      descriptors = { {address = buffers_phy, size = hdr_len}, 
                      {address = buffers_phy + hdr_len, size = size - hdr_len} }
    elseif multi == 3 and size == 4096 then
      print("DBG: size = "..tostring(size))
      print("DBG: DD1 size = hdr_len = "..tostring(hdr_len))
      print("DBG: DD2 size = 1024")
      print("DBG: DD3 size = size - hdr_len - 1024 = "..tostring(size - hdr_len - 1024))
      descriptors = { {address = buffers_phy, size = hdr_len}, 
                      {address = buffers_phy + hdr_len, size = 1024},
                      {address = buffers_phy + hdr_len + 1024, size = size - hdr_len - 1024} }
    else
      assert(false, "Not Implemented yet!! ;-)")
    end

    M.add_txbuf_tso( descriptors, size, mss, buffers._ptr, vlan )
    M.flush_tx()
    --M.tx_diagnostics()
   end

	function gen_msg(item_str, received, expected, index1, index2)
		if index1 ~= nil then index1 = "Index: ["..tostring(index1).."]" else index1 = "" end
		if index2 ~= nil then index1 = index1.."["..tostring(index2).."]" end
		return string.format("%s Got %s = %s | Expected = %s", index1, item_str, "0x"..bit.tohex(received), "0x"..bit.tohex(expected))
	end

	--TSO tx+rx loopback test with verification of receive buffers and writebacks.
	--this is useful for STT testing.
	-- for e.g.:
	-- transmit = { buffers = { { 0x00, ... , 0xdc }, { 0xdd, ... , 0xff } },
	--              mss     = 1422
	--              vlan    = { pcp=0, cfi=0, id=0x01 }
	--            }
	-- receive  = { buffers = { { 0x00, ... , 0x6f }, { 0x70, ... , 0xff } }
	--              writebacks  = { { mrq=0x00, id=0x00, checksum=0x00, status=0x00, length=0x70, vlan=0x01 },
	--                              { mrq=0x00, id=0x01, checksum=0x00, status=0x00, length=0x90, vlan=0x01 }
	--                            },
	--            }
	-- statistics = { TPR=3, TPT=3 }
	function M.verify_tso(transmit, receive, statistics)
		local buf_tail = 0
		local tx_descs = {} -- transmit descriptors for transmit.buffers
		local tx_size  = 0  -- total size of transmitted packet

        M.enable_mac_loopback()
		pcie_master_reset() -- will force clearing of pending descriptors

		test.waitfor("linkup", M.linkup, 20, 250000)

--		print("DBG: verify_tso: Statistics [Before]")
		M.update_stats()
--		M.print_stats()
		
		--copy transmit.buffers to buffers
		for i=1, #transmit.buffers do
			tx_descs[1 + #tx_descs] = { address = buffers_phy + buf_tail, size = #transmit.buffers[i] }
			tx_size = tx_size + #transmit.buffers[i]

			for j=1, #transmit.buffers[i] do
				buffers[buf_tail] = transmit.buffers[i][j]
				buf_tail = buf_tail + 1
			end
		end
	
		local rx_start = buf_tail --offset to start of rx buffers

		--add receive descriptors for receive.packets
		for i=1, #receive.buffers do
			M.add_rxbuf( buffers_phy + buf_tail ) -- + rx_start + 5000*(i-1) )
			buf_tail = buf_tail + 8192 --#receive.buffers[i] --XXX add spacer?
		end
		M.flush_rx()
	
		M.add_txbuf_tso( tx_descs, tx_size, transmit.mss, buffers._ptr, transmit.vlan )

		M.flush_tx()
		C.usleep(100000) --wait for 100ms so that transmission is completed
		M.clear_tx()

--		print("DBG: verify_tso: Statistics [After]")
		M.update_stats()
		M.print_stats()

		for k, v in pairs(statistics) do
			assert( M.stats[k] == v, gen_msg("M.stats["..k.."]", M.stats[k], v) )
		end
	
--        print "packets2 = ["
		--verify the received packet buffers and writebacks
		for i=1, #receive.buffers do
--          io.write("[ ")
		  		   --print(gen_msg("mrq", rxdesc[i-1].wb.mrq, receive.writebacks[i].mrq, i))
			assert(rxdesc[i-1].wb.mrq == receive.writebacks[i].mrq,     
		  		   gen_msg("mrq", rxdesc[i-1].wb.mrq, receive.writebacks[i].mrq, i))

	  			   --print(gen_msg("id", rxdesc[i-1].wb.id, receive.writebacks[i].id, i))
			assert(rxdesc[i-1].wb.id == receive.writebacks[i].id,
	  			   gen_msg("id", rxdesc[i-1].wb.id, receive.writebacks[i].id, i))

				   --print(gen_msg("checksum", rxdesc[i-1].wb.checksum, receive.writebacks[i].checksum, i))
			assert(rxdesc[i-1].wb.checksum == receive.writebacks[i].checksum,
				   gen_msg("checksum", rxdesc[i-1].wb.checksum, receive.writebacks[i].checksum, i))

		  		   --print(gen_msg("status", rxdesc[i-1].wb.status, receive.writebacks[i].status, i))
			assert(rxdesc[i-1].wb.status == receive.writebacks[i].status,
		  		   gen_msg("status", rxdesc[i-1].wb.status, receive.writebacks[i].status, i))

		  		   --print(gen_msg("length", rxdesc[i-1].wb.length, receive.writebacks[i].length, i))
			assert(rxdesc[i-1].wb.length == receive.writebacks[i].length,
		  		   gen_msg("length", rxdesc[i-1].wb.length, receive.writebacks[i].length, i))

	  			   --print(gen_msg("vlan", rxdesc[i-1].wb.vlan, receive.writebacks[i].vlan, i))
			assert(rxdesc[i-1].wb.vlan == receive.writebacks[i].vlan,
	  			   gen_msg("vlan", rxdesc[i-1].wb.vlan, receive.writebacks[i].vlan, i))

			local mem = protected("uint8_t", buffers._ptr, rx_start, #receive.buffers[i])
			rx_start = rx_start + 8192 --#receive.buffers[i]

			for j=1, #receive.buffers[i] do
--			   io.write("0x"..bit.tohex(tonumber(mem[j-1]))..", ")
				assert(mem[j-1] == receive.buffers[i][j], 
					   gen_msg("buffer", mem[j-1], receive.buffers[i][j], i, j))
			end
--          io.write(" ],\n")
		end --for i
--        print " ]"

		M.clear_rx()
		pcie_master_reset()

		print "[PASS]" -- :-)
	end

	--create a copy of the given table
	function table.copy(t)
		local u = { }
		for k, v in pairs(t) do u[k] = v end
		return setmetatable(u, getmetatable(t))
	end

	--This function tests tso verification
	function M.selftest_verify_tso()

		--CONFIGURATION START--
		local size, desc2_size = 4096, 1024
		local vlan_id = 0x00
		                    --Ethernet+IPv6+TCP headers
		local tx_header = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x86, 0xDD, 0x60, 0x00,
						    0x00, 0x00, 0x0F, 0xCA, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xE4, 0x2B, 0x00, 0x00 }
		
	    local rx_fields = { { ip_len_h=0x05, ip_len_l=0xa2, tcp_seq_1=0x00, tcp_seq_0=0x00, tcp_cs_h=0x4d, tcp_cs_l=0xb3 },
						    { ip_len_h=0x05, ip_len_l=0xa2, tcp_seq_1=0x05, tcp_seq_0=0x8e, tcp_cs_h=0x48, tcp_cs_l=0x25 },
							{ ip_len_h=0x04, ip_len_l=0xae, tcp_seq_1=0x0b, tcp_seq_0=0x1c, tcp_cs_h=0x5c, tcp_cs_l=0xa4 } }
		
		local rx_writebacks = { { mrq=0x00, id=0x00, checksum=0x09df, status=0x060023, length=0x05d8, vlan=vlan_id },
						        { mrq=0x00, id=0x00, checksum=0x09df, status=0x060023, length=0x05d8, vlan=vlan_id },	
						        { mrq=0x00, id=0x00, checksum=0x09df, status=0x060023, length=0x04e4, vlan=vlan_id } }
		
		local statistics = { PRC1522=3, GPRC=3, MPRC=3, GPTC=3, GORCL=4256, GOTCL=4256, MPTC=3, TORL=4256, TOTL=4256, 
							 TPR=3, TPT=3, PTC1522=3, MPTC=3, TSCTC=1 }
		--CONFIGURATION END--

		local transmit, receive = {}, {}
		local buf = nil
		local pkt_fields = { ip_len_h=19, ip_len_l=20, tcp_seq_1=61, tcp_seq_0=62, tcp_cs_h=71, tcp_cs_l=72 } --offsets

		transmit.buffers = { tx_header, {}, {} }
		transmit.mss = 1500 - (#tx_header + 4) -- note: 4 = CRC length
		if vlan_id ~= 0 then
			transmit.vlan = { pcp=0, cfi=0, vid=vlan_id }
		end
		receive.writebacks = rx_writebacks

		buf = transmit.buffers[2]

		for i=1, desc2_size do
			buf[1 + #buf] = 0x41 --char 'A' 	
		end
		
		buf = transmit.buffers[3]

		for i=1, size - #tx_header - desc2_size do
			buf[1 + #buf] = 0x41 --char 'A'
		end

		receive.buffers = {}
		local rx_remain = size - #tx_header

		for i=1, math.ceil(size / transmit.mss) do
			receive.buffers[i] = table.copy(transmit.buffers[1]) --copy Ethernet+IP+TCP header from transmit
			
			for k, v in pairs(pkt_fields) do
				receive.buffers[i][v] = rx_fields[i][k] -- changed header fields
			end
			
			local count = nil
			if rx_remain > transmit.mss then count = transmit.mss else count = rx_remain end
		
			for j=1, count do
				receive.buffers[i][1 + #receive.buffers[i]] = 0x41 --char 'A'
			end
			rx_remain = rx_remain - transmit.mss
		end

		print "selftest_verify_tso: "
--		print("DBG: #receive.buffers[1] = "..tostring(#receive.buffers[1]))
--		print("DBG: #receive.buffers[2] = "..tostring(#receive.buffers[2]))
--		print("DBG: #receive.buffers[3] = "..tostring(#receive.buffers[3]))
		M.verify_tso(transmit, receive, statistics)

	end --M.selftest_verify_tso()


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
		--check ethernet headers --XXX use memcmp?
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
	--Receive a "big" packet using software emulated LRO
	--Parameters: buf_address - memory address to copy the received packet
	--            buf_size    - size of the buffer
	--Returns: Tuple (length, num_of_packets) [Note: length bytes of given buffer that got used]
	--            OR (nil, "Error message")
	function M.receive_lro(buf_address, buf_size)
		if M.rx_empty() then 
			return nil, "Empty rx ring"
		else
			local pkt_count = 0 --num of rx packets that make up the "big" packet
			local buf_used = 0
			local big_pkt = nil
			local start_addr = nil
			local big_pkt_paylen = 0 -- payload length of "big" packet

			while rxnext < M.regs[RDH] do --read the newly written rx packets
			
				--handle packets with rxdesc[rxnext].wb.status showing invalid IP/TCP checksums
				if rxdesc[rxnext].wb.status ~= 0x060023 then --in-correct status for Eth+IPv6+TCP
					rxnext = (rxnext + 1) % num_descriptors --skip this packet
				else
					local pkt = unprotected("struct frame_hdr", rxbuffers[rxnext])
					assert(pkt.eth.type == 0x86DD and 
						   bit.band(pkt.ipv6.ver_traf_flow, 0xf0000000) == 0x60000000 and
						   pkt.ipv6.next_hdr == 0x06,
						   "NYI: Only Eth + IPv6 + TCP(STT) supported ATM")
					
					local cp_offset, cp_length = 0, 0 --copy parameters
					
					if pkt_count = 0 then --first rx packet
						start_addr = rxbuffers[rxnext]
						cp_length = rxdesc[rxnext].wb.length
						big_pkt = unprotected("struct frame_hdr", buf_address)

					elseif not match_packets(pkt, big_pkt, big_pkt_paylen) then
						break --out of while loop
					else
						cp_offset = ffi.sizeof(ffi.typeof("struct frame_hdr")) --skip the current packet's headers
						assert(pkt.ipv6.pay_len == (rxdesc[rxnext].wb.length - cp_offset),"payload lengths are not matching")
						cp_length = rxdesc[rxnext].wb.length - cp_offset
					end

					assert( (buf_size - buf_used -1) >= cp_length, "Insufficient buffer size") --1 byte for padding
					ffi.copy(buf_address + buf_used, rxbuffers[rxnext] + cp_offset, cp_length)
					buf_used = buf_used + cp_length

					big_pkt_paylen = big_pkt_paylen + pkt.ipv6.pay_len
					rxnext = (rxnext + 1) % num_descriptors
					pkt_count = pkt_count + 1
				end --if else rxdesc[rxnext].wb.status
			end --while loop

			pkt = unprotected("struct frame_hdr", start_addr) --access big packet
			pkt.ipv6.pay_len = big_pkt_paylen --set its payload length
			pkt.seg.checksum = 0

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
		end --if (M.rx_empty) else
	end

   return M
end
