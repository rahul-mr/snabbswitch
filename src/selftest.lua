module(...,package.seeall)

local intel = require "intel"
local ffi = require "ffi"
local C = ffi.C
local test = require("test")
local memory = require("memory")

assert(C.lock_memory() == 0)

memory.selftest({verbose = false})
pci.selftest()

for _,device in ipairs(pci.suitable_devices()) do
   local pciaddress = device.pciaddress
   print("selftest: intel device "..pciaddress)
   if not pci.prepare_device(pciaddress) then
      error("Failed to prepare PCI device: " .. device.pciaddress)
   end
   local nic = intel.new(pciaddress)
   print "NIC transmit test"
   nic.init()
   nic.selftest({secs=1})
   print "NIC transmit+receive loopback test"
   nic.init()
   nic.reset_stats()
   nic.selftest({secs=1,loopback=true,receive=true})
   print "NIC transmit tso test - defaults"
   nic.init()
   nic.reset_stats()
   nic.selftest_tso()
   print "NIC transmit tso test - size=4096, mss=1500"
   nic.init()
   nic.reset_stats()
   nic.selftest_tso({size=4096, mss=1500})
   print "NIC transmit+receive loopback tso test - size=4096, mss=1500"
   nic.init()
   nic.reset_stats()
   nic.selftest_tso({size=4096, mss=1500, loopback=true, receive=true})
--   -- nic.selftest({packets=10000000})
end

