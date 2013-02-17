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
   print "\nNIC transmit test"
   nic.init()
   nic.selftest({secs=1})
   print "\nNIC transmit+receive loopback test"
   nic.init()
   nic.reset_stats()
   nic.selftest({secs=1,loopback=true,receive=true})
--   print "\nNIC tx tso test - defaults (TCP, IPv4, size=58, mss=1442)" 
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso()
--   print "\nNIC tx tso test - TCP, IPv4, size=4096, mss=1442" -- max frame size = 1500 (54 + 1442 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({size=4096, mss=1442})
--   print "\nNIC tx+rx loopback tso test - TCP, IPv4, size=4096, mss=1442" -- max frame size = 1500 (54 + 1442 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({size=4096, mss=1442, loopback=true, receive=true})
--   print "\nNIC tx tso test - UDP, IPv4, size=4096, mss=1454" -- max frame size = 1500 (42 + 1454 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, size=4096, mss=1454})
--   print "\nNIC tx+rx loopback tso test - UDP, IPv4, size=4096, mss=1454" -- max frame size = 1500 (42 + 1454 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, size=4096, mss=1454, loopback=true, receive=true})
--   print "\nNIC tx tso test - TCP, IPv6, size=4096, mss=1422" -- max frame size = 1500 (74 + 1422 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({ipv6=true, size=4096, mss=1422})
--   print "\nNIC tx+rx loopback tso test - TCP, IPv6, size=4096, mss=1422" -- max frame size = 1500 (74 + 1422 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({ipv6=true, size=4096, mss=1422, loopback=true, receive=true})
--   print "\nNIC tx tso test - UDP, IPv6, size=4096, mss=1434" -- max frame size = 1500 (62 + 1434 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, ipv6=true, size=4096, mss=1434})
--   print "\nNIC tx+rx loopback tso test - UDP, IPv6, size=4096, mss=1434" -- max frame size = 1500 (62 + 1434 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, ipv6=true, size=4096, mss=1434, loopback=true, receive=true})
--   
--   --Multiple descriptor tests
--   print "\nNIC tx+rx loopback tso test - TCP, IPv4, size=4096, mss=1442, multi=2" -- max frame size = 1500 (54 + 1442 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({size=4096, mss=1442, loopback=true, receive=true, multi=2})
--   print "\nNIC tx+rx loopback tso test - TCP, IPv4, size=4096, mss=1442, multi=3" -- max frame size = 1500 (54 + 1442 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({size=4096, mss=1442, loopback=true, receive=true, multi=3})
--   print "\nNIC tx+rx loopback tso test - UDP, IPv4, size=4096, mss=1454, multi=2" -- max frame size = 1500 (42 + 1454 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, size=4096, mss=1454, loopback=true, receive=true, multi=2})
--   print "\nNIC tx+rx loopback tso test - UDP, IPv4, size=4096, mss=1454, multi=3" -- max frame size = 1500 (42 + 1454 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, size=4096, mss=1454, loopback=true, receive=true, multi=3})
--   print "\nNIC tx+rx loopback tso test - TCP, IPv6, size=4096, mss=1422, multi=2" -- max frame size = 1500 (74 + 1422 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({ipv6=true, size=4096, mss=1422, loopback=true, receive=true, multi=2})
--   print "\nNIC tx+rx loopback tso test - TCP, IPv6, size=4096, mss=1422, multi=3" -- max frame size = 1500 (74 + 1422 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({ipv6=true, size=4096, mss=1422, loopback=true, receive=true, multi=3})
--   print "\nNIC tx+rx loopback tso test - UDP, IPv6, size=4096, mss=1434, multi=2" -- max frame size = 1500 (62 + 1434 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, ipv6=true, size=4096, mss=1434, loopback=true, receive=true, multi=2})
--   print "\nNIC tx+rx loopback tso test - UDP, IPv6, size=4096, mss=1434, multi=3" -- max frame size = 1500 (62 + 1434 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, ipv6=true, size=4096, mss=1434, loopback=true, receive=true, multi=3})
--   
--   --VLAN tests
   print "\nNIC tx+rx loopback tso test - TCP, IPv4, size=4096, mss=1442, vlan={pcp=2, cfi=0, vid=19}"
   nic.init()
   nic.reset_stats()
   nic.selftest_tso({size=4096, mss=1442, loopback=true, receive=true, vlan={pcp=2, cfi=0, vid=19}})
--   print "\nNIC tx+rx loopback tso test - TCP, IPv4, size=4096, mss=1442, multi=2, vlan={pcp=2, cfi=0, vid=19}"
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({size=4096, mss=1442, loopback=true, receive=true, multi=2, vlan={pcp=2, cfi=0, vid=19}})
--   print "\nNIC tx+rx loopback tso test - TCP, IPv4, size=4096, mss=1442, multi=3, vlan={pcp=2, cfi=0, vid=19}"
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({size=4096, mss=1442, loopback=true, receive=true, multi=3, vlan={pcp=2, cfi=0, vid=19}})
--
--   print "\nNIC tx+rx loopback tso test - UDP, IPv4, size=4096, mss=1454, vlan={pcp=2, cfi=0, vid=19}"
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, size=4096, mss=1454, loopback=true, receive=true, vlan={pcp=2, cfi=0, vid=19}})
--   print "\nNIC tx+rx loopback tso test - UDP, IPv4, size=4096, mss=1454, multi=2, vlan={pcp=2, cfi=0, vid=19}"
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, size=4096, mss=1454, loopback=true, receive=true, multi=2, vlan={pcp=2, cfi=0, vid=19}})
--   print "\nNIC tx+rx loopback tso test - UDP, IPv4, size=4096, mss=1454, multi=3, vlan={pcp=2, cfi=0, vid=19}"
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, size=4096, mss=1454, loopback=true, receive=true, multi=3, vlan={pcp=2, cfi=0, vid=19}})
--
--   print "\nNIC tx+rx loopback tso test - TCP, IPv6, size=4096, mss=1422, vlan={pcp=2, cfi=0, vid=19}" 
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({ipv6=true, size=4096, mss=1422, loopback=true, receive=true, vlan={pcp=2, cfi=0, vid=19}})
--   print "\nNIC tx+rx loopback tso test - TCP, IPv6, size=4096, mss=1422, multi=2, vlan={pcp=2, cfi=0, vid=19}" 
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({ipv6=true, size=4096, mss=1422, loopback=true, receive=true, multi=2, vlan={pcp=2, cfi=0, vid=19}})
--   print "\nNIC tx+rx loopback tso test - TCP, IPv6, size=4096, mss=1422, multi=3, vlan={pcp=2, cfi=0, vid=19}" 
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({ipv6=true, size=4096, mss=1422, loopback=true, receive=true, multi=3, vlan={pcp=2, cfi=0, vid=19}})
--
--   print "\nNIC tx+rx loopback tso test - UDP, IPv6, size=4096, mss=1434, vlan={pcp=2, cfi=0, vid=19}"
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, ipv6=true, size=4096, mss=1434, loopback=true, receive=true, vlan={pcp=2, cfi=0, vid=19}})
--   print "\nNIC tx+rx loopback tso test - UDP, IPv6, size=4096, mss=1434, multi=2, vlan={pcp=2, cfi=0, vid=19}"
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, ipv6=true, size=4096, mss=1434, loopback=true, receive=true, multi=2, vlan={pcp=2, cfi=0, vid=19}})
--   print "\nNIC tx+rx loopback tso test - UDP, IPv6, size=4096, mss=1434, multi=3, vlan={pcp=2, cfi=0, vid=19}"
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, ipv6=true, size=4096, mss=1434, loopback=true, receive=true, multi=3, vlan={pcp=2, cfi=0, vid=19}})
--
--   print "\nNIC tx tso test - UDP, IPv6, size=2922, mss=1430, vlan" -- max frame size = 1500 (14 + 4 + 40 + 8 + 1430 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, ipv6=true, size=2922, mss=1430, vlan={pcp=2, cfi=0, vid=19}})
--   print "\nNIC tx tso test - UDP, IPv6, size=2922, mss=1430 " -- max frame size =  (14 + 40 + 8 + 1430 + 4)
--   nic.init()
--   nic.reset_stats()
--   nic.selftest_tso({udp=true, ipv6=true, size=2922, mss=1430})
--   -- nic.selftest({packets=10000000})
end

