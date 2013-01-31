module(...,package.seeall)

local ffi = require("ffi")
local C = ffi.C

function new()
   _pvt = { }
   setmetatable(_pvt, { __mode = "kv" }) --weak keys and values
   
   F = { }
   setmetatable(F, { __index = function(t, key)
                                 local v = rawget(_pvt, key)

                                 if type(v) == "table" then
                                   assert(v.expiry ~= nil and v.port ~= nil, "Invalid dict value for _pvt[key]")

                                   if v.expiry <= C.get_time_ns() then --expired
                                      rawset(_pvt, key, nil)
                                      return nil
                                   else --not expired
                                      return v.port
                                   end

                                 else
                                   return nil
                                 end
                              end,
   
                     __newindex = function(t, key, value)
                                    rawset(_pvt, key, value)
                                  end
                     }) 

   rawset(F, 999, _pvt)

   return F
end

function fdb_add(F, address, sw_port, ttl) --ttl in seconds
   F[address] = {port = sw_port,  expiry = (C.get_time_ns() + ttl * 10^9) }
end

function fdb_pairs(F)
  return pairs(rawget(F, 999))
end

function pp_key(s)
  if s == "\x00\x00\x00\x00\x00\x00" then
    return "00:00:00:00:00:00"
  elseif s == "\x01\x01\x01\x01\x01\x01" then
    return "01:01:01:01:01:01"
  elseif s == "\x02\x02\x02\x02\x02\x02" then
    return "02:02:02:02:02:02"
  else
    return "???" --hmmm
  end
end

function pp_val(t)
  if t == nil then
    return "nil"
  else
    return string.format("{ port = %d, expiry = %d }", t.port, tonumber(t.expiry))
  end
end

function selftest()
   print("\nDBG: selftest(): starting\n")

   local F = new()
   fdb_add(F, "\x00\x00\x00\x00\x00\x00", 0, 2)
   fdb_add(F, "\x01\x01\x01\x01\x01\x01", 1, 4)
   fdb_add(F, "\x02\x02\x02\x02\x02\x02", 2, 6)

   for i=1,4,1 do
     print("\nDBG: i="..tostring(i))
     print(" F[00:00:00:00:00:00] = "..tostring(F["\x00\x00\x00\x00\x00\x00"]))
     print(" F[01:01:01:01:01:01] = "..tostring(F["\x01\x01\x01\x01\x01\x01"]))
     print(" F[02:02:02:02:02:02] = "..tostring(F["\x02\x02\x02\x02\x02\x02"]))
     print("")
     for k, v in fdb_pairs(F) do
       io.write(string.format(" key = %s ; value = %s\n", pp_key(k), pp_val(v)))
     end
     print("DBG: sleeping 2 seconds")
     C.usleep(2*10^6)
   end
end  

