module(...,package.seeall)

local ffi = require("ffi")

function readfile (filename, what)
   local f = io.open(filename, "r")
   if f == nil then error("Unable to open file: " .. filename) end
   local value = f:read(what)
   f:close()
   return value
end

function writefile (filename, value)
   local f = io.open(filename, "w")
   if f == nil then error("Unable to open file: " .. filename) end
   local result = f:write(value)
   f:close()
   return result
end

-- Return a bitmask using the values of `bitset' as indexes.
-- The keys of bitset are ignored (and can be used as comments).
-- Example: bits({RESET=0,ENABLE=4}, 123) => 1<<0 | 1<<4 | 123
function bits (bitset, basevalue)
   local sum = basevalue or 0
   for _,n in pairs(bitset) do
	 sum = bit.bor(sum, bit.lshift(1, n))
   end
   return sum
end

-- Return true if bit number 'n' of 'value' is set.
function bitset (value, n)
   return bit.band(value, bit.lshift(1, n)) ~= 0
end

function protected (type, base, offset, size)
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

function bitset2(value, flags)
  if type(flags) == 'table' then
	for _, v in pairs(flags) do
		if bit.band(value, bit.lshift(1, v)) == 0 then 
			return false 
		end
	end
	return true
  elseif type(flags) == 'number' then --assume number is bitmask
	  return bit.band(value, flags) == flags
  else
	  assert(false, 'Invalid type')
  end
end

function bitrange(from, to)
   assert(from >= 0 and to >= 0 and from ~= to)
   if from > to then --swap
	   local temp = from
	   from = to
	   to = temp
   end
   return bit.bxor( math.pow(2, to+1) - 1, math.pow(2, from) - 1 )	
end

function bitfield(value, from, to)
	return bit.rshift( bit.band(value, bitrange(from, to)), math.min(from, to) )
end

function comma_value(n) -- credit http://richard.warburton.it
   local left,num,right = string.match(n,'^([^%d]*%d)(%d*)(.-)$')
   return left..(num:reverse():gsub('(%d%d%d)','%1,'):reverse())..right
end

--create a copy of the given table
function table_copy(t)
	local u = { }
	for k, v in pairs(t) do u[k] = v end
	return setmetatable(u, getmetatable(t))
end

--returns pointer to element of 'type' located at 'base'+'offset' address (without any protection ;-))
function unprotected(type, base, offset)
	offset = offset or 0
	return ffi.cast( ffi.typeof("$ *", ffi.typeof(type)),
					 ffi.cast("uint8_t *", base) + offset)
end

