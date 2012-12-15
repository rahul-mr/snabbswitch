module(...,package.seeall)

-- From virtual page to physical page
local cache = {}
local pagesize = 4096

-- Return the 64-bit physical address of virt_addr.
function map (virt_addr)
   virt_addr = ffi.cast("int64_t", virt_addr)
   local virtpage = tonumber(virt_addr / page_size)
   local offset   = tonumber(virt_addr % page_size)
   local physpage = cache[virtpage] or resolve(virtpage)
   return ffi.cast("int64_t", physpage * pagesize + offset)
end

-- Return (and cache) the physical page number of virtpage.
function resolve (virtpage)
   local physpage = C.virt_to_phys(page)
   if phys_page == 0 then error("Unable to resolve page " .. virt_page) end
   cache[virtpage] = physpage
   return phys_page
end

