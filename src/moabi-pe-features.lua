--============================================================================
local M = {}
--  MOABI-PE-FEATURES v1.0 — PE → 28-dim Feature Vector Mapper
--============================================================================

local LOG2 = math.log(2)

local function entropy(data, size)
    if size <= 0 then return 0 end
    local hist = {}
    for i=0,255 do hist[i]=0 end
    for i=1,size do
        local b = data:byte(i)
        hist[b] = hist[b] + 1
    end
    local e = 0
    for i=0,255 do
        if hist[i] > 0 then
            local p = hist[i] / size
            e = e - p * (math.log(p) / LOG2)
        end
    end
    return e
end

function M.extract_pe_features(filepath)
    local f = io.open(filepath, "rb")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    local size = #data
    if size < 64 then return nil end
    
    -- Parse PE header
    if data:sub(1,2) ~= "MZ" then return nil end
    
    local pe_offset = 0
    local b1, b2, b3, b4 = data:byte(61), data:byte(62), data:byte(63), data:byte(64)
    pe_offset = b1 + b2*256 + b3*65536 + b4*16777216
    
    if pe_offset + 4 > size then return nil end
    if data:sub(pe_offset+1, pe_offset+4) ~= "PE\0\0" then return nil end
    
    -- COFF Header (20 bytes after PE signature)
    local coff = pe_offset + 5
    if coff + 20 > size then return nil end
    
    local machine = data:byte(coff+1) + data:byte(coff+2)*256
    local section_count = data:byte(coff+3) + data:byte(coff+4)*256
    
    -- Optional Header
    local opt = coff + 20
    local opt_magic = data:byte(opt+1) + data:byte(opt+2)*256
    local is_pe32plus = (opt_magic == 0x20b)  -- PE32+
    
    local subsystem = 0
    if is_pe32plus then
        subsystem = data:byte(opt+69) + data:byte(opt+70)*256
    else
        subsystem = data:byte(opt+69) + data:byte(opt+70)*256
    end
    
    -- Parse imports from Data Directory
    local import_rva = 0
    if is_pe32plus then
        import_rva = data:byte(opt+113) + data:byte(opt+114)*256 + data:byte(opt+115)*65536 + data:byte(opt+116)*16777216
    else
        import_rva = data:byte(opt+105) + data:byte(opt+106)*256 + data:byte(opt+107)*65536 + data:byte(opt+108)*16777216
    end
    
    -- Count imports by scanning for DLL name strings
    local dll_count = 0
    local dlls = {}
    for dll in data:gmatch("([%w_%-]+)%.dll") do
        dll = dll:lower()
        if not dlls[dll] then
            dlls[dll] = true
            dll_count = dll_count + 1
        end
    end
    
    -- Detect library patterns
    local has_ssl = data:find("ssl", 1, true) ~= nil
    local has_crypto = data:find("crypto", 1, true) ~= nil
    local has_curl = data:find("curl", 1, true) ~= nil
    local has_zlib = data:find("zlib", 1, true) ~= nil or data:find("libz", 1, true) ~= nil
    
    -- Compute entropy
    local ent = entropy(data, size)
    
    -- Build 28-dim vector matching ELF feature order
    local vec = {
        math.log(size + 1),           -- 1: size_log
        ent,                           -- 2: entropy
        0, 0, 0, 0,                    -- 3-6: byte_mean, byte_stddev, null_ratio, printable_ratio (placeholder)
        is_pe32plus and 2 or 1,        -- 7: is_elf → machine class (1=32bit, 2=64bit)
        is_pe32plus and 2 or 1,        -- 8: elf_class_num → PE32+ = 2
        subsystem == 2 and 2 or (subsystem == 3 and 3 or 0),  -- 9: elf_type_num → gui=2, cui=3
        0, 0, 0,                       -- 10-12: entropy_variance, high/low entropy_ratio
        0, 0,                           -- 13-14: top_byte_ratio, ff_ratio
        section_count,                  -- 15: section_count
        dll_count,                      -- 16: import_count
        0,                              -- 17: export_count
        0,                              -- 18: symbol_size
        0,                              -- 19: has_debug
        has_ssl and 1 or 0,             -- 20: has_libssl
        has_crypto and 1 or 0,          -- 21: has_libcrypto
        has_curl and 1 or 0,            -- 22: has_libcurl
        has_zlib and 1 or 0,            -- 23: has_libz
        0, 0, 0, 0, 0                  -- 24-28: other libs
    }
    
    return vec
end

return M
