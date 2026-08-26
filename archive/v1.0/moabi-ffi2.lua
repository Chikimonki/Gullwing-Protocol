#!/usr/bin/env luajit
--============================================================================
--  MOABI-FFI v1.0: Zig -> LuaJIT Zero-Copy Bridge
--  Part of the MOABI Binary Analysis Suite
--  https://moabi.com/
--============================================================================

local ffi = require("ffi")

-- Define the C-ABI exports from your Zig shared library (libmoabi.so)
ffi.cdef[[
    typedef struct {
        double entropy;
        double byte_mean;
        double byte_stddev;
        double null_ratio;
        double printable_ratio;
        double ff_ratio;
        double top_byte_ratio;
    } MoabiByteStats;

    int    moabi_is_elf(const uint8_t* data, size_t len);
    double moabi_entropy(const uint8_t* data, size_t len);
    void   moabi_histogram(const uint8_t* data, size_t len, uint32_t out_hist[256]);
    int    moabi_extract_stats(const uint8_t* data, size_t len, MoabiByteStats* out_stats);
]]

local M = {}
local lib = nil

-- Attempt to load libmoabi.so dynamically from common build/bin paths
local paths = {
    "/mnt/d/moabi/bin/libmoabi.so",
    "/mnt/d/moabi/src/libmoabi.so",
    "libmoabi.so"
}

for _, p in ipairs(paths) do
    local ok, l = pcall(ffi.load, p)
    if ok then
        lib = l
        break
    end
end

M.has_zig_ffi = (lib ~= nil)

--- Read binary file into a zero-copy FFI buffer
function M.read_buffer(filepath)
    local f = io.open(filepath, "rb")
    if not f then return nil, "Cannot open: " .. filepath end
    local data = f:read("*a")
    f:close()
    if not data or #data == 0 then return nil, "Empty file" end
    
    local buf = ffi.new("uint8_t[?]", #data)
    ffi.copy(buf, data, #data)
    return buf, #data, data
end

--- Extract accelerated stats via Zig (or graceful fallback to Lua)
function M.extract_byte_stats(buf, len, raw_string)
    if M.has_zig_ffi and pcall(function() return lib.moabi_extract_stats end) then
        local stats = ffi.new("MoabiByteStats")
        if lib.moabi_extract_stats(buf, len, stats) == 0 then
            return {
                entropy         = stats.entropy,
                byte_mean       = stats.byte_mean,
                byte_stddev     = stats.byte_stddev,
                null_ratio      = stats.null_ratio,
                printable_ratio = stats.printable_ratio,
                ff_ratio        = stats.ff_ratio,
                top_byte_ratio  = stats.top_byte_ratio
            }
        end
    end

    -- Fast LuaJIT fallback if libmoabi.so is missing or specific symbol isn't exported yet
    local byte_sum, byte_sq_sum = 0, 0
    local null_cnt, ff_cnt, print_cnt = 0, 0, 0
    local hist = ffi.new("uint32_t[256]")
    
    for i = 0, len - 1 do
        local b = buf[i]
        hist[b] = hist[b] + 1
        byte_sum = byte_sum + b
        byte_sq_sum = byte_sq_sum + b * b
        if b == 0x00 then null_cnt = null_cnt + 1 end
        if b == 0xFF then ff_cnt = ff_cnt + 1 end
        if b >= 0x20 and b <= 0x7E then print_cnt = print_cnt + 1 end
    end

    local mean = byte_sum / len
    local stddev = math.sqrt(math.max(0, byte_sq_sum / len - mean * mean))
    
    local max_cnt = 0
    local e = 0.0
    local log2 = math.log(2)
    for i = 0, 255 do
        if hist[i] > max_cnt then max_cnt = hist[i] end
        if hist[i] > 0 then
            local p = hist[i] / len
            e = e - p * (math.log(p) / log2)
        end
    end

    return {
        entropy         = e,
        byte_mean       = mean,
        byte_stddev     = stddev,
        null_ratio      = null_cnt / len,
        printable_ratio = print_cnt / len,
        ff_ratio        = ff_cnt / len,
        top_byte_ratio  = max_cnt / len
    }
end

-- ============================================================================
--  High-level ML-compatible analysis API
--
--  These wrappers preserve the existing low-level API:
--    read_buffer()
--    extract_byte_stats()
--
--  They add:
--    extract_ml_features(filepath)
--    analyze_file(filepath)
--
--  The 15-feature schema matches moabi-ml.lua / moabi-dynamic2.lua.
-- ============================================================================

local MOABI_FFI2_LOG2 = math.log(2)
local MOABI_FFI2_WINDOW_SIZE = 1024

local function moabi_ffi2_entropy_from_hist(hist, total)
    if total <= 0 then
        return 0.0
    end

    local e = 0.0

    for i = 0, 255 do
        local count = tonumber(hist[i]) or 0

        if count > 0 then
            local p = count / total
            e = e - p * (math.log(p) / MOABI_FFI2_LOG2)
        end
    end

    return e
end

local function moabi_ffi2_window_entropy_features(raw, len)
    local n_windows = math.floor(len / MOABI_FFI2_WINDOW_SIZE)

    if n_windows < 2 then
        return 0.0, 0.0, 0.0
    end

    local entropies = {}

    for w = 0, n_windows - 1 do
        local hist = ffi.new("uint32_t[256]")
        local start_index = (w * MOABI_FFI2_WINDOW_SIZE) + 1

        for offset = 0, MOABI_FFI2_WINDOW_SIZE - 1 do
            local b = raw:byte(start_index + offset)
            hist[b] = hist[b] + 1
        end

        entropies[#entropies + 1] =
            moabi_ffi2_entropy_from_hist(hist, MOABI_FFI2_WINDOW_SIZE)
    end

    local sum = 0.0

    for _, e in ipairs(entropies) do
        sum = sum + e
    end

    local mean = sum / #entropies
    local variance = 0.0
    local high = 0
    local low = 0

    for _, e in ipairs(entropies) do
        local d = e - mean
        variance = variance + d * d

        if e > 7.0 then
            high = high + 1
        end

        if e < 2.0 then
            low = low + 1
        end
    end

    return variance / #entropies,
           high / #entropies,
           low / #entropies
end

local function moabi_ffi2_elf_fields(raw, len)
    if len >= 5
       and raw:byte(1) == 0x7f
       and raw:byte(2) == 0x45
       and raw:byte(3) == 0x4c
       and raw:byte(4) == 0x46
    then
        local elf_class = raw:byte(5) or 0
        local elf_type = 0

        if len >= 18 then
            local ei_data = raw:byte(6)
            local b1 = raw:byte(17) or 0
            local b2 = raw:byte(18) or 0

            if ei_data == 1 then
                -- Little-endian ELF
                elf_type = b1 + b2 * 256
            elseif ei_data == 2 then
                -- Big-endian ELF
                elf_type = b1 * 256 + b2
            end
        end

        return 1.0, elf_class, elf_type
    end

    return 0.0, 0.0, 0.0
end

local function moabi_ffi2_byte_stats_with_source(buf, len, raw)
    local stats = nil
    local source = "moabi-ffi2/LuaJIT fallback"

    -- Try native Zig first so the reported source is honest.
    if M.has_zig_ffi and lib ~= nil then
        local symbol_ok = pcall(function()
            return lib.moabi_extract_stats
        end)

        if symbol_ok then
            local native = ffi.new("MoabiByteStats")

            local call_ok, rc = pcall(function()
                return lib.moabi_extract_stats(buf, len, native)
            end)

            if call_ok and rc == 0 then
                stats = {
                    entropy         = native.entropy,
                    byte_mean       = native.byte_mean,
                    byte_stddev     = native.byte_stddev,
                    null_ratio      = native.null_ratio,
                    printable_ratio = native.printable_ratio,
                    ff_ratio        = native.ff_ratio,
                    top_byte_ratio  = native.top_byte_ratio,
                }

                source = "moabi-ffi2/libmoabi.so"
            end
        end
    end

    -- Existing graceful fallback.
    if not stats then
        stats = M.extract_byte_stats(buf, len, raw)
    end

    return stats, source
end

function M.extract_ml_features(filepath)
    local buf, len_or_err, raw = M.read_buffer(filepath)

    if not buf then
        return nil, len_or_err
    end

    local len = len_or_err

    local stats, source =
        moabi_ffi2_byte_stats_with_source(buf, len, raw)

    if not stats then
        return nil, "extract_byte_stats failed"
    end

    local is_elf, elf_class_num, elf_type_num =
        moabi_ffi2_elf_fields(raw, len)

    local entropy_variance, high_entropy_ratio, low_entropy_ratio =
        moabi_ffi2_window_entropy_features(raw, len)

    local features = {
        size_log           = math.log(len + 1),
        entropy            = stats.entropy or 0.0,
        byte_mean          = stats.byte_mean or 0.0,
        byte_stddev        = stats.byte_stddev or 0.0,
        null_ratio         = stats.null_ratio or 0.0,
        printable_ratio    = stats.printable_ratio or 0.0,
        is_elf             = is_elf,
        elf_class_num      = elf_class_num,
        elf_type_num       = elf_type_num,
        entropy_variance   = entropy_variance,
        high_entropy_ratio = high_entropy_ratio,
        low_entropy_ratio  = low_entropy_ratio,
        top_byte_ratio     = stats.top_byte_ratio or 0.0,
        ff_ratio           = stats.ff_ratio or 0.0,
        packer_detected    = 0.0,
        dependency_count = 0.0,
        has_libssl      = 0.0,
        has_libcrypto   = 0.0,
        has_libcurl     = 0.0,
        has_libz        = 0.0,
        has_liblzma     = 0.0,
        has_ncurses     = 0.0,
        has_readline    = 0.0,
        has_python      = 0.0,
        has_perl        = 0.0,
        has_ruby        = 0.0,
    }
    
    local dep_features = M.extract_dependency_features(filepath)

    if dep_features then
        features.dependency_count = dep_features.dependency_count or 0.0
        features.has_libssl      = dep_features.has_libssl      or 0.0
        features.has_libcrypto   = dep_features.has_libcrypto   or 0.0
        features.has_libcurl     = dep_features.has_libcurl     or 0.0
        features.has_libz        = dep_features.has_libz        or 0.0
        features.has_liblzma     = dep_features.has_liblzma     or 0.0
        features.has_ncurses     = dep_features.has_ncurses     or 0.0
        features.has_readline    = dep_features.has_readline    or 0.0
        features.has_python      = dep_features.has_python      or 0.0
        features.has_perl        = dep_features.has_perl        or 0.0
        features.has_ruby        = dep_features.has_ruby        or 0.0
    end

    if features.entropy > 7.2
       and features.null_ratio < 0.05
       and features.printable_ratio < 0.10
    then
        features.packer_detected = 1.0
    end

    return features, {
        path        = filepath,
        size        = len,
        source      = source,
        has_zig_ffi = M.has_zig_ffi,
    }
end

function M.analyze_file(filepath)
    local features, meta = M.extract_ml_features(filepath)

    if not features then
        return nil, meta
    end

    return {
        path              = filepath,
        size              = meta.size,
        source            = meta.source,
        has_zig_ffi       = meta.has_zig_ffi,

        entropy           = features.entropy,
        byte_mean         = features.byte_mean,
        byte_stddev       = features.byte_stddev,
        null_ratio        = features.null_ratio,
        printable_ratio   = features.printable_ratio,
        ff_ratio          = features.ff_ratio,
        top_byte_ratio    = features.top_byte_ratio,

        is_elf            = features.is_elf == 1.0,
        elf_class_num     = features.elf_class_num,
        elf_type_num      = features.elf_type_num,
        packer_detected   = features.packer_detected == 1.0,

        features          = features,

        dependency_count = features.dependency_count,
        has_libssl       = features.has_libssl,
        has_libcrypto    = features.has_libcrypto,
        has_libcurl      = features.has_libcurl,
        has_libz         = features.has_libz,
        has_liblzma      = features.has_liblzma,
        has_ncurses      = features.has_ncurses,
        has_readline     = features.has_readline,
        has_python       = features.has_python,
        has_perl         = features.has_perl,
        has_ruby         = features.has_ruby,
    }
end

-- ============================================================================
--  STRUCTURAL ELF FEATURE EXTRACTION (NO EXTERNAL LIBRARY REQUIRED)
--
--  Extracts:
--    section_count   — total section headers
--    import_count    — count of DT_NEEDED entries (dynamic dependencies)
--    export_count    — count of exported symbols (.dynsym / .symtab)
--    symbol_size     — total bytes of symbol tables
--    has_debug       — 1.0 if .debug_info section present, else 0.0
-- ============================================================================

-- ============================================================================
--  STRUCTURAL ELF FEATURE EXTRACTION v2 (corrected buffer scoping)
-- ============================================================================

local function elf_read_u16(data, offset, is_le)
    local lo = data:byte(offset) or 0
    local hi = data:byte(offset + 1) or 0
    if is_le then return lo + hi * 256
    else return lo * 256 + hi end
end

local function elf_read_u32(data, offset, is_le)
    local b1 = data:byte(offset) or 0
    local b2 = data:byte(offset + 1) or 0
    local b3 = data:byte(offset + 2) or 0
    local b4 = data:byte(offset + 3) or 0
    if is_le then
        return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
    else
        return b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
    end
end

local function elf_read_u64(data, offset, is_le)
    local lo = elf_read_u32(data, offset, is_le)
    local hi = elf_read_u32(data, offset + 4, is_le)
    if is_le then return lo + hi * 4294967296.0
    else return lo * 4294967296.0 + hi end
end

local function elf_read_string(data, offset)
    local s = {}
    for i = offset, math.min(offset + 255, #data) do
        local c = data:byte(i)
        if not c or c == 0 then break end
        s[#s + 1] = string.char(c)
    end
    return table.concat(s)
end

function M.extract_elf_features(filepath)
    local zero = {
        section_count = 0, import_count = 0, export_count = 0,
        symbol_size = 0, has_debug = 0,
        has_libssl = 0, has_libcrypto = 0, has_libcurl = 0,
        has_libz = 0, has_lzma = 0, has_ncurses = 0,
        has_readline = 0, has_libpython = 0, has_libperl = 0,
        has_libruby = 0,
    }

    local f = io.open(filepath, "rb")
    if not f then return zero end

    local hdr = f:read(64)
    if not hdr or #hdr < 64 then f:close(); return zero end

    if hdr:byte(1) ~= 0x7f or hdr:byte(2) ~= 0x45
       or hdr:byte(3) ~= 0x4c or hdr:byte(4) ~= 0x46 then
        f:close(); return zero
    end

    local is_64 = hdr:byte(5) == 2
    local is_le = hdr:byte(6) == 1

    local e_shoff, e_shentsize, e_shnum, e_shstrndx
    if is_64 then
        e_shoff     = elf_read_u64(hdr, 41, is_le)
        e_shentsize = elf_read_u16(hdr, 59, is_le)
        e_shnum     = elf_read_u16(hdr, 61, is_le)
        e_shstrndx  = elf_read_u16(hdr, 63, is_le)
    else
        e_shoff     = elf_read_u32(hdr, 33, is_le)
        e_shentsize = elf_read_u16(hdr, 47, is_le)
        e_shnum     = elf_read_u16(hdr, 49, is_le)
        e_shstrndx  = elf_read_u16(hdr, 51, is_le)
    end

    if e_shnum == 0 or e_shoff == 0 or e_shentsize == 0 then
        f:close(); return zero
    end

    -- Read section name string table
    local strtab_data = ""
    do
        local shstr_off = e_shoff + (e_shstrndx * e_shentsize)
        f:seek("set", shstr_off)
        local entry = f:read(e_shentsize)
        if entry and #entry >= e_shentsize then
            local st_off, st_size
            if is_64 then
                st_off  = elf_read_u64(entry, 25, is_le)
                st_size = elf_read_u64(entry, 33, is_le)
            else
                st_off  = elf_read_u32(entry, 17, is_le)
                st_size = elf_read_u32(entry, 21, is_le)
            end
            if st_off > 0 and st_size > 0 then
                f:seek("set", st_off)
                strtab_data = f:read(math.min(st_size, 131072)) or ""
            end
        end
    end

    local result = {
        section_count = e_shnum,
        import_count  = 0,
        export_count  = 0,
        symbol_size   = 0,
        has_debug     = 0,
        has_libssl    = 0,
        has_libcrypto = 0,
        has_libcurl   = 0,
        has_libz      = 0,
        has_lzma      = 0,
        has_ncurses   = 0,
        has_readline  = 0,
        has_libpython = 0,
        has_libperl   = 0,
        has_libruby   = 0,
    }

    local needed_names = {}

    -- Iterate all section headers
    for i = 0, e_shnum - 1 do
        f:seek("set", e_shoff + i * e_shentsize)
        local sh = f:read(e_shentsize)
        if not sh or #sh < e_shentsize then break end

        local name_idx = elf_read_u32(sh, 1, is_le)
        local sh_type  = elf_read_u32(sh, 5, is_le)
        local sh_off, sh_size
        if is_64 then
            sh_off  = elf_read_u64(sh, 25, is_le)
            sh_size = elf_read_u64(sh, 33, is_le)
        else
            sh_off  = elf_read_u32(sh, 17, is_le)
            sh_size = elf_read_u32(sh, 21, is_le)
        end

        local name = ""
        if name_idx > 0 and name_idx < #strtab_data then
            name = elf_read_string(strtab_data, name_idx + 1)
        end

        -- SHT_SYMTAB (2) or SHT_DYNSYM (11): count symbol entries
        if sh_type == 2 or sh_type == 11 then
            local entry_size = is_64 and 24 or 16
            if entry_size > 0 and sh_size > 0 then
                local count = math.floor(sh_size / entry_size)
                result.export_count = result.export_count + count
                result.symbol_size  = result.symbol_size + sh_size
            end
        end

        -- SHT_DYNAMIC (6): parse DT_NEEDED entries
        if sh_type == 6 and sh_off > 0 and sh_size > 0 then
            f:seek("set", sh_off)
            local dyn_data = f:read(math.min(sh_size, 262144))
            if dyn_data then
                local dyn_entry_size = is_64 and 16 or 8
                local n_entries = math.floor(#dyn_data / dyn_entry_size)
                for d = 0, n_entries - 1 do
                    local base = d * dyn_entry_size + 1
                    local dt_tag
                    if is_64 then
                        dt_tag = elf_read_u64(dyn_data, base, is_le)
                    else
                        dt_tag = elf_read_u32(dyn_data, base, is_le)
                    end
                    if dt_tag == 1 then
                        -- DT_NEEDED: value is index into .dynstr
                        local dt_val
                        if is_64 then
                            dt_val = elf_read_u64(dyn_data, base + 8, is_le)
                        else
                            dt_val = elf_read_u32(dyn_data, base + 4, is_le)
                        end
                        needed_names[#needed_names + 1] = dt_val
                        result.import_count = result.import_count + 1
                    end
                    if dt_tag == 0 then break end -- DT_NULL
                end
            end
        end

        -- Debug info
        if name == ".debug_info" and sh_size > 0 then
            result.has_debug = 1
        end
    end

    -- Resolve DT_NEEDED names from .dynstr
    if #needed_names > 0 then
        -- Find .dynstr section
        for i = 0, e_shnum - 1 do
            f:seek("set", e_shoff + i * e_shentsize)
            local sh = f:read(e_shentsize)
            if not sh or #sh < e_shentsize then break end
            local sh_type = elf_read_u32(sh, 5, is_le)
            if sh_type == 3 then -- SHT_STRTAB
                local name_idx = elf_read_u32(sh, 1, is_le)
                local sname = ""
                if name_idx > 0 and name_idx < #strtab_data then
                    sname = elf_read_string(strtab_data, name_idx + 1)
                end
                if sname == ".dynstr" then
                    local ds_off, ds_size
                    if is_64 then
                        ds_off  = elf_read_u64(sh, 25, is_le)
                        ds_size = elf_read_u64(sh, 33, is_le)
                    else
                        ds_off  = elf_read_u32(sh, 17, is_le)
                        ds_size = elf_read_u32(sh, 21, is_le)
                    end
                    if ds_off > 0 and ds_size > 0 then
                        f:seek("set", ds_off)
                        local dynstr = f:read(math.min(ds_size, 131072)) or ""
                        for _, idx in ipairs(needed_names) do
                            local lib_name = ""
                            if idx > 0 and idx < #dynstr then
                                lib_name = elf_read_string(dynstr, idx + 1)
                            end
                            if lib_name:find("ssl")      then result.has_libssl    = 1 end
                            if lib_name:find("crypto")   then result.has_libcrypto = 1 end
                            if lib_name:find("curl")     then result.has_libcurl   = 1 end
                            if lib_name:find("libz")     then result.has_libz      = 1 end
                            if lib_name:find("lzma")     then result.has_lzma      = 1 end
                            if lib_name:find("ncurses")  then result.has_ncurses   = 1 end
                            if lib_name:find("readline") then result.has_readline  = 1 end
                            if lib_name:find("python")   then result.has_libpython = 1 end
                            if lib_name:find("perl")     then result.has_libperl   = 1 end
                            if lib_name:find("ruby")     then result.has_libruby   = 1 end
                        end
                    end
                    break
                end
            end
        end
    end

    f:close()
    return result
end
               
M.extract_elf_features = M.extract_elf_features

-- ============================================================================
--  DEPENDENCY IDENTITY FEATURES
--
--  Fast string-based dependency identity.
--  This is deliberately simple and robust: it does not need full ELF dynamic
--  parsing and works even when section tables are stripped.
-- ============================================================================

function M.extract_dependency_features(filepath)
    local f = io.open(filepath, "rb")
    if not f then
        return nil, "Cannot open: " .. filepath
    end

    local data = f:read("*a")
    f:close()

    if not data or #data == 0 then
        return nil, "Empty file"
    end

    local function has(s)
        return data:find(s, 1, true) and 1.0 or 0.0
    end

    local deps = {
        has_libssl      = has("libssl"),
        has_libcrypto   = has("libcrypto"),
        has_libcurl     = has("libcurl"),
        has_libz        = has("libz.so"),
        has_liblzma     = has("liblzma"),
        has_ncurses     = (has("libncurses") == 1.0 or has("libtinfo") == 1.0) and 1.0 or 0.0,
        has_readline    = has("libreadline"),
        has_python      = has("libpython"),
        has_perl        = has("libperl"),
        has_ruby        = has("libruby"),
    }

    -- Count unique-looking shared object references.
    local seen = {}
    local count = 0

    for lib in data:gmatch("lib[%w%._%+%-]+%.so[%w%._%-]*") do
        if not seen[lib] then
            seen[lib] = true
            count = count + 1
        end
    end

    deps.dependency_count = count

    return deps
end

return M
