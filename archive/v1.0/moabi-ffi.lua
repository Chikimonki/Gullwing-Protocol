#!/usr/bin/env luajit
--[[
  MOABI LuaJIT FFI Bridge v0.2
  
  Zero-copy file analysis via mmap.
  Direct Zig function calls at native speed.
  Packer detection via windowed entropy.
  Cross-architecture awareness via jit.arch.
]]

local ffi = require("ffi")
local bit = require("bit")

-- ============================================================
-- FFI DECLARATIONS
-- ============================================================

ffi.cdef[[
    // Entropy
    double moabi_entropy(const uint8_t *data, size_t len);

    // Byte statistics
    double moabi_byte_mean(const uint8_t *data, size_t len);
    double moabi_byte_stddev(const uint8_t *data, size_t len);
    double moabi_null_ratio(const uint8_t *data, size_t len);
    double moabi_printable_ratio(const uint8_t *data, size_t len);

    // Windowed entropy
    size_t moabi_window_entropy(
        const uint8_t *data, size_t len,
        size_t window_size,
        double *results,
        size_t max_results);

    size_t moabi_count_high_entropy(
        const uint8_t *data, size_t len,
        size_t window_size,
        double threshold);

    // Histogram
    void moabi_histogram(
        const uint8_t *data, size_t len,
        uint64_t *output);

    // Pattern detection
    int64_t moabi_find_pattern(
        const uint8_t *data, size_t data_len,
        const uint8_t *pattern, size_t pattern_len);

    // Cave helpers
    bool moabi_is_zeroed(const uint8_t *data, size_t len);
    bool moabi_is_nop_sled(const uint8_t *data, size_t len);

    // ELF checks
    bool moabi_is_elf(const uint8_t *data, size_t len);
    int  moabi_elf_class(const uint8_t *data, size_t len);
    int  moabi_elf_type(const uint8_t *data, size_t len);

    // SHA-256
    void moabi_sha256(
        const uint8_t *data, size_t len,
        uint8_t *output);

    // Zero-copy mmap
    uint8_t* moabi_mmap_file(
        const char *path, size_t *len_out);
    void moabi_munmap(uint8_t *ptr, size_t len);
    int64_t moabi_file_size(const char *path);

    // Version
    uint32_t moabi_version();
]]

-- ============================================================
-- LOAD LIBRARY
-- ============================================================

local LIB_PATH = "/mnt/d/moabi/bin/libmoabi.so"
local lib = ffi.load(LIB_PATH)

-- ============================================================
-- ARCHITECTURE AWARENESS
-- ============================================================

local ARCH = jit.arch  -- x64, arm64, arm, mips, etc

-- Relocation type names per architecture
-- Used when analysing foreign-arch binaries
local RELOC_NAMES = {
    x64 = {
        [0]  = "R_X86_64_NONE",
        [1]  = "R_X86_64_64",
        [2]  = "R_X86_64_PC32",
        [4]  = "R_X86_64_PLT32",
        [6]  = "R_X86_64_GLOB_DAT",
        [7]  = "R_X86_64_JUMP_SLOT",
        [8]  = "R_X86_64_RELATIVE",
        [10] = "R_X86_64_32",
        [24] = "R_X86_64_PC64",
    },
    arm64 = {
        [0]    = "R_AARCH64_NONE",
        [257]  = "R_AARCH64_ABS64",
        [258]  = "R_AARCH64_ABS32",
        [1025] = "R_AARCH64_GLOB_DAT",
        [1026] = "R_AARCH64_JUMP_SLOT",
        [1027] = "R_AARCH64_RELATIVE",
    },
    arm = {
        [0]  = "R_ARM_NONE",
        [2]  = "R_ARM_ABS32",
        [22] = "R_ARM_JUMP_SLOT",
        [23] = "R_ARM_RELATIVE",
        [28] = "R_ARM_GLOB_DAT",
    },
    mips = {
        [0]  = "R_MIPS_NONE",
        [2]  = "R_MIPS_32",
        [3]  = "R_MIPS_REL32",
        [22] = "R_MIPS_JUMP_SLOT",
    },
}

local function reloc_name(type_id, arch)
    arch = arch or ARCH
    local map = RELOC_NAMES[arch]
    if map then
        return map[type_id] or
               string.format("R_UNKNOWN_%d", type_id)
    end
    return string.format("R_UNKNOWN_%d", type_id)
end

-- ============================================================
-- PACKER SIGNATURES
-- ============================================================

local PACKER_SIGS = {
    { name = "UPX",       pattern = "UPX!" },
    { name = "UPX0",      pattern = "UPX0" },
    { name = "MPRESS",    pattern = "MPRESS" },
    { name = "FSG",       pattern = "FSG!" },
    { name = "PECompact", pattern = "PEC2" },
    { name = "ASPack",    pattern = ".aspack" },
    { name = "Themida",   pattern = ".themida" },
    { name = "ELF_Pack",  pattern = ".elf.pack" },
}

-- ============================================================
-- CORE MODULE
-- ============================================================

local moabi = {}

-- ---- VERSION ----

function moabi.version()
    local v = lib.moabi_version()
    return string.format("%d.%d.%d",
        bit.band(bit.rshift(v, 16), 0xff),
        bit.band(bit.rshift(v, 8), 0xff),
        bit.band(v, 0xff))
end

function moabi.arch()
    return ARCH
end

-- ---- ZERO-COPY FILE ACCESS ----

-- Returns a mapped file object
-- caller must call :close() when done
function moabi.map_file(path)
    local len_out = ffi.new("size_t[1]")
    local ptr = lib.moabi_mmap_file(path, len_out)

    if ptr == nil then
        return nil, "cannot map file: " .. path
    end

    local len = tonumber(len_out[0])

    local mapped = {
        ptr  = ptr,
        len  = len,
        path = path,
    }

    function mapped:close()
        if self.ptr ~= nil then
            lib.moabi_munmap(self.ptr, self.len)
            self.ptr = nil
        end
    end

    -- Convenience: treat like a string for pattern search
    function mapped:find_pattern(pattern)
        local pos = lib.moabi_find_pattern(
            self.ptr, self.len,
            pattern, #pattern)
        if pos < 0 then return nil end
        return tonumber(pos)
    end

    return mapped, nil
end

-- Fallback: read into Lua string (for compatibility)
function moabi.read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local data = f:read("*all")
    f:close()
    return data
end

function moabi.file_size(path)
    local sz = lib.moabi_file_size(path)
    if sz < 0 then return nil end
    return tonumber(sz)
end

-- ---- ENTROPY ----

function moabi.entropy(data, len)
    if type(data) == "string" then
        return lib.moabi_entropy(data, #data)
    end
    -- cdata pointer
    return lib.moabi_entropy(data, len or 0)
end

-- ---- STATISTICS ----

function moabi.byte_mean(data, len)
    if type(data) == "string" then
        return lib.moabi_byte_mean(data, #data)
    end
    return lib.moabi_byte_mean(data, len or 0)
end

function moabi.byte_stddev(data, len)
    if type(data) == "string" then
        return lib.moabi_byte_stddev(data, #data)
    end
    return lib.moabi_byte_stddev(data, len or 0)
end

function moabi.null_ratio(data, len)
    if type(data) == "string" then
        return lib.moabi_null_ratio(data, #data)
    end
    return lib.moabi_null_ratio(data, len or 0)
end

function moabi.printable_ratio(data, len)
    if type(data) == "string" then
        return lib.moabi_printable_ratio(data, #data)
    end
    return lib.moabi_printable_ratio(data, len or 0)
end

-- ---- SHA-256 ----

function moabi.sha256(data, len)
    local hash = ffi.new("uint8_t[32]")
    if type(data) == "string" then
        lib.moabi_sha256(data, #data, hash)
    else
        lib.moabi_sha256(data, len or 0, hash)
    end
    local hex = {}
    for i = 0, 31 do
        table.insert(hex, string.format("%02x", hash[i]))
    end
    return table.concat(hex)
end

-- ---- ELF ----

function moabi.is_elf(data, len)
    if type(data) == "string" then
        return lib.moabi_is_elf(data, #data)
    end
    return lib.moabi_is_elf(data, len or 0)
end

function moabi.elf_class(data, len)
    local c
    if type(data) == "string" then
        c = lib.moabi_elf_class(data, #data)
    else
        c = lib.moabi_elf_class(data, len or 0)
    end
    if c == 1 then return "ELF32"
    elseif c == 2 then return "ELF64"
    else return "Unknown" end
end

function moabi.elf_type(data, len)
    local t
    if type(data) == "string" then
        t = lib.moabi_elf_type(data, #data)
    else
        t = lib.moabi_elf_type(data, len or 0)
    end
    if t == 1 then return "ET_REL"
    elseif t == 2 then return "ET_EXEC"
    elseif t == 3 then return "ET_DYN"
    elseif t == 4 then return "ET_CORE"
    else return "Unknown" end
end

-- ---- WINDOWED ENTROPY ----

function moabi.window_entropies(data, len, window_size)
    window_size = window_size or 256
    local max_results = 10000
    local results = ffi.new("double[10000]")

    local count
    if type(data) == "string" then
        count = lib.moabi_window_entropy(
            data, #data, window_size, results, max_results)
    else
        count = lib.moabi_window_entropy(
            data, len, window_size, results, max_results)
    end

    count = tonumber(count)
    local out = {}
    for i = 0, count - 1 do
        table.insert(out, tonumber(results[i]))
    end
    return out
end

function moabi.high_entropy_count(data, len, window_size, threshold)
    window_size = window_size or 256
    threshold = threshold or 7.0

    if type(data) == "string" then
        return tonumber(lib.moabi_count_high_entropy(
            data, #data, window_size, threshold))
    end
    return tonumber(lib.moabi_count_high_entropy(
        data, len, window_size, threshold))
end

-- ---- PACKER DETECTION ----

function moabi.detect_packer(data, len)
    local is_str = type(data) == "string"
    local data_len = is_str and #data or len

    -- Check for known packer signatures
    for _, sig in ipairs(PACKER_SIGS) do
        local pos
        if is_str then
            pos = lib.moabi_find_pattern(
                data, data_len,
                sig.pattern, #sig.pattern)
        else
            pos = lib.moabi_find_pattern(
                data, data_len,
                sig.pattern, #sig.pattern)
        end
        if tonumber(pos) >= 0 then
            return {
                detected = true,
                name = sig.name,
                offset = tonumber(pos),
                method = "signature",
            }
        end
    end

    -- Entropy-based detection
    local global_ent
    if is_str then
        global_ent = lib.moabi_entropy(data, data_len)
    else
        global_ent = lib.moabi_entropy(data, data_len)
    end

    -- Get window entropies
    local windows = moabi.window_entropies(data, data_len, 256)
    local total = #windows
    if total == 0 then
        return { detected = false, reason = "no data" }
    end

    -- Count high/low entropy windows
    local high = 0
    local low = 0
    local sum = 0

    for _, e in ipairs(windows) do
        sum = sum + e
        if e > 7.0 then high = high + 1
        elseif e < 2.0 then low = low + 1
        end
    end

    local mean_ent = sum / total
    local high_ratio = high / total
    local low_ratio = low / total

    -- Compute variance
    local variance = 0
    for _, e in ipairs(windows) do
        variance = variance + (e - mean_ent)^2
    end
    variance = variance / total
    local stddev = math.sqrt(variance)

    -- Classification logic
    -- Packed: uniformly high entropy, low variance
    -- Encrypted section: high entropy in cluster, low elsewhere
    -- Normal: varied entropy, moderate mean
    -- Obfuscated: high variance

    if high_ratio > 0.85 and stddev < 0.5 then
        return {
            detected = true,
            name = "UNKNOWN_PACKER",
            method = "entropy_uniform_high",
            global_entropy = global_ent,
            high_ratio = high_ratio,
            stddev = stddev,
            confidence = "HIGH",
        }
    elseif high_ratio > 0.4 and low_ratio > 0.2 then
        return {
            detected = true,
            name = "ENCRYPTED_PAYLOAD",
            method = "entropy_bimodal",
            global_entropy = global_ent,
            high_ratio = high_ratio,
            low_ratio = low_ratio,
            confidence = "MEDIUM",
        }
    elseif global_ent > 7.2 then
        return {
            detected = true,
            name = "HIGH_ENTROPY_CONTENT",
            method = "entropy_global",
            global_entropy = global_ent,
            confidence = "LOW",
        }
    else
        return {
            detected = false,
            global_entropy = global_ent,
            high_ratio = high_ratio,
            stddev = stddev,
        }
    end
end

-- ---- HISTOGRAM ----

function moabi.histogram(data, len)
    local hist = ffi.new("uint64_t[256]")
    if type(data) == "string" then
        lib.moabi_histogram(data, #data, hist)
    else
        lib.moabi_histogram(data, len, hist)
    end
    local result = {}
    for i = 0, 255 do
        result[i] = tonumber(hist[i])
    end
    return result
end

-- ---- RELOCATION NAMES ----

function moabi.reloc_name(type_id, arch)
    return reloc_name(type_id, arch)
end

-- ---- FULL ANALYSIS (ZERO-COPY) ----

function moabi.analyse(path)
    print("")
    print("============================================")
    print("  MOABI FFI Engine v" .. moabi.version())
    print("  Architecture: " .. ARCH)
    print("============================================")
    print("")
    print("File: " .. path)

    -- Zero-copy map
    local mapped, err = moabi.map_file(path)
    if not mapped then
        print("Error: " .. (err or "unknown"))
        return nil
    end

    local ptr = mapped.ptr
    local len = mapped.len

    print(string.format("Size: %d bytes (zero-copy mmap)", len))
    print("")

    -- Identity
    local hash = moabi.sha256(ptr, len)
    print("SHA-256:  " .. hash)

    if moabi.is_elf(ptr, len) then
        print("Format:   ELF")
        print("Class:    " .. moabi.elf_class(ptr, len))
        print("Type:     " .. moabi.elf_type(ptr, len))
    else
        print("Format:   Non-ELF")
    end

    -- Entropy
    print("")
    print("--- Entropy ---")
    local ent = moabi.entropy(ptr, len)
    print(string.format("  Global:     %.4f / 8.0", ent))
    print(string.format("  Byte Mean:  %.2f", moabi.byte_mean(ptr, len)))
    print(string.format("  Byte StdDev:%.2f", moabi.byte_stddev(ptr, len)))
    print(string.format("  Null Ratio: %.4f", moabi.null_ratio(ptr, len)))
    print(string.format("  Printable:  %.4f", moabi.printable_ratio(ptr, len)))

    local high_ent = moabi.high_entropy_count(ptr, len, 256, 7.0)
    print(string.format("  High-Entropy Windows (>7.0): %d", high_ent))

    -- Packer detection
    print("")
    print("--- Packer Detection ---")
    local pack = moabi.detect_packer(ptr, len)
    if pack.detected then
        print(string.format("  ⚠  PACKER DETECTED: %s", pack.name))
        print(string.format("     Method:     %s", pack.method))
        print(string.format("     Confidence: %s",
              pack.confidence or "N/A"))
        if pack.global_entropy then
            print(string.format("     Entropy:    %.4f",
                  pack.global_entropy))
        end
        if pack.offset then
            print(string.format("     Signature at: 0x%x", pack.offset))
        end
        if pack.high_ratio then
            print(string.format("     High-Ent Ratio: %.2f%%",
                  pack.high_ratio * 100))
        end
    else
        print(string.format("  CLEAN (entropy %.4f, high-ent %.1f%%)",
              pack.global_entropy or ent,
              (pack.high_ratio or 0) * 100))
    end

    -- Byte distribution
    print("")
    print("--- Byte Distribution ---")
    local hist = moabi.histogram(ptr, len)
    local top = {}
    for i = 0, 255 do
        table.insert(top, {byte = i, count = hist[i]})
    end
    table.sort(top, function(a, b) return a.count > b.count end)

    print("  Top 5 bytes:")
    for i = 1, math.min(5, #top) do
        local b = top[i]
        local ch = ""
        if b.byte >= 32 and b.byte <= 126 then
            ch = string.format(" '%s'", string.char(b.byte))
        end
        print(string.format("    0x%02x%s: %d (%.1f%%)",
            b.byte, ch, b.count,
            b.count / len * 100))
    end

    -- Architecture context
    print("")
    print("--- Architecture Context ---")
    print("  Host JIT arch: " .. ARCH)
    print("  Relocation type 7 on this arch: " ..
          reloc_name(7, ARCH))

    mapped:close()
    print("")
end

-- ---- BATCH SCAN ----

function moabi.batch(directory, threshold)
    threshold = threshold or 6.5
    print("")
    print("MOABI Batch Scanner")
    print("Directory: " .. directory)
    print(string.format("%-40s %6s %8s %s",
          "File", "Size", "Entropy", "Packer"))
    print(string.rep("-", 70))

    local handle = io.popen(
        "find " .. directory ..
        " -type f -executable 2>/dev/null")
    local files = handle:read("*all")
    handle:close()

    local flagged = {}

    for file in files:gmatch("[^\n]+") do
        local mapped, err = moabi.map_file(file)
        if mapped then
            local ent = moabi.entropy(mapped.ptr, mapped.len)
            local pack = moabi.detect_packer(mapped.ptr, mapped.len)
            local name = file:match("([^/]+)$") or file
            local flag = pack.detected and
                         ("⚠ " .. pack.name) or ""

            print(string.format("%-40s %6d %8.4f %s",
                name,
                mapped.len,
                ent,
                flag))

            if pack.detected then
                table.insert(flagged, {
                    file = file,
                    pack = pack,
                })
            end

            mapped:close()
        end
    end

    if #flagged > 0 then
        print("")
        print("Flagged binaries:")
        for _, f in ipairs(flagged) do
            print(string.format("  ⚠  %s [%s]",
                  f.file, f.pack.name))
        end
    end
end

-- In moabi-ffi.lua
function moabi.fingerprint_arch(data, len)
    local hist = moabi.histogram(data, len)
    
    -- REX prefix 0x48 frequency fingerprints x86_64
    local rex_ratio = hist[0x48] / len
    -- 0x0F escape byte
    local escape_ratio = hist[0x0f] / len
    -- ARM64 instructions are 4-byte aligned
    -- RISC-V compressed = 2-byte aligned
    
    if rex_ratio > 0.02 and escape_ratio > 0.01 then
        return "x86_64 (high confidence)"
    elseif hist[0xe8] / len > 0.001 then
        -- 0xE8 = CALL relative in x86
        return "x86 family"
    else
        return "non-x86 or insufficient data"
    end
end

-- ============================================================
-- CLI
-- ============================================================

if arg and #arg >= 1 then
    if arg[1] == "batch" and arg[2] then
        moabi.batch(arg[2])
    elseif arg[1] == "--version" then
        print("MOABI FFI Engine v" .. moabi.version())
        print("Architecture: " .. ARCH)
    elseif arg[1] == "--help" then
        print([[
MOABI FFI Analysis Engine v0.2

Usage:
  luajit moabi-ffi.lua <binary>        Analyse a binary
  luajit moabi-ffi.lua batch <dir>     Batch scan directory
  luajit moabi-ffi.lua --version       Show version

Features:
  Zero-copy mmap (no data copying)
  Packer detection (signature + entropy)
  Architecture-aware relocation names
  SHA-256, entropy, byte statistics
]])
    else
        moabi.analyse(arg[1])
    end
end

return moabi
