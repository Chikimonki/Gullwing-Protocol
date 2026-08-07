local ffi = require("ffi")

ffi.cdef[[
typedef unsigned char  uint8_t;
typedef unsigned long  size_t;
typedef unsigned long long uint64_t;

double moabi_entropy(const uint8_t *data, size_t len);
void   moabi_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void   moabi_histogram(const uint8_t *data, size_t len, uint64_t out[256]);
int    moabi_find_pattern(const uint8_t *data, size_t len,
                          const uint8_t *pat, size_t pat_len);
int    moabi_is_elf(const uint8_t *data, size_t len);
]]

local M = {}

-- Resolve library path
local lib
for _, p in ipairs({
    "/mnt/d/moabi/bin/libmoabi.so",
    "./libmoabi.so",
    "libmoabi.so",
}) do
    local ok, res = pcall(ffi.load, p)
    if ok then lib = res; M.lib_path = p; break end
end
if not lib then error("libmoabi.so not found") end

-- Helpers
local function data_ptr(data)
    return ffi.cast("const uint8_t*", data)
end

function M.entropy(data)
    return lib.moabi_entropy(data_ptr(data), #data)
end

function M.sha256(data)
    local out = ffi.new("uint8_t[32]")
    lib.moabi_sha256(data_ptr(data), #data, out)
    local hex = {}
    for i = 0, 31 do hex[#hex+1] = string.format("%02x", out[i]) end
    return table.concat(hex)
end

function M.histogram(data)
    local out = ffi.new("uint64_t[256]")
    lib.moabi_histogram(data_ptr(data), #data, out)
    local h = {}
    for i = 0, 255 do h[i] = tonumber(out[i]) end
    return h
end

function M.is_elf(data)
    return lib.moabi_is_elf(data_ptr(data), #data) == 1
end

function M.find_pattern(data, pattern)
    local off = lib.moabi_find_pattern(data_ptr(data), #data,
                                       data_ptr(pattern), #pattern)
    return off >= 0 and tonumber(off) or nil
end

-- High-level: read file, return full FFI analysis
function M.analyze_file(path)
    local f, err = io.open(path, "rb")
    if not f then return nil, err end
    local data = f:read("*a")
    f:close()

    local hist = M.histogram(data)
    local byte_sum = 0
    for i = 0, 255 do byte_sum = byte_sum + hist[i] * i end

    return {
        path       = path,
        size       = #data,
        entropy    = M.entropy(data),
        sha256     = M.sha256(data),
        is_elf     = M.is_elf(data),
        byte_mean  = byte_sum / #data,
        histogram  = hist,
    }
end

return M
