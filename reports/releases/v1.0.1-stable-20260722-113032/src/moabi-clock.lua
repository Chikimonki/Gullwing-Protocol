local ffi = require("ffi")
local M = {}

pcall(ffi.cdef, [[
    struct moabi_ts { long tv_sec; long tv_nsec; };
    int clock_gettime(int clock_id, struct moabi_ts *tp);
]])

local CLOCK_MONOTONIC = 1
local _ts = ffi.new("struct moabi_ts[1]")

function M.now_ms()
    if ffi.C.clock_gettime(CLOCK_MONOTONIC, _ts) == 0 then
        return tonumber(_ts[0].tv_sec) * 1000 + tonumber(_ts[0].tv_nsec) / 1e6
    end
    return os.clock() * 1000
end

return M
