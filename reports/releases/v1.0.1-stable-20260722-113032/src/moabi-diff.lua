#!/usr/bin/env luajit
--============================================================================
--  MOABI-DIFF v2.2 — Disk vs Memory Executable Segment Comparator
--============================================================================

local ffi = require("ffi")
local LOG2 = math.log(2)
local M = {}

ffi.cdef[[
long ptrace(int request, int pid, void *addr, void *data);
int  waitpid(int pid, int *status, int options);
int  kill(int pid, int sig);
]]

local PTRACE_SEIZE = 0x4206
local PTRACE_DETACH = 17
local PTRACE_O_TRACEEXEC = 0x00000010

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function entropy(d)
    local n = #d
    if n == 0 then return 0 end
    local h = {}
    for i = 0, 255 do h[i] = 0 end
    for i = 1, n do h[d:byte(i)] = h[d:byte(i)] + 1 end
    local e = 0
    for i = 0, 255 do
        if h[i] > 0 then
            local p = h[i] / n
            e = e - p * (math.log(p) / LOG2)
        end
    end
    return e
end

local function parse_phdr(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    if not data or #data < 64 or data:byte(1) ~= 0x7f then return nil end

    local is64 = data:byte(5) == 2
    local le = data:byte(6) == 1
    local function u16(o) local a, b = data:byte(o+1), data:byte(o+2); return le and a+b*256 or a*256+b end
    local function u32(o) local a, b, c, d = data:byte(o+1), data:byte(o+2), data:byte(o+3), data:byte(o+4); return le and a+b*256+c*65536+d*16777216 or a*16777216+b*65536+c*256+d end
    local function u64(o) return u32(o) + u32(o+4)*4294967296 end

    local phoff, phentsize, phnum = is64 and u64(32) or u32(28), is64 and u16(54) or u16(42), is64 and u16(56) or u16(44)
    local segs = {}

    for i = 0, phnum - 1 do
        local base = phoff + i * phentsize
        if base + phentsize > #data then break end
        if u32(base) == 1 then -- PT_LOAD
            local flags, offset, filesz = is64 and u32(base+4) or u32(base+24), is64 and u64(base+8) or u32(base+4), is64 and u64(base+32) or u32(base+16)
            if (flags % 2) == 1 and filesz > 0 then
                local s = math.floor(offset) + 1
                local e = s + math.floor(filesz) - 1
                if e <= #data then
                    segs[#segs+1] = { offset = math.floor(offset), filesz = math.floor(filesz), disk = data:sub(s, e) }
                end
            end
        end
    end
    return segs
end

local function parse_maps(pid)
    local f = io.open("/proc/" .. pid .. "/maps", "r")
    if not f then return {} end
    local out = {}
    for line in f:lines() do
        local sa, sb, perms, offset_s = line:match("^(%x+)%-(%x+)%s+(%S+)%s+(%x+)%s+%S+%s+%S+%s*.*$")
        if sa and perms then
            out[#out+1] = { start = tonumber(sa, 16), stop = tonumber(sb, 16), perms = perms, offset = tonumber(offset_s, 16), exec = perms:find("x") ~= nil }
        end
    end
    f:close()
    return out
end

local function launch_pid(target)
    local fifo = os.tmpname() .. ".fifo"
    os.remove(fifo)
    os.execute("mkfifo " .. shq(fifo) .. " 2>/dev/null")
    local cmd = "echo $$; read _ < " .. shq(fifo) .. "; exec " .. shq(target) .. " </dev/null >/dev/null 2>&1"
    local h = io.popen(cmd)
    if not h then os.remove(fifo); return nil end
    local pid = tonumber(h:read("*l") or "")
    if not pid then h:close(); os.remove(fifo); return nil end
    ffi.C.ptrace(PTRACE_SEIZE, pid, nil, ffi.cast("void*", PTRACE_O_TRACEEXEC))
    local wf = io.open(fifo, "w")
    if wf then wf:write("\n"); wf:close() end
    local st = ffi.new("int[1]")
    ffi.C.waitpid(pid, st, 0)
    os.execute("sleep 0.02")
    os.remove(fifo)
    return pid, h
end

function M.compare(target)
    local segs = parse_phdr(target)
    if not segs or #segs == 0 then
        return { available = false, error = "not ELF or no executable segments" }
    end

    local pid, h = launch_pid(target)
    if not pid then
        return { available = false, error = "launch failed" }
    end

    local maps = parse_maps(pid)
    local comparisons = {}
    local total_bytes, total_matching, max_drop = 0, 0, 0.0

    for _, seg in ipairs(segs) do
        local ddata = seg.disk
        local map = nil
        for _, m in ipairs(maps) do
            if m.exec and m.offset == seg.offset then map = m; break end
        end

        local seg_res = { size = #ddata, disk_entropy = entropy(ddata) }
        if map then
            local fm = io.open("/proc/" .. pid .. "/mem", "rb")
            local mem = nil
            if fm then
                fm:seek("set", map.start)
                local ok, dat = pcall(function() return fm:read(#ddata) end)
                fm:close()
                if ok then mem = dat end
            end
            if mem and #mem == #ddata then
                seg_res.mem_entropy = entropy(mem)
                seg_res.entropy_delta = seg_res.mem_entropy - seg_res.disk_entropy
                local match = 0
                for i = 1, #ddata do if ddata:byte(i) == mem:byte(i) then match = match + 1 end end
                seg_res.match_ratio = match / #ddata
                total_bytes = total_bytes + #ddata
                total_matching = total_matching + match
                local ad = math.abs(seg_res.entropy_delta)
                if ad > max_drop then max_drop = ad end
            else
                seg_res.match_ratio = 0.0
            end
        else
            seg_res.match_ratio = 0.0
        end
        comparisons[#comparisons + 1] = seg_res
    end

    ffi.C.ptrace(PTRACE_DETACH, pid, nil, nil)
    ffi.C.kill(pid, 9)
    if h then h:close() end

    local match_ratio = total_bytes > 0 and (total_matching / total_bytes) or 0.0
    local unpack_detected = (max_drop > 1.0 and match_ratio < 0.8)

    return {
        available = true,
        exec_segments = #comparisons,
        total_bytes = total_bytes,
        match_ratio = match_ratio,
        max_entropy_delta = max_drop,
        unpack_detected = unpack_detected,
        segments = comparisons,
    }
end

function M.evidence_fragment(res)
    if not res.available then
        return { profiled = false, error = res.error }
    end
    return {
        profiled = true,
        exec_segments = res.exec_segments,
        total_bytes = res.total_bytes,
        match_ratio = res.match_ratio,
        max_entropy_delta = res.max_entropy_delta,
        unpack_detected = res.unpack_detected,
    }
end

local invoked = arg and arg[0] and arg[0]:match("moabi%-diff%.lua$")
if invoked and arg[1] then
    local r = M.compare(arg[1])
    print("Diff available:", r.available, "Match ratio:", r.match_ratio, "Unpack:", r.unpack_detected)
end

return M
