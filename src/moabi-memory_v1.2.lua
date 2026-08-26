#!/usr/bin/env luajit
--============================================================================
--  MOABI-MEMORY v1.1 — Post-Execution Memory Inspection
--  Launches target as a direct child, ptrace-attaches BEFORE exec,
--  snapshots /proc/<pid>/maps and /proc/<pid>/mem, then kills it.
--
--  Robust signals (from maps, no ptrace needed):
--    rwx_regions        writable+executable pages
--    anon_exec_regions  executable memory NOT backed by a file (runtime codegen/unpack)
--  Best-effort signals (need ptrace mem read):
--    exec entropy per region
--============================================================================

local ffi = require("ffi")
local LOG2 = math.log(2)
local M = {}

ffi.cdef[[
long ptrace(int request, int pid, void *addr, void *data);
int  waitpid(int pid, int *status, int options);
int  kill(int pid, int sig);
]]

local PTRACE_SEIZE        = 0x4206
local PTRACE_DETACH       = 17
local PTRACE_O_TRACEEXEC  = 0x00000010
local SIGTRAP             = 5
local PTRACE_EVENT_EXEC   = 4

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function file_exists(p) local f=io.open(p,"rb"); if f then f:close(); return true end return false end

local function entropy(data)
    local n = #data
    if n == 0 then return 0.0 end
    local hist = {}
    for i = 0, 255 do hist[i] = 0 end
    for i = 1, n do local b = data:byte(i); hist[b] = hist[b] + 1 end
    local e = 0.0
    for i = 0, 255 do
        if hist[i] > 0 then
            local p = hist[i] / n
            e = e - p * (math.log(p) / LOG2)
        end
    end
    return e
end

local function disk_entropy(path)
    local f = io.open(path, "rb"); if not f then return nil end
    local d = f:read("*a"); f:close()
    return entropy(d or "")
end

local function parse_maps(pid)
    local f = io.open("/proc/" .. pid .. "/maps", "r")
    if not f then return nil end
    local regions = {}
    for line in f:lines() do
        local a, b, perms, path = line:match(
            "^(%x+)%-(%x+)%s+(%S+)%s+%S+%s+%S+%s+%S+%s*(.*)$")
        if a and perms then
            regions[#regions + 1] = {
                start = tonumber(a, 16),
                stop  = tonumber(b, 16),
                perms = perms,
                path  = (path or ""):gsub("^%s+",""):gsub("%s+$",""),
                exec  = perms:find("x") ~= nil,
                write = perms:find("w") ~= nil,
            }
        end
    end
    f:close()
    return regions
end

local function read_mem(pid, region, maxbytes)
    local f = io.open("/proc/" .. pid .. "/mem", "rb")
    if not f then return nil end
    local size = math.min(region.stop - region.start, maxbytes or 65536)
    local ok = f:seek("set", region.start)
    if not ok then f:close(); return nil end
    local ok2, data = pcall(function() return f:read(size) end)
    f:close()
    if ok2 then return data end
    return nil
end

function M.inspect(target, opts)
    opts = opts or {}
    local result = {
        target = target, inspected = false, reason = nil,
        regions_total = 0, exec_regions = 0, rwx_regions = 0,
        anon_exec_regions = 0, max_exec_entropy = 0.0, mean_exec_entropy = 0.0,
        entropy_available = false, disk_entropy = nil, entropy_delta = nil,
        rwx_suspicious = false, anon_exec_suspicious = false,
    }

    if not file_exists(target) then
        result.reason = "target not found"; return result
    end

    -- FIFO gate: child echoes its PID, waits, then execs target (same PID).
    local fifo = os.tmpname() .. ".fifo"
    os.remove(fifo)
    os.execute("mkfifo " .. shq(fifo) .. " 2>/dev/null")

    local cmd = "echo $$; read _ < " .. shq(fifo) ..
                "; exec " .. shq(target) .. " </dev/null >/dev/null 2>&1"
    local h = io.popen(cmd)
    if not h then result.reason = "popen failed"; os.remove(fifo); return result end

    local pid = tonumber(h:read("*l") or "")
    if not pid then
        result.reason = "no pid from child"; h:close(); os.remove(fifo); return result
    end
    result.pid = pid

    -- Attach before exec, request exec-stop.
    local seize = ffi.C.ptrace(PTRACE_SEIZE, pid, nil,
                               ffi.cast("void*", PTRACE_O_TRACEEXEC))
    local traced = (seize == 0)

    -- Release the child into exec().
    local wf = io.open(fifo, "w")
    if wf then wf:write("\n"); wf:close() end

    if traced then
        -- Wait for the exec-stop event.
        local status = ffi.new("int[1]")
        local caught = false
        for _ = 1, 200 do
            local r = ffi.C.waitpid(pid, status, 0)
            if r <= 0 then break end
            local s = status[0]
            local stopped = (bit.band(s, 0xff) == 0x7f)
            local sig = bit.band(bit.rshift(s, 8), 0xff)
            local event = bit.band(bit.rshift(s, 16), 0xff)
            if stopped and sig == SIGTRAP and event == PTRACE_EVENT_EXEC then
                caught = true; break
            end
            -- exited?
            if bit.band(s, 0x7f) == 0 then break end
        end
        if not caught then traced = false end
    end

    -- Small settle delay so libraries are mapped.
    os.execute("sleep 0.02")

    if not file_exists("/proc/" .. pid .. "/maps") then
        result.reason = "target exited before snapshot"
        ffi.C.kill(pid, 9); if h then h:close() end; os.remove(fifo)
        return result
    end

    result.inspected = true
    local regions = parse_maps(pid) or {}
    result.regions_total = #regions

    local ent = {}
    for _, r in ipairs(regions) do
        if r.exec then
            result.exec_regions = result.exec_regions + 1
            if r.write then result.rwx_regions = result.rwx_regions + 1 end
            local anon = (r.path == "")
            if anon then result.anon_exec_regions = result.anon_exec_regions + 1 end
            if traced then
                local data = read_mem(pid, r, 65536)
                if data and #data > 0 then
                    local e = entropy(data)
                    ent[#ent + 1] = e
                    if e > result.max_exec_entropy then result.max_exec_entropy = e end
                end
            end
        end
    end

    if #ent > 0 then
        result.entropy_available = true
        local sum = 0; for _, e in ipairs(ent) do sum = sum + e end
        result.mean_exec_entropy = sum / #ent
        result.disk_entropy = disk_entropy(target)
        if result.disk_entropy then
            result.entropy_delta = result.max_exec_entropy - result.disk_entropy
        end
    end

    result.rwx_suspicious       = result.rwx_regions > 0
    result.anon_exec_suspicious = result.anon_exec_regions > 0

    -- Cleanup.
    if traced then ffi.C.ptrace(PTRACE_DETACH, pid, nil, nil) end
    ffi.C.kill(pid, 9)
    if h then h:close() end
    os.remove(fifo)

    return result
end

function M.print_report(r)
    local line = string.rep("=", 60)
    print(line)
    print("  MOABI MEMORY INSPECTION")
    print(line)
    print("  Target:             " .. tostring(r.target))
    if not r.inspected then
        print("  Status:             NOT INSPECTED (" .. tostring(r.reason) .. ")")
        print(line); return
    end
    print("  PID (snapshot):     " .. tostring(r.pid))
    print("  Total regions:      " .. r.regions_total)
    print("  Executable regions: " .. r.exec_regions)
    print("  RWX regions:        " .. r.rwx_regions .. (r.rwx_suspicious and "  [SUSPICIOUS]" or ""))
    print("  Anon exec regions:  " .. r.anon_exec_regions .. (r.anon_exec_suspicious and "  [SUSPICIOUS]" or ""))
    if r.entropy_available then
        print(string.format("  Max exec entropy:   %.4f / 8.0", r.max_exec_entropy))
        print(string.format("  Mean exec entropy:  %.4f / 8.0", r.mean_exec_entropy))
        if r.disk_entropy then
            print(string.format("  Disk entropy:       %.4f / 8.0", r.disk_entropy))
            print(string.format("  Entropy delta:      %+.4f", r.entropy_delta))
        end
    else
        print("  Exec entropy:       unavailable (ptrace read not permitted)")
    end
    print(line)
end

function M.evidence_fragment(r)
    return {
        profiled = r.inspected,
        reason = r.reason,
        regions_total = r.regions_total,
        exec_regions = r.exec_regions,
        rwx_regions = r.rwx_regions,
        anon_exec_regions = r.anon_exec_regions,
        entropy_available = r.entropy_available,
        max_exec_entropy = r.max_exec_entropy,
        mean_exec_entropy = r.mean_exec_entropy,
        disk_entropy = r.disk_entropy,
        entropy_delta = r.entropy_delta,
        rwx_suspicious = r.rwx_suspicious,
        anon_exec_suspicious = r.anon_exec_suspicious,
    }
end

if arg and arg[1] then
    M.print_report(M.inspect(arg[1]))
end

return M
