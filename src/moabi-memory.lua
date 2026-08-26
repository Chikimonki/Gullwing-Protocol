#!/usr/bin/env luajit
-- MOABI-MEMORY v1.2
-- Standard runtime memory telemetry.
-- Temporal differential analysis remains standalone.

local ffi = require("ffi")
local bit = require("bit")
local clock = require("moabi-clock")

ffi.cdef[[
long ptrace(int request, int pid, void *addr, void *data);
int waitpid(int pid, int *status, int options);
int kill(int pid, int sig);
]]

local M = {}

local PTRACE_SEIZE = 0x4206
local PTRACE_DETACH = 17
local PTRACE_O_TRACEEXEC = 0x00000010
local PTRACE_EVENT_EXEC = 4
local SIGKILL = 9

local function now_ms()
    return clock.now_ms()
end

local function quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function exists(path)
    local f = io.open(path, "rb")
    if f then
        f:close()
        return true
    end
    return false
end

local function entropy(data)
    if not data or #data == 0 then
        return 0.0
    end

    local histogram = {}
    for i = 0, 255 do
        histogram[i] = 0
    end

    for i = 1, #data do
        local byte = data:byte(i)
        histogram[byte] = histogram[byte] + 1
    end

    local value = 0.0

    for i = 0, 255 do
        if histogram[i] > 0 then
            local p = histogram[i] / #data
            value = value - p * (math.log(p) / math.log(2))
        end
    end

    return value
end

local function disk_entropy(path)
    local f = io.open(path, "rb")
    if not f then
        return nil
    end

    local data = f:read("*a")
    f:close()

    return entropy(data)
end

local function parse_maps(pid)
    local f = io.open("/proc/" .. tostring(pid) .. "/maps", "r")
    if not f then
        return nil
    end

    local maps = {}

    for line in f:lines() do
        local first, last, permissions, pathname = line:match(
            "^(%x+)%-(%x+)%s+(%S+)%s+%S+%s+%S+%s+%S+%s*(.*)$"
        )

        if first and last and permissions then
            maps[#maps + 1] = {
                start = tonumber(first, 16),
                stop = tonumber(last, 16),
                permissions = permissions,
                path = (pathname or "")
                    :gsub("^%s+", "")
                    :gsub("%s+$", ""),
                executable = permissions:find("x", 1, true) ~= nil,
                writable = permissions:find("w", 1, true) ~= nil,
            }
        end
    end

    f:close()
    return maps
end

local function real_anonymous_executable(path)
    path = path or ""

    -- Normal Linux kernel/process mappings are not payloads.
    if path == "[vdso]"
       or path == "[vvar]"
       or path == "[vsyscall]"
       or path == "[stack]"
       or path == "[heap]"
    then
        return false
    end

    if path == "" then
        return true
    end

    if path:match("^/memfd:")
       or path:match("^memfd:")
       or path:match("^%[anon")
    then
        return true
    end

    return false
end

local function read_memory(pid, mapping, maximum)
    local f = io.open("/proc/" .. tostring(pid) .. "/mem", "rb")
    if not f then
        return nil
    end

    local size = math.min(
        mapping.stop - mapping.start,
        maximum or 65536
    )

    if not f:seek("set", mapping.start) then
        f:close()
        return nil
    end

    local ok, data = pcall(function()
        return f:read(size)
    end)

    f:close()

    if ok then
        return data
    end

    return nil
end

local function cleanup(pid, handle, fifo, attached)
    if attached then
        pcall(function()
            ffi.C.ptrace(PTRACE_DETACH, pid, nil, nil)
        end)
    end

    pcall(function()
        ffi.C.kill(pid, SIGKILL)
    end)

    if handle then
        pcall(function()
            handle:close()
        end)
    end

    if fifo then
        os.remove(fifo)
    end
end

local function launch(target)
    local fifo = os.tmpname() .. ".moabi-memory-fifo"
    os.remove(fifo)

    os.execute("mkfifo " .. quote(fifo) .. " 2>/dev/null")

    local command =
        "echo $$; read _ < "
        .. quote(fifo)
        .. "; exec "
        .. quote(target)
        .. " </dev/null >/dev/null 2>&1"

    local handle = io.popen(command)
    if not handle then
        os.remove(fifo)
        return nil, "failed to launch target"
    end

    local pid = tonumber(handle:read("*l") or "")
    if not pid then
        handle:close()
        os.remove(fifo)
        return nil, "failed to receive target PID"
    end

    local result = ffi.C.ptrace(
        PTRACE_SEIZE,
        pid,
        nil,
        ffi.cast("void *", PTRACE_O_TRACEEXEC)
    )

    if result ~= 0 then
        cleanup(pid, handle, fifo, false)
        return nil, "PTRACE_SEIZE failed"
    end

    local gate = io.open(fifo, "w")
    if gate then
        gate:write("\n")
        gate:close()
    end

    local status = ffi.new("int[1]")
    local waited = ffi.C.waitpid(pid, status, 0)

    if waited ~= pid then
        cleanup(pid, handle, fifo, true)
        return nil, "waitpid failed"
    end

    local status_value = tonumber(status[0])
    local stopped = bit.band(status_value, 0xff) == 0x7f
    local event = bit.band(bit.rshift(status_value, 16), 0xffff)

    if not stopped or event ~= PTRACE_EVENT_EXEC then
        cleanup(pid, handle, fifo, true)
        return nil, "target exited before exec snapshot"
    end

    os.remove(fifo)

    return {
        pid = pid,
        handle = handle,
        attached = true,
    }
end

function M.inspect(target)
    local result = {
        target = target,
        inspected = false,
        reason = nil,
        regions_total = 0,
        exec_regions = 0,
        rwx_regions = 0,
        anon_exec_regions = 0,
        max_exec_entropy = 0.0,
        mean_exec_entropy = 0.0,
        entropy_available = false,
        disk_entropy = nil,
        entropy_delta = nil,
        rwx_suspicious = false,
        anon_exec_suspicious = false,
    }

    if not exists(target) then
        result.reason = "target not found"
        return result
    end

    local context, error_message = launch(target)

    if not context then
        result.reason = error_message
        return result
    end

    local pid = context.pid
    result.pid = pid

    os.execute("sleep 0.02")

    local maps = parse_maps(pid)

    if not maps then
        result.reason = "cannot read process maps"
        cleanup(pid, context.handle, nil, context.attached)
        return result
    end

    result.inspected = true
    result.regions_total = #maps

    local values = {}

    for _, mapping in ipairs(maps) do
        if mapping.executable then
            result.exec_regions = result.exec_regions + 1

            if mapping.writable then
                result.rwx_regions = result.rwx_regions + 1
            end

            if real_anonymous_executable(mapping.path) then
                result.anon_exec_regions =
                    result.anon_exec_regions + 1
            end

            local data = read_memory(pid, mapping, 65536)

            if data and #data > 0 then
                local value = entropy(data)
                values[#values + 1] = value

                if value > result.max_exec_entropy then
                    result.max_exec_entropy = value
                end
            end
        end
    end

    if #values > 0 then
        local total = 0.0

        for _, value in ipairs(values) do
            total = total + value
        end

        result.entropy_available = true
        result.mean_exec_entropy = total / #values
        result.disk_entropy = disk_entropy(target)

        if result.disk_entropy then
            result.entropy_delta =
                result.max_exec_entropy - result.disk_entropy
        end
    end

    result.rwx_suspicious = result.rwx_regions > 0
    result.anon_exec_suspicious = result.anon_exec_regions > 0

    cleanup(pid, context.handle, nil, context.attached)

    return result
end

function M.evidence_fragment(result)
    return {
        profiled = result.inspected,
        reason = result.reason,
        regions_total = result.regions_total,
        exec_regions = result.exec_regions,
        rwx_regions = result.rwx_regions,
        anon_exec_regions = result.anon_exec_regions,
        entropy_available = result.entropy_available,
        max_exec_entropy = result.max_exec_entropy,
        mean_exec_entropy = result.mean_exec_entropy,
        disk_entropy = result.disk_entropy,
        entropy_delta = result.entropy_delta,
        rwx_suspicious = result.rwx_suspicious,
        anon_exec_suspicious = result.anon_exec_suspicious,
    }
end

local invoked_as_script =
    arg
    and arg[0]
    and arg[0]:match("moabi%-memory%.lua$")

if invoked_as_script and arg[1] then
    M.print_report(M.inspect(arg[1]))
end

return M
