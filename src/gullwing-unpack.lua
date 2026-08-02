#!/usr/bin/env luajit
--============================================================================
--  GULLWING-UNPACK v1.0 — Polymorphic Decryption Automation
--============================================================================

local SRC = "/mnt/d/moabi/src"
local REFLECT = SRC .. "/moabi-reflect.lua"
local TIMEOUT = 5

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

local function usage()
    print("GULLWING-UNPACK v1.0 — Polymorphic Decryption Automation")
    print("Usage: gullwing unpack <binary> [--arch arm64|riscv64]")
end

local function unpack_and_reflect(target, arch)
    local name = target:match("([^/]+)$") or "unknown"
    local trace_path = "/tmp/" .. name .. ".strace"
    
    print(string.format("GULLWING-UNPACK: %s", target))
    print(string.format("  Architecture: %s | Timeout: %ds", arch or "x86_64", TIMEOUT))
    print()
    
    -- Run under QEMU with strace
    local qemu_bin = arch and ("qemu-" .. arch) or "qemu-x86_64"
    local qemu_cmd = string.format(
        "timeout %d %s -strace %s 2>%s 1>/dev/null",
        TIMEOUT, shq(qemu_bin), shq(target), shq(trace_path))
    
    print("  [1/2] Running under QEMU...")
    os.execute(qemu_cmd)
    
    -- Count memory writes from trace
    print("  [2/2] Analyzing trace...")
    local h = io.open(trace_path, "r")
    local writes = 0
    if h then
        for line in h:lines() do
            if line:match("write%(") then writes = writes + 1 end
        end
        h:close()
    end
    
    -- Run Gullwing
    os.execute("luajit " .. shq(REFLECT) .. " " .. shq(target) .. " --static-only --json 2>/dev/null")
    
    local line = string.rep("=", 64)
    print(line)
    print("  UNPACK REPORT: " .. name)
    print(line)
    print(string.format("  Memory writes detected: %d", writes))
    if writes > 50 then
        print("  VERDICT: Potential unpacking/decryption detected.")
        print("  High write count suggests self-modifying code.")
    else
        print("  VERDICT: No significant unpacking detected.")
    end
    print(line)
    
    os.remove(trace_path)
    return writes
end

local function main()
    if not arg[1] or arg[1] == "-h" then usage(); return 0 end
    local arch = nil
    for i = 2, #arg do
        if arg[i] == "--arch" and arg[i+1] then arch = arg[i+1] end
    end
    unpack_and_reflect(arg[1], arch)
    return 0
end

main()
