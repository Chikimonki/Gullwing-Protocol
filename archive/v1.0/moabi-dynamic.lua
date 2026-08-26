#!/usr/bin/env luajit
--[[
  MOABI Dynamic Analysis — Runtime Behaviour Monitor v0.2
  
  Uses strace to capture and analyse system calls made by
  a binary at runtime. Compares what a binary DECLARES it
  can do (static analysis) vs what it ACTUALLY does (dynamic).
  
  Part of the MOABI Binary Analysis Suite.
]]

local ffi = require("ffi")
local math = require("math")

ffi.cdef[[
    typedef long time_t;
    time_t time(time_t *tloc);
    int mkdir(const char *pathname, int mode);
]]

local C = ffi.C

-- ============================================================
-- CONFIGURATION
-- ============================================================

local MOABI_TMP = "/mnt/d/moabi/tmp"
local MOABI_BIN = "/mnt/d/moabi/bin"

-- Sensitive files that should be flagged
local SENSITIVE_FILES = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/gshadow",
    "/proc/self",
    "/dev/mem",
    "/dev/kmem",
    "/proc/kcore",
    "/etc/ssh/ssh_host",
    "/root/",
}

-- Sensitive syscalls that indicate elevated behaviour
local SENSITIVE_SYSCALLS = {
    ptrace = { risk = 3, desc = "process tracing / anti-debug" },
    mprotect = { risk = 2, desc = "memory protection change" },
    prctl = { risk = 1, desc = "process control" },
    mount = { risk = 3, desc = "filesystem mount" },
    umount = { risk = 3, desc = "filesystem unmount" },
    chroot = { risk = 3, desc = "change root directory" },
    setuid = { risk = 3, desc = "set user ID" },
    setgid = { risk = 3, desc = "set group ID" },
    setreuid = { risk = 3, desc = "set real/effective UID" },
    unlink = { risk = 1, desc = "delete file" },
    rename = { risk = 1, desc = "rename file" },
    chmod = { risk = 2, desc = "change file permissions" },
    chown = { risk = 2, desc = "change file ownership" },
}

-- ============================================================
-- UTILITY FUNCTIONS
-- ============================================================

local function file_exists(path)
    local f = io.open(path, "r")
    if f then f:close() return true end
    return false
end

local function ensure_tmp_dir()
    C.mkdir(MOABI_TMP, tonumber("755", 8))
end

local function generate_trace_path()
    local t = ffi.new("time_t[1]")
    C.time(t)
    local ts = tonumber(t[0])
    local rand = math.random(10000, 99999)
    return string.format("%s/trace_%d_%d.log", MOABI_TMP, ts, rand)
end

local function basename(path)
    return path:match("([^/]+)$") or path
end

-- ============================================================
-- STRACE RUNNER
-- ============================================================

local function run_traced(binary, extra_args, timeout)
    timeout = timeout or 5
    extra_args = extra_args or ""

    ensure_tmp_dir()
    local trace_file = generate_trace_path()

    print("")
    print("╔═══════════════════════════════════════════════════╗")
    print("║  MOABI DYNAMIC ANALYSER v0.2                      ║")
    print("║  Runtime Behaviour Monitor                        ║")
    print("╚═══════════════════════════════════════════════════╝")
    print("")
    print("Target:  " .. binary)
    print("Args:    " .. (extra_args ~= "" and extra_args or "(none)"))
    print("Timeout: " .. timeout .. "s")
    print("Trace:   " .. trace_file)
    print("")

    -- Build strace command
    -- -f: follow forks
    -- -e trace=file,network,process,memory: capture relevant categories
    -- -o: output to file (keeps binary stdout/stderr separate)
    -- -qq: suppress strace messages
    local cmd = string.format(
        "timeout %d strace -f -qq " ..
        "-e trace=file,network,process,memory " ..
        "-o %s " ..
        "%s %s " ..
        ">/dev/null 2>&1",
        timeout, trace_file, binary, extra_args
    )

    os.execute(cmd)

    -- Read trace
    local f = io.open(trace_file, "r")
    if not f then
        print("Error: Could not capture trace")
        print("Check that strace is installed: sudo apt install strace")
        return
    end

    local trace = f:read("*all")
    f:close()
    os.remove(trace_file)

    if #trace == 0 then
        print("Error: Empty trace (binary may have failed to start)")
        return
    end

    -- ============================================================
    -- PARSE TRACE
    -- ============================================================

    local syscalls = {}
    local files_accessed = {}
    local network_ops = {}
    local network_inet = {}
    local network_unix = {}
    local processes_spawned = {}
    local sensitive_hits = {}
    local memory_ops = {}
    local execve_count = 0

    for line in trace:gmatch("[^\n]+") do
        -- Extract syscall name
        -- Format: PID  syscall(args) = result
        local syscall = line:match("^%d+%s+(%w+)%(")
        if not syscall then
            -- Sometimes no PID prefix
            syscall = line:match("^(%w+)%(")
        end

        if syscall then
            syscalls[syscall] = (syscalls[syscall] or 0) + 1

            -- File access tracking
            if syscall == "openat" or syscall == "open" or
               syscall == "stat" or syscall == "lstat" or
               syscall == "access" or syscall == "newfstatat" or
               syscall == "statx" or syscall == "readlink" then
                local path = line:match('"([^"]+)"')
                if path then
                    files_accessed[path] = true

                    -- Check against sensitive files
                    for _, sensitive in ipairs(SENSITIVE_FILES) do
                        if path:find(sensitive, 1, true) then
                            sensitive_hits[path] = sensitive
                        end
                    end
                end
            end

            -- Network tracking with protocol distinction
            if syscall == "socket" or syscall == "connect" or
               syscall == "bind" or syscall == "listen" or
               syscall == "accept" or syscall == "accept4" or
               syscall == "sendto" or syscall == "recvfrom" or
               syscall == "sendmsg" or syscall == "recvmsg" or
               syscall == "getsockname" or syscall == "getpeername" then

                table.insert(network_ops, line)

                if line:find("AF_INET") then
                    table.insert(network_inet, line)
                elseif line:find("AF_UNIX") then
                    table.insert(network_unix, line)
                end
            end

            -- Process creation tracking
            -- Skip the FIRST execve — that is strace launching our target
            if syscall == "execve" then
                execve_count = execve_count + 1
                if execve_count > 1 then
                    table.insert(processes_spawned, line)
                end
            elseif syscall == "clone" or syscall == "clone3" or
                   syscall == "fork" or syscall == "vfork" then
                table.insert(processes_spawned, line)
            end

            -- Memory protection changes
            if syscall == "mprotect" or syscall == "mmap" or
               syscall == "mremap" or syscall == "brk" then
                table.insert(memory_ops, line)
            end

            -- Track sensitive syscalls
            if SENSITIVE_SYSCALLS[syscall] then
                if not sensitive_hits[syscall] then
                    sensitive_hits["syscall:" .. syscall] =
                        SENSITIVE_SYSCALLS[syscall].desc
                end
            end
        end
    end

    -- ============================================================
    -- REPORT
    -- ============================================================

    -- Syscall Summary
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  SYSCALL SUMMARY")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    local sorted_syscalls = {}
    local total_syscalls = 0
    for name, count in pairs(syscalls) do
        table.insert(sorted_syscalls, { name = name, count = count })
        total_syscalls = total_syscalls + count
    end
    table.sort(sorted_syscalls, function(a, b)
        return a.count > b.count
    end)

    for _, entry in ipairs(sorted_syscalls) do
        local flag = ""
        if SENSITIVE_SYSCALLS[entry.name] then
            flag = "  ⚠ " .. SENSITIVE_SYSCALLS[entry.name].desc
        end
        print(string.format("  %-20s  %4d%s",
              entry.name, entry.count, flag))
    end
    print(string.format("\n  Total syscalls: %d", total_syscalls))

    -- Files Accessed
    print("")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  FILES ACCESSED")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    -- Categorise files
    local libs = {}
    local locale_files = {}
    local config_files = {}
    local proc_files = {}
    local other_files = {}

    for path in pairs(files_accessed) do
        if path:match("%.so") then
            table.insert(libs, path)
        elseif path:match("/locale/") then
            table.insert(locale_files, path)
        elseif path:match("^/etc/") then
            table.insert(config_files, path)
        elseif path:match("^/proc/") then
            table.insert(proc_files, path)
        else
            table.insert(other_files, path)
        end
    end

    table.sort(libs)
    table.sort(config_files)
    table.sort(proc_files)
    table.sort(other_files)

    if #libs > 0 then
        print(string.format("\n  Libraries loaded (%d):", #libs))
        for _, path in ipairs(libs) do
            print("    " .. path)
        end
    end

    if #config_files > 0 then
        print(string.format("\n  Config files read (%d):", #config_files))
        for _, path in ipairs(config_files) do
            local flag = ""
            if sensitive_hits[path] then
                flag = "  ⚠ SENSITIVE"
            end
            print("    " .. path .. flag)
        end
    end

    if #proc_files > 0 then
        print(string.format("\n  /proc access (%d):", #proc_files))
        for _, path in ipairs(proc_files) do
            local flag = ""
            if sensitive_hits[path] then
                flag = "  ⚠ SENSITIVE"
            end
            print("    " .. path .. flag)
        end
    end

    if #other_files > 0 then
        print(string.format("\n  Other files (%d):", #other_files))
        for _, path in ipairs(other_files) do
            print("    " .. path)
        end
    end

    if #locale_files > 0 then
        print(string.format("\n  Locale files: %d (collapsed)", #locale_files))
    end

    local total_files = #libs + #config_files + #proc_files +
                        #other_files + #locale_files
    print(string.format("\n  Total files touched: %d", total_files))

    -- Network Activity
    if #network_ops > 0 then
        print("")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        if #network_inet > 0 then
            print("  ⚠ INTERNET NETWORK ACTIVITY (AF_INET)")
        else
            print("  ℹ LOCAL SOCKET ACTIVITY (AF_UNIX only)")
        end
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        if #network_inet > 0 then
            print("\n  Internet connections (AF_INET/AF_INET6):")
            for _, op in ipairs(network_inet) do
                -- Extract the useful part
                local short = op:match("^%d+%s+(.-)$") or op
                print("    " .. short:sub(1, 90))
            end
        end

        if #network_unix > 0 then
            print(string.format(
                "\n  Unix domain sockets: %d (local IPC, lower risk)",
                #network_unix))
            for _, op in ipairs(network_unix) do
                local path = op:match('sun_path="([^"]+)"')
                if path then
                    print("    → " .. path)
                end
            end
        end
    end

    -- Child Processes
    if #processes_spawned > 0 then
        print("")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  ⚠ CHILD PROCESSES / THREADS")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        for _, op in ipairs(processes_spawned) do
            local short = op:match("^%d+%s+(.-)$") or op
            print("  " .. short:sub(1, 90))
        end
    end

    -- Memory Operations Summary
    if syscalls["mprotect"] then
        print("")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  MEMORY PROTECTION CHANGES")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        local rwx_count = 0
        local rx_count = 0
        local rw_count = 0
        local r_count = 0
        local none_count = 0

        for _, op in ipairs(memory_ops) do
            if op:find("mprotect") then
                if op:find("PROT_READ|PROT_WRITE|PROT_EXEC") or
                   op:find("PROT_READ, PROT_WRITE, PROT_EXEC") then
                    rwx_count = rwx_count + 1
                elseif op:find("PROT_READ|PROT_EXEC") or
                       op:find("PROT_READ, PROT_EXEC") then
                    rx_count = rx_count + 1
                elseif op:find("PROT_READ|PROT_WRITE") or
                       op:find("PROT_READ, PROT_WRITE") then
                    rw_count = rw_count + 1
                elseif op:find("PROT_READ") then
                    r_count = r_count + 1
                elseif op:find("PROT_NONE") then
                    none_count = none_count + 1
                end
            end
        end

        print(string.format("  mprotect calls:  %d",
              syscalls["mprotect"]))
        if rwx_count > 0 then
            print(string.format(
                "  ⚠ RWX (read+write+exec):  %d  ← DANGEROUS",
                rwx_count))
        end
        if rx_count > 0 then
            print(string.format("  R+X (read+exec):          %d  (normal for code)",
                  rx_count))
        end
        if rw_count > 0 then
            print(string.format("  R+W (read+write):         %d  (normal for data)",
                  rw_count))
        end
        if r_count > 0 then
            print(string.format("  R   (read only):          %d",
                  r_count))
        end
        if none_count > 0 then
            print(string.format("  NONE (guard pages):       %d",
                  none_count))
        end
    end

    -- ============================================================
    -- RISK ASSESSMENT
    -- ============================================================

    print("")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  RUNTIME RISK ASSESSMENT")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("")

    local risk = 0

    -- Network risk
    if #network_inet > 0 then
        print("  ⚠ Binary made INTERNET connections (AF_INET)")
        risk = risk + 3
    elseif #network_unix > 0 then
        print("  ℹ Binary used local Unix sockets (lower risk)")
        risk = risk + 1
    end

    -- Process spawning
    if #processes_spawned > 0 then
        local clone_count = 0
        local exec_count = 0
        for _, op in ipairs(processes_spawned) do
            if op:find("clone") then clone_count = clone_count + 1 end
            if op:find("execve") then exec_count = exec_count + 1 end
        end
        if exec_count > 0 then
            print(string.format(
                "  ⚠ Binary executed %d other program(s)", exec_count))
            risk = risk + 3
        end
        if clone_count > 0 then
            print(string.format(
                "  ℹ Binary created %d thread(s)/fork(s)", clone_count))
            risk = risk + 1
        end
    end

    -- Sensitive syscalls
    for key, desc in pairs(sensitive_hits) do
        if key:find("^syscall:") then
            local syscall_name = key:sub(9)
            local info = SENSITIVE_SYSCALLS[syscall_name]
            if info and info.risk >= 2 then
                print("  ⚠ Sensitive syscall: " .. syscall_name ..
                      " (" .. desc .. ")")
                risk = risk + info.risk
            end
        end
    end

    -- Memory protection
    if syscalls["mprotect"] then
        -- Check for RWX
        local has_rwx = false
        for _, op in ipairs(memory_ops) do
            if op:find("mprotect") and
               (op:find("PROT_READ|PROT_WRITE|PROT_EXEC") or
                op:find("PROT_READ, PROT_WRITE, PROT_EXEC")) then
                has_rwx = true
            end
        end
        if has_rwx then
            print("  ⚠ Binary created RWX memory regions (code injection risk)")
            risk = risk + 4
        else
            print("  ℹ Memory protection changes detected (normal for dynamic linking)")
        end
    end

    -- Sensitive file access
    local sens_file_count = 0
    for path, _ in pairs(sensitive_hits) do
        if not path:find("^syscall:") then
            sens_file_count = sens_file_count + 1
        end
    end
    if sens_file_count > 0 then
        print(string.format(
            "  ⚠ Binary accessed %d sensitive file(s)",
            sens_file_count))
        for path, pattern in pairs(sensitive_hits) do
            if not path:find("^syscall:") then
                print("    → " .. path)
            end
        end
        risk = risk + math.min(sens_file_count * 2, 6)
    end

    -- Final verdict
    print("")
    print("  ──────────────────────────────────────")
    print(string.format("  Risk Score: %d", risk))
    print("")

    if risk == 0 then
        print("  ╔═════════════════════════════════════╗")
        print("  ║  Runtime Risk: CLEAN                 ║")
        print("  ║  Minimal syscall footprint           ║")
        print("  ╚═════════════════════════════════════╝")
    elseif risk <= 3 then
        print("  ╔═════════════════════════════════════╗")
        print("  ║  Runtime Risk: LOW                   ║")
        print("  ║  Standard operating behaviour        ║")
        print("  ╚═════════════════════════════════════╝")
    elseif risk <= 6 then
        print("  ╔═════════════════════════════════════╗")
        print("  ║  Runtime Risk: MEDIUM                ║")
        print("  ║  Review recommended                  ║")
        print("  ╚═════════════════════════════════════╝")
    elseif risk <= 10 then
        print("  ╔═════════════════════════════════════╗")
        print("  ║  Runtime Risk: HIGH                  ║")
        print("  ║  Investigate runtime behaviour       ║")
        print("  ╚═════════════════════════════════════╝")
    else
        print("  ╔═════════════════════════════════════╗")
        print("  ║  Runtime Risk: CRITICAL              ║")
        print("  ║  Immediate investigation required    ║")
        print("  ╚═════════════════════════════════════╝")
    end

    print("")
end

-- ============================================================
-- CLI INTERFACE
-- ============================================================

local function print_usage()
    print([[
MOABI Dynamic Analyser v0.2

Usage:
  luajit moabi-dynamic.lua <binary> [binary-args] [--timeout N]

Options:
  --timeout N    Kill process after N seconds (default: 5)

Examples:
  luajit moabi-dynamic.lua /usr/bin/ls /tmp
  luajit moabi-dynamic.lua /usr/bin/curl --timeout 3
  luajit moabi-dynamic.lua /usr/bin/ssh --timeout 2
  luajit moabi-dynamic.lua /mnt/d/moabi/bin/moabi-entropy /usr/bin/ls

What it does:
  Runs the target binary under strace, captures all system calls,
  and analyses the runtime behaviour for:
    - File access patterns
    - Network activity (Internet vs local sockets)
    - Process creation
    - Memory protection changes (RWX = dangerous)
    - Sensitive file/syscall access
]])
end

local function main()
    math.randomseed(os.time())

    if #arg < 1 then
        print_usage()
        return
    end

    if arg[1] == "--help" or arg[1] == "-h" then
        print_usage()
        return
    end

    -- Check strace is available
    local strace_check = io.popen("which strace 2>/dev/null")
    local strace_path = strace_check:read("*all"):gsub("%s+", "")
    strace_check:close()

    if strace_path == "" then
        print("Error: strace not found")
        print("Install with: sudo apt install strace")
        return
    end

    -- Parse arguments
    local binary = arg[1]
    local extra_args = {}
    local timeout = 5

    local i = 2
    while i <= #arg do
        if arg[i] == "--timeout" and arg[i + 1] then
            timeout = tonumber(arg[i + 1]) or 5
            i = i + 2
        else
            table.insert(extra_args, arg[i])
            i = i + 1
        end
    end

    local args_str = table.concat(extra_args, " ")

    -- Verify binary exists
    if not file_exists(binary) then
        -- Try finding in PATH
        local which = io.popen("which " .. binary .. " 2>/dev/null")
        local found = which:read("*all"):gsub("%s+", "")
        which:close()
        if found ~= "" then
            binary = found
        else
            print("Error: Binary not found: " .. binary)
            return
        end
    end

    run_traced(binary, args_str, timeout)
end

main()
