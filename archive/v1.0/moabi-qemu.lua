#!/usr/bin/env luajit
--============================================================================
--  MOABI-QEMU v1.0
--  Tier-2 escalation engine for runnable ELF targets.
--
--  Notes:
--    - Shared libraries (.so) and relocatable objects (.o) are static artifacts.
--    - Non-ELF executables (scripts, blobs) are reported as Tier-2 N/A.
--    - QEMU user-mode is emulation, not a security sandbox.
--============================================================================

local M = {}

local function shq(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function file_exists(path)
    local f = io.open(path, "rb")
    if f then
        f:close()
        return true
    end
    return false
end

local function which(cmd)
    local h = io.popen("which " .. shq(cmd) .. " 2>/dev/null")
    if not h then return nil end
    local r = h:read("*l")
    h:close()
    if r and #r > 0 then return r end
    return nil
end

local QEMU_MAP = {
    x64 = "qemu-x86_64",
    x86 = "qemu-i386",
    arm64 = "qemu-aarch64",
    aarch64 = "qemu-aarch64",
    riscv64 = "qemu-riscv64",
    arm = "qemu-arm",
}

local function read_head(path, n)
    local f = io.open(path, "rb")
    if not f then return nil end
    local d = f:read(n)
    f:close()
    return d
end

local function is_elf_bytes(d)
    return d
       and #d >= 4
       and d:byte(1) == 0x7f
       and d:byte(2) == 0x45
       and d:byte(3) == 0x4c
       and d:byte(4) == 0x46
end

local function detect_arch(path)
    local d = read_head(path, 32)
    if not d or not is_elf_bytes(d) then
        return "unknown"
    end

    local le = d:byte(6) == 1
    local machine
    if le then
        machine = (d:byte(19) or 0) + (d:byte(20) or 0) * 256
    else
        machine = (d:byte(19) or 0) * 256 + (d:byte(20) or 0)
    end

    if machine == 62  then return "x64" end       -- EM_X86_64
    if machine == 3   then return "x86" end       -- EM_386
    if machine == 183 then return "arm64" end     -- EM_AARCH64
    if machine == 243 then return "riscv64" end   -- EM_RISCV
    if machine == 40  then return "arm" end       -- EM_ARM
    return "unknown"
end

local function is_executable_permission(path)
    local h = io.popen("test -x " .. shq(path) .. " && echo 1")
    if not h then return false end
    local r = h:read("*l")
    h:close()
    return r == "1"
end

local function classify_target_kind(path)
    -- Returns:
    --   "exec"      runnable ELF executable / PIE
    --   "artifact"  ELF shared library / object / non-runnable ELF
    --   "nonelf"    non-ELF file (even if executable bit is set)
    local d = read_head(path, 8192)
    if not d then return "nonelf" end

    if not is_elf_bytes(d) then
        return "nonelf"
    end

    if #d < 20 then
        return "artifact"
    end

    local le = d:byte(6) == 1
    local et
    if le then
        et = (d:byte(17) or 0) + (d:byte(18) or 0) * 256
    else
        et = (d:byte(17) or 0) * 256 + (d:byte(18) or 0)
    end

    if et == 2 then
        -- ET_EXEC
        return "exec"
    elseif et == 1 then
        -- ET_REL
        return "artifact"
    elseif et == 3 then
        -- ET_DYN: PIE executable or shared library
        -- Look for interpreter path near the start of the file.
        if d:find("/lib64/ld-linux", 1, true)
        or d:find("/lib/ld-linux", 1, true)
        or d:find("ld-linux", 1, true)
        or d:find("ld.so", 1, true)
        then
            return "exec"
        end
        return "artifact"
    end

    return "artifact"
end

local function parse_qemu_strace(stdout_path)
    local syscalls = {}
    local total = 0
    local f = io.open(stdout_path, "r")
    if not f then
        return syscalls, total
    end

    for line in f:lines() do
        local sc = line:match("^([%a_][%w_]*)%(")
        if sc then
            syscalls[sc] = (syscalls[sc] or 0) + 1
            total = total + 1
        end
    end
    f:close()

    return syscalls, total
end

local function syscall_entropy(syscalls, total)
    if total <= 0 then return 0.0 end
    local e = 0.0
    for _, n in pairs(syscalls) do
        local p = n / total
        e = e - p * (math.log(p) / math.log(2))
    end
    return e
end

local function count_trace_execs(log_path)
    local n = 0
    local f = io.open(log_path, "r")
    if not f then return 0 end
    for line in f:lines() do
        if line:find("Trace 0x", 1, true) then
            n = n + 1
        end
    end
    f:close()
    return n
end

function M.escalate(target, opts)
    opts = opts or {}

    local result = {
        target = target,
        architecture = "unknown",
        qemu = false,
        qemu_binary = nil,
        emulated = false,
        runnable = false,
        tier2_verdict = "TIER-2 UNKNOWN",
        signals = {},
        syscalls = 0,
        entropy = 0.0,
        network = 0,
        file_io = 0,
        execve = 0,
        instructions = 0,
        exit_code = nil,
    }

    if not file_exists(target) then
        result.tier2_verdict = "TIER-2 ERROR"
        result.signals[#result.signals + 1] = "target not found"
        return result
    end

    local arch = opts.arch or detect_arch(target)
    result.architecture = arch

    local kind = classify_target_kind(target)
    if kind == "artifact" then
        result.runnable = false
        result.tier2_verdict = "TIER-2 N/A (static artifact)"
        result.signals[#result.signals + 1] =
            "not a runnable binary (library/object) — Tier-2 execution skipped"
        return result
    elseif kind == "nonelf" then
        result.runnable = false
        result.tier2_verdict = "TIER-2 N/A (non-ELF executable)"
        result.signals[#result.signals + 1] =
            "non-ELF executable — QEMU user-mode only supports ELF targets"
        return result
    end

    result.runnable = true

    local runner_name = QEMU_MAP[arch]
    local runner = runner_name and which(runner_name) or nil
    if not runner then
        result.tier2_verdict = "TIER-2 N/A (no QEMU for architecture)"
        result.signals[#result.signals + 1] =
            "no QEMU user-mode runner for architecture: " .. tostring(arch)
        return result
    end

    result.qemu = true
    result.qemu_binary = runner
    result.emulated = true

    local workspace = os.tmpname() .. ".moabi-qemu"
    os.execute("mkdir -p " .. shq(workspace))

    local stdout_path = workspace .. "/stdout"
    local log_path    = workspace .. "/qemu.log"
    local exit_path   = workspace .. "/exit"

    local timeout = tonumber(opts.timeout) or 3

    local cmd = string.format(
        "timeout %ds %s -strace -d exec -D %s %s >%s 2>&1; echo $? > %s",
        timeout,
        runner,
        shq(log_path),
        shq(target),
        shq(stdout_path),
        shq(exit_path)
    )

    os.execute(cmd)

    local ef = io.open(exit_path, "r")
    if ef then
        result.exit_code = tonumber(ef:read("*l") or "")
        ef:close()
    end

    local syscalls, total = parse_qemu_strace(stdout_path)
    result.syscalls = total
    result.entropy = syscall_entropy(syscalls, total)
    result.execve = syscalls.execve or 0

    local net_count = 0
    for _, name in ipairs({
        "socket","connect","accept","accept4","bind","listen",
        "sendto","recvfrom","sendmsg","recvmsg"
    }) do
        net_count = net_count + (syscalls[name] or 0)
    end
    result.network = net_count

    local file_count = 0
    for _, name in ipairs({
        "open","openat","openat2","read","write","close",
        "stat","fstat","lstat","newfstatat","access"
    }) do
        file_count = file_count + (syscalls[name] or 0)
    end
    result.file_io = file_count

    result.instructions = count_trace_execs(log_path)

    os.remove(stdout_path)
    os.remove(log_path)
    os.remove(exit_path)
    os.execute("rmdir " .. shq(workspace) .. " >/dev/null 2>&1")

    -- Signals
    if result.syscalls == 0 and (result.exit_code or 0) ~= 0 then
        result.signals[#result.signals + 1] =
            "binary crashed or refused to execute under containment"
    end
    if result.execve > 1 then
        result.signals[#result.signals + 1] =
            "re-execution detected (" .. tostring(result.execve) .. " execve calls)"
    end
    if result.instructions > 100000 then
        result.signals[#result.signals + 1] =
            "high instruction count — complex or obfuscated execution"
    end
    if result.instructions > 0 and result.instructions < 10 and result.syscalls < 5 then
        result.signals[#result.signals + 1] =
            "minimal execution — possible stub or dropper"
    end

    if #result.signals > 2 then
        result.tier2_verdict = "CONFIRMED HOSTILE"
    elseif #result.signals > 0 then
        result.tier2_verdict = "ESCALATED SUSPICIOUS"
    else
        result.tier2_verdict = "TIER-2 CLEAR"
    end

    return result
end

function M.print_report(result)
    local line = string.rep("=", 64)
    print(line)
    print("  MOABI TIER-2 ESCALATION REPORT (QEMU)")
    print(line)
    print()
    print("  Target:        " .. tostring(result.target))
    print("  Architecture:  " .. tostring(result.architecture))
    print("  QEMU:          " ..
        (result.qemu and ("yes (" .. tostring(result.qemu_binary) .. ")") or "no"))
    print("  Emulated:      " .. tostring(result.emulated))
    print("  Runnable:      " .. tostring(result.runnable))
    print()
    print("  Syscalls:      " .. tostring(result.syscalls))
    print(string.format("  Entropy:       %.4f", tonumber(result.entropy) or 0.0))
    print("  Network:       " .. tostring(result.network))
    print("  File I/O:      " .. tostring(result.file_io))
    print("  execve:        " .. tostring(result.execve))
    print("  Instructions:  " .. tostring(result.instructions))
    if result.exit_code ~= nil then
        print("  Exit code:     " .. tostring(result.exit_code))
    end
    print()
    print("  Tier-2 Verdict: " .. tostring(result.tier2_verdict))
    if #result.signals > 0 then
        print("  Signals:")
        for _, s in ipairs(result.signals) do
            print("    - " .. s)
        end
    end
    print()
    print(line)
end

-- CLI
local function main()
    local target = arg[1]
    if not target or target == "-h" or target == "--help" then
        print("Usage: luajit moabi-qemu.lua <target> [--arch ARCH] [--timeout N]")
        return 0
    end

    local opts = {}
    local i = 2
    while i <= #arg do
        if arg[i] == "--arch" and arg[i + 1] then
            opts.arch = arg[i + 1]
            i = i + 2
        elseif arg[i] == "--timeout" and arg[i + 1] then
            opts.timeout = tonumber(arg[i + 1]) or 3
            i = i + 2
        else
            i = i + 1
        end
    end

    local result = M.escalate(target, opts)
    M.print_report(result)
    return 0
end

if arg and arg[0] and arg[1] then
    local ok, err = pcall(main)
    if not ok then
        io.stderr:write("ERROR: " .. tostring(err) .. "\n")
        os.exit(1)
    end
end

return M
