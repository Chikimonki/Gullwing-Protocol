#!/usr/bin/env luajit
--============================================================================
--  MOABI-ANALYZE v1.0
--  The Convergence Layer: every tool, one evidence object
--
--  Lua = moon = reflection. This file reflects the light of the Zig engines
--  into a single coherent analysis.
--
--  The Zig tools are the engine (sun). The ML is the turbocharger.
--  This analyzer is the mirror that integrates everything.
--
--  Usage:
--    luajit analyzer/moabi-analyze.lua <target> [--model path] [--json] [--no-runtime]
--============================================================================

local SRC = "/mnt/d/moabi/src"
local BIN = "/mnt/d/moabi/bin"
local DEFAULT_MODEL = "/mnt/d/moabi/reports/system.model"

package.path = SRC .. "/?.lua;" .. package.path

local LOG2 = math.log(2)
local EPSILON = 1e-10

-- ============================================================================
--  UTILITIES
-- ============================================================================
local function shq(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function file_exists(p)
    local f = io.open(p, "rb")
    if f then f:close(); return true end
    return false
end

local function is_executable(p)
    local h = io.popen("test -x " .. shq(p) .. " && echo 1")
    if not h then return false end
    local r = h:read("*l"); h:close()
    return r == "1"
end

local function read_file(p)
    local f = io.open(p, "rb")
    if not f then return nil end
    local d = f:read("*a"); f:close()
    return d
end

local function now_ms()
    return os.clock() * 1000
end

local function run_tool(tool, args)
    local path = BIN .. "/" .. tool
    if not file_exists(path) then return nil, "missing: " .. tool end
    local cmd = shq(path) .. " " .. args .. " 2>&1"
    local h = io.popen(cmd)
    if not h then return nil, "cannot run: " .. tool end
    local out = h:read("*a") or ""
    h:close()
    return out
end

-- ============================================================================
--  FFI CORE (the in-process heart)
-- ============================================================================
local ffi2_ok, ffi2 = pcall(require, "moabi-ffi2")
if not ffi2_ok then ffi2 = nil end
local ev = require("moabi-evidence")

-- ============================================================================
--  LAYER 1: IDENTITY  (what IS this object, at rest?)
-- ============================================================================
local function analyze_identity(target)
    local t0 = now_ms()
    local id = { path = target, exists = file_exists(target) }
    if not id.exists then return id end

    local data = read_file(target)
    id.size = data and #data or 0
    id.executable = is_executable(target)

    -- hash via FFI if available, else sha256sum
    if ffi2 and type(ffi2.sha256) == "function" then
        local ok, h = pcall(ffi2.sha256, data)
        if ok and h then
            id.sha256 = h
            id.hash_source = "moabi-ffi2"
        end
    end
    if not id.sha256 then
        local h = io.popen("sha256sum " .. shq(target) .. " 2>/dev/null")
        if h then
            local line = h:read("*l") or ""
            h:close()
            id.sha256 = line:match("^(%x+)")
            id.hash_source = "sha256sum"
        end
    end

    id.elapsed_ms = now_ms() - t0
    return id
end

-- ============================================================================
--  LAYER 2: STRUCTURE  (the ELF skeleton)
-- ============================================================================
local function analyze_structure(target)
    local t0 = now_ms()
    local st = {}

    -- FFI structural pass
    if ffi2 and type(ffi2.extract_elf_features) == "function" then
        local ok, res = pcall(ffi2.extract_elf_features, target)
        if ok and res then
            st.section_count  = res.section_count or 0
            st.import_count   = res.import_count or res.dependency_count or 0
            st.export_count   = res.export_count or 0
            st.symbol_size    = res.symbol_size or 0
            st.has_debug      = (res.has_debug or 0) == 1
            st.source         = "moabi-ffi2"
        end
    end

    -- ELF header basics from raw bytes (always available)
    local data = read_file(target)
    if data and #data >= 20
       and data:byte(1) == 0x7f and data:byte(2) == 0x45
       and data:byte(3) == 0x4c and data:byte(4) == 0x46 then
        st.is_elf = true
        st.elf_class = data:byte(5) == 2 and "ELF64" or "ELF32"
        st.endianness = data:byte(6) == 1 and "little" or "big"
        local et
        if st.endianness == "little" then
            et = data:byte(17) + data:byte(18) * 256
        else
            et = data:byte(17) * 256 + data:byte(18)
        end
        st.elf_type_num = et
        st.elf_type = ({[0]="NONE",[1]="REL",[2]="EXEC",[3]="DYN",[4]="CORE"})[et] or tostring(et)
    else
        st.is_elf = false
    end

    -- moabi-elfparse for deep structure (authoritative when present)
    local elf_out = run_tool("moabi-elfparse", shq(target))
    if elf_out then
        st.elfparse = {
            available = true,
            interp = elf_out:match("[Ii]nterp[^:]*:%s*(%S+)"),
            entry  = elf_out:match("[Ee]ntry[^:]*:%s*(%S+)"),
        }
    else
        st.elfparse = { available = false }
    end

    st.elapsed_ms = now_ms() - t0
    return st
end

-- ============================================================================
--  LAYER 3: SEMANTICS  (what does it MEAN? libraries, symbols, strings)
-- ============================================================================
local function analyze_semantics(target)
    local t0 = now_ms()
    local sem = {}

    -- Library fingerprint (the dependency DNA)
    if ffi2 and type(ffi2.extract_elf_features) == "function" then
        local ok, res = pcall(ffi2.extract_elf_features, target)
        if ok and res then
            sem.libraries = {
                libssl    = (res.has_libssl or 0) == 1,
                libcrypto = (res.has_libcrypto or 0) == 1,
                libcurl   = (res.has_libcurl or 0) == 1,
                libz      = (res.has_libz or 0) == 1,
                lzma      = (res.has_lzma or res.has_liblzma or 0) == 1,
                ncurses   = (res.has_ncurses or 0) == 1,
                readline  = (res.has_readline or 0) == 1,
                python    = (res.has_libpython or res.has_python or 0) == 1,
                perl      = (res.has_libperl or res.has_perl or 0) == 1,
                ruby      = (res.has_libruby or res.has_ruby or 0) == 1,
            }
            sem.library_source = "moabi-ffi2"
        end
    end

    -- Symbols (via moabi-symbols engine)
    local sym_out = run_tool("moabi-symbols", shq(target))
    if sym_out then
        sem.symbols = { available = true }
        local n = 0
        for _ in sym_out:gmatch("\n") do n = n + 1 end
        sem.symbols.line_count = n
        -- Semantic signal: detect known families in symbol names
        sem.symbols.has_py_eval   = sym_out:find("PyEval") ~= nil
        sem.symbols.has_curl_easy = sym_out:find("curl_easy") ~= nil
        sem.symbols.has_ssl_ctx   = sym_out:find("SSL_CTX") ~= nil
        sem.symbols.has_z_main    = sym_out:find("luaL_") ~= nil
    else
        sem.symbols = { available = false }
    end

    -- Strings (via moabi-strings engine)
    local str_out = run_tool("moabi-strings", shq(target))
    if str_out then
        sem.strings = { available = true }
        sem.strings.has_usage  = str_out:find("[Uu]sage") ~= nil
        sem.strings.has_gcc    = str_out:find("GCC:") ~= nil
        sem.strings.has_zig    = str_out:find("zig") ~= nil
        sem.strings.has_rust   = str_out:find("rustc") ~= nil
        sem.strings.has_python = str_out:find("libpython") ~= nil
        local n = 0
        for _ in str_out:gmatch("\n") do n = n + 1 end
        sem.strings.line_count = n
    else
        sem.strings = { available = false }
    end

    sem.elapsed_ms = now_ms() - t0
    return sem
end

-- ============================================================================
--  LAYER 4: ENTROPY PROFILE  (the byte-level soul)
-- ============================================================================
local function analyze_entropy_profile(target)
    local t0 = now_ms()
    local ep = {}

    -- Prefer the standalone engine (it is the authoritative implementation)
    local ent_out = run_tool("moabi-entropy", shq(target))
    if ent_out then
        ep.available = true
        ep.global = tonumber(ent_out:match("([%d]%.%d+)%s*/%s*8"))
            or tonumber(ent_out:match("Entropy[^%d]*([%d]+%.%d+)"))
        ep.windows_high = tonumber(ent_out:match("(%d+)%s*high"))
    end

    -- Caves (packing/interleave signal)
    local cave_out = run_tool("moabi-caves", shq(target))
    if cave_out then
        ep.caves = { available = true }
        ep.caves.total = tonumber(cave_out:match("(%d+)%s*caves"))
            or tonumber(cave_out:match("[Tt]otal[^%d]*(%d+)"))
    else
        ep.caves = { available = false }
    end

    ep.elapsed_ms = now_ms() - t0
    return ep
end

-- ============================================================================
--  LAYER 5: ML VERDICT  (the turbocharger, not the engine)
-- ============================================================================
local function analyze_ml(target, model_path)
    local t0 = now_ms()
    local ml = { model = model_path, available = file_exists(model_path) }
    if not ml.available then return ml end

    local script = SRC .. "/moabi-ml.lua"
    if not file_exists(script) then
        ml.error = "moabi-ml.lua missing"
        return ml
    end

    local cmd = "luajit " .. shq(script) .. " classify "
        .. shq(model_path) .. " " .. shq(target) .. " 2>&1"
    local h = io.popen(cmd)
    if not h then ml.error = "cannot invoke moabi-ml"; return ml end
    local out = h:read("*a") or ""
    h:close()

    ml.class = out:match("Class:%s+([%w_%-]+)") or out:match("Classified:%s+([%w_%-]+)")
    ml.confidence = tonumber(out:match("Confidence:%s+([%d%.]+)"))
    ml.anomaly = out:match("Anomaly:%s+(%a+)") == "YES"
        or out:find("ANOMALY") ~= nil
    ml.avg_dist = tonumber(out:match("Avg dist:%s+([%d%.]+)"))
    ml.threshold = tonumber(out:match("threshold%s+([%d%.]+)"))
    ml.exact_match = out:find("EXACT TRAINING MATCH") ~= nil
        or (ml.avg_dist ~= nil and ml.avg_dist <= EPSILON)

    ml.elapsed_ms = now_ms() - t0
    return ml
end

-- ============================================================================
--  LAYER 6: RUNTIME  (does its behavior agree with its structure?)
-- ============================================================================
local NETWORK_SYSCALLS = {
    socket=1, connect=1, accept=1, accept4=1, bind=1, listen=1,
    sendto=1, recvfrom=1, sendmsg=1, recvmsg=1,
}
local FILE_SYSCALLS = {
    open=1, openat=1, openat2=1, read=1, write=1, close=1,
    stat=1, fstat=1, lstat=1, newfstatat=1, access=1,
    unlink=1, rename=1, readlink=1,
}
local PROC_SYSCALLS = {
    execve=1, execveat=1, fork=1, vfork=1, clone=1, clone3=1,
}

local function analyze_runtime(target)
    local t0 = now_ms()
    local rt = { attempted = true }

    if not is_executable(target) then
        rt.attempted = false
        rt.reason = "not executable"
        return rt
    end

    local trace = os.tmpname() .. ".moabi"
    local cmd = "timeout 3s strace -f -qq -o " .. shq(trace)
        .. " -- " .. shq(target) .. " >/dev/null 2>&1"
    os.execute(cmd)

    local f = io.open(trace, "r")
    if not f then
        rt.attempted = false
        rt.reason = "trace unavailable"
        os.remove(trace)
        return rt
    end

    local counts, total = {}, 0
    for line in f:lines() do
        local sc = line:match("^%s*%d+%s+([%a_][%w_]*)%(")
            or line:match("^%s*([%a_][%w_]*)%(")
        if sc then counts[sc] = (counts[sc] or 0) + 1; total = total + 1 end
    end
    f:close()
    os.remove(trace)

    local net, fil, prc = 0, 0, 0
    local uniq = 0
    for sc, n in pairs(counts) do
        uniq = uniq + 1
        if NETWORK_SYSCALLS[sc] then net = net + n end
        if FILE_SYSCALLS[sc] then fil = fil + n end
        if PROC_SYSCALLS[sc] then prc = prc + n end
    end

    local e = 0.0
    if total > 0 then
        for _, n in pairs(counts) do
            local p = n / total
            e = e - p * (math.log(p) / LOG2)
        end
    end

    rt.total = total
    rt.unique = uniq
    rt.entropy = e
    rt.net_count = net
    rt.file_count = fil
    rt.proc_count = prc
    rt.exec_count = counts.execve or 0
    rt.net_ratio = total > 0 and net / total or 0
    rt.file_ratio = total > 0 and fil / total or 0
    rt.elapsed_ms = now_ms() - t0
    return rt
end

-- ============================================================================
--  CONVERGENCE: risk engine (evidence -> decision)
-- ============================================================================
local function converge(ev)
    local risk = { score = 0, signals = {}, verdict = "UNKNOWN" }

    -- Structural risk
    if ev.structure and ev.structure.is_elf == false then
        risk.score = risk.score + 2
        risk.signals[#risk.signals + 1] = "non-ELF object"
    end

    -- ML anomaly
    if ev.ml and ev.ml.anomaly then
        risk.score = risk.score + 3
        risk.signals[#risk.signals + 1] = string.format(
            "ML anomaly (avg_dist %.2f exceeds threshold)", ev.ml.avg_dist or 0)
    end

    -- Exact training match lowers risk (known-good identity)
    if ev.ml and ev.ml.exact_match and not ev.ml.anomaly then
        risk.score = risk.score - 2
        risk.signals[#risk.signals + 1] = "exact match to known training identity"
    end

    -- Runtime vs static agreement
    if ev.runtime and ev.runtime.attempted then
        local rt = ev.runtime

        -- Structure says network tool, runtime silent
        local expects_net = ev.semantics and ev.semantics.libraries
            and (ev.semantics.libraries.libssl or ev.semantics.libraries.libcrypto
                 or ev.semantics.libraries.libcurl)
        if expects_net and rt.net_count == 0 and rt.total > 20 then
            risk.score = risk.score + 1
            risk.signals[#risk.signals + 1] =
                "crypto/network-linked but zero network syscalls observed"
        end

        -- Plain utility speaking to the network
        local plain = ev.semantics and ev.semantics.libraries
            and not (ev.semantics.libraries.libssl or ev.semantics.libraries.libcrypto
                     or ev.semantics.libraries.libcurl)
        if plain and rt.net_ratio > 0.10 then
            risk.score = risk.score + 3
            risk.signals[#risk.signals + 1] =
                "no network libraries but significant network syscalls"
        end

        -- Execution anomalies
        if rt.exec_count > 1 then
            risk.score = risk.score + 2
            risk.signals[#risk.signals + 1] =
                "re-exec observed (" .. rt.exec_count .. " execve calls)"
        elseif rt.exec_count == 1 and rt.total < 10 then
            risk.score = risk.score + 2
            risk.signals[#risk.signals + 1] =
                "execve with only " .. rt.total .. " syscalls (stub-like)"
        end

        if rt.entropy > 4.5 then
            risk.score = risk.score + 1
            risk.signals[#risk.signals + 1] =
                "high syscall entropy (" .. string.format("%.2f", rt.entropy) .. ")"
        end
    end

    -- Verdict mapping
    if risk.score <= 0 then
        risk.verdict = "CLEAR"
    elseif risk.score <= 2 then
        risk.verdict = "NOTABLE"
    elseif risk.score <= 4 then
        risk.verdict = "SUSPICIOUS"
    else
        risk.verdict = "HOSTILE"
    end

    return risk
end

-- ============================================================================
--  OUTPUT: the single evidence object
-- ============================================================================
local function print_report(ev)
    local line = string.rep("=", 64)
    local thin = string.rep("-", 64)

    print(line)
    print("  MOABI ANALYSIS — CONVERGENT EVIDENCE")
    print(line)
    print()

    print("  [IDENTITY]")
    print("    Path:     " .. tostring(ev.identity.path))
    print("    Size:     " .. tostring(ev.identity.size) .. " bytes")
    print("    SHA-256:  " .. tostring(ev.identity.sha256 or "unavailable"))
    print("    Executable: " .. tostring(ev.identity.executable))
    print()

    print("  [STRUCTURE]")
    print("    ELF:      " .. tostring(ev.structure.is_elf))
    if ev.structure.is_elf then
        print("    Class:    " .. tostring(ev.structure.elf_class))
        print("    Type:     " .. tostring(ev.structure.elf_type))
        print("    Sections: " .. tostring(ev.structure.section_count))
        print("    Imports:  " .. tostring(ev.structure.import_count))
        print("    Exports:  " .. tostring(ev.structure.export_count))
        print("    Debug:    " .. tostring(ev.structure.has_debug))
    end
    print()

    print("  [SEMANTICS]")
    if ev.semantics.libraries then
        local libs = {}
        for k, v in pairs(ev.semantics.libraries) do
            if v then libs[#libs + 1] = k end
        end
        table.sort(libs)
        print("    Libraries: " .. (#libs > 0 and table.concat(libs, ", ") or "none detected"))
    end
    if ev.semantics.strings and ev.semantics.strings.available then
        local s = ev.semantics.strings
        local tags = {}
        if s.has_gcc then tags[#tags + 1] = "GCC" end
        if s.has_zig then tags[#tags + 1] = "Zig" end
        if s.has_rust then tags[#tags + 1] = "Rust" end
        print("    Toolchain: " .. (#tags > 0 and table.concat(tags, ", ") or "unknown"))
    end
    if ev.semantics.symbols and ev.semantics.symbols.available then
        local sy = ev.semantics.symbols
        local tags = {}
        if sy.has_py_eval then tags[#tags + 1] = "CPython-API" end
        if sy.has_curl_easy then tags[#tags + 1] = "libcurl-API" end
        if sy.has_ssl_ctx then tags[#tags + 1] = "OpenSSL-API" end
        print("    Symbol families: " .. (#tags > 0 and table.concat(tags, ", ") or "none notable"))
    end
    print()

    print("  [ML VERDICT]")
    if ev.ml and ev.ml.available then
        print("    Class:      " .. tostring(ev.ml.class))
        print("    Confidence: " .. tostring(ev.ml.confidence) .. "%")
        print("    Anomaly:    " .. tostring(ev.ml.anomaly))
        if ev.ml.exact_match then
            print("    Note:       exact training identity (not held-out inference)")
        end
    else
        print("    Unavailable (model not found)")
    end
    print()

    print("  [RUNTIME]")
    if ev.runtime and ev.runtime.attempted then
        local rt = ev.runtime
        print(string.format("    Syscalls:   %d total, %d unique", rt.total, rt.unique))
        print(string.format("    Entropy:    %.4f", rt.entropy))
        print(string.format("    Network:    %d calls (%.1f%%)", rt.net_count, rt.net_ratio * 100))
        print(string.format("    File I/O:   %d calls (%.1f%%)", rt.file_count, rt.file_ratio * 100))
        print(string.format("    execve:     %d", rt.exec_count))
    else
        print("    " .. tostring(ev.runtime and ev.runtime.reason or "not attempted"))
    end
    print()

    print(thin)
    print("  [CONVERGENCE]")
    print("    Verdict:  " .. ev.risk.verdict .. "  (score " .. ev.risk.score .. ")")
    if #ev.risk.signals > 0 then
        print("    Signals:")
        for _, s in ipairs(ev.risk.signals) do
            print("      - " .. s)
        end
    else
        print("    Signals:  none")
    end
    print()

    -- Timing reflection
    print("  [TIMING]")
    local layers = {
        { "identity", ev.identity.elapsed_ms },
        { "structure", ev.structure.elapsed_ms },
        { "semantics", ev.semantics.elapsed_ms },
        { "entropy", ev.entropy_profile and ev.entropy_profile.elapsed_ms },
        { "ml", ev.ml and ev.ml.elapsed_ms },
        { "runtime", ev.runtime and ev.runtime.elapsed_ms },
    }
    local total = 0
    for _, l in ipairs(layers) do
        if l[2] then
            print(string.format("    %-10s %8.2f ms", l[1], l[2]))
            total = total + l[2]
        end
    end
    print(string.format("    %-10s %8.2f ms", "TOTAL", total))
    print()
    print(line)
end

-- ============================================================================
--  MAIN
-- ============================================================================
local function usage()
    print("MOABI-ANALYZE v1.0 — the convergence layer")
    print()
    print("Usage:")
    print("  luajit analyzer/moabi-analyze.lua <target> [--model path] [--no-runtime]")
    print()
    print("Layers: identity, structure, semantics, entropy, ml, runtime -> convergence")
end

--json
local function main()
    local target = arg[1]
    if not target or target == "-h" or target == "--help" then
        usage()
        return 0
    end

    local model = DEFAULT_MODEL
    local do_runtime = true
    local i = 2
    while i <= #arg do
        if arg[i] == "--model" and arg[i + 1] then
            model = arg[i + 1]
            i = i + 2
        elseif arg[i] == "--no-runtime" then
            do_runtime = false
            i = i + 1
        else
            i = i + 1
        end
    end

    if not file_exists(target) then
        io.stderr:write("Target not found: " .. tostring(target) .. "\n")
        return 1
    end

    local e = ev.new(target)

    -- Identity
    local t0 = os.clock()
    local id = analyze_identity(target)
    ev.set_identity(e, id, "moabi-ffi2+filesystem", (os.clock() - t0) * 1000)

    -- Structure
    t0 = os.clock()
    local st = analyze_structure(target)
    ev.set_structure(e, st, "moabi-ffi2+elfparse", (os.clock() - t0) * 1000)

    -- Semantics
    t0 = os.clock()
    local sem = analyze_semantics(target)
    ev.set_semantics(e, sem, "moabi-symbols+strings", (os.clock() - t0) * 1000)

    -- Entropy profile
    t0 = os.clock()
    local ep = analyze_entropy_profile(target)
    ev.set_entropy_profile(e, ep, "moabi-entropy", (os.clock() - t0) * 1000)

    -- ML
    t0 = os.clock()
    local ml = analyze_ml(target, model)
    ev.set_ml(e, ml, "moabi-ml", (os.clock() - t0) * 1000)

    -- Runtime
    if do_runtime then
        t0 = os.clock()
        local rt = analyze_runtime(target)
        ev.set_runtime(e, rt, "strace", (os.clock() - t0) * 1000)
    end

    -- Converge and reflect
    ev.converge(e)
    ev.print_report(e)

    -- Optional JSON export
    if json_output then
        local outpath = target:gsub(".+/(.+)", "/mnt/d/moabi/reports/%1.evidence.json")
        ev.write_json(e, outpath)
        print("Evidence JSON written to " .. outpath)
    end

    return 0
end

local ok, ret = pcall(main)
if not ok then
    io.stderr:write("\nERROR: " .. tostring(ret) .. "\n")
    os.exit(1)
end
os.exit(ret or 0)
