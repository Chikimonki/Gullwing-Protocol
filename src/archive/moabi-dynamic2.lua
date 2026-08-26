#!/usr/bin/env luajit
--============================================================================
--  MOABI-DYNAMIC2 v1.3
--  CRA 2024 Runtime Gatekeeper and Supervisor
--  Part of the MOABI Binary Analysis Suite
--  https://moabi.com/
--
--  Uses:
--    moabi-ffi2.lua   (read_buffer, extract_byte_stats)
--    system.model     (MOABI-ML v2 k-NN model)
--
--  Usage:
--    luajit moabi-dynamic2.lua MODEL TARGET [TARGET_ARGS...]
--    luajit moabi-dynamic2.lua MODEL TARGET --static-only
--============================================================================

local LOG2 = math.log(2)
local WINDOW_SIZE = 1024
local EPSILON = 1e-10
local DEFAULT_K = 5

-- Locate sibling modules
local script_dir = (arg[0] or ""):match("^(.*)/")
if script_dir and script_dir ~= "" then
    package.path = script_dir .. "/?.lua;" .. package.path
end

-- Load FFI wrapper (current filename: moabi-ffi2)
local ffi_ok, ffi_mod = pcall(require, "moabi-ffi2")
if not ffi_ok then
    ffi_mod = nil
end

-- ============================================================================
--  POLICY TIERS
-- ============================================================================
local PROFILES = {
    TRUSTED = {
        name = "TIER 1: TRUSTED",
        desc = "High-confidence classification; standard runtime observation.",
        color = "\27[32m",
    },
    UNCERTAIN = {
        name = "TIER 2: UNCERTAIN",
        desc = "Moderate confidence or atypical feature profile.",
        color = "\27[33m",
    },
    ANOMALY = {
        name = "TIER 3: ANOMALY / UNKNOWN",
        desc = "Low-confidence or structurally anomalous target.",
        color = "\27[31m",
    },
}
local RESET = "\27[0m"

-- ============================================================================
--  HELPERS
-- ============================================================================
local function fail(msg)
    error(msg, 0)
end

local function shq(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function read_file(path)
    local f, err = io.open(path, "rb")
    if not f then return nil, err end
    local data = f:read("*a")
    f:close()
    if not data or #data == 0 then return nil, "empty file" end
    return data
end

local function file_exists(path)
    local f = io.open(path, "rb")
    if f then f:close(); return true end
    return false
end

local function is_executable(path)
    local p = io.popen("test -x " .. shq(path) .. " && echo 1")
    if not p then return false end
    local r = p:read("*l")
    p:close()
    return r == "1"
end

-- ============================================================================
--  ENTROPY
-- ============================================================================
local function entropy_from_hist(hist, total)
    if total <= 0 then return 0.0 end
    local e = 0.0
    for i = 0, 255 do
        local n = hist[i] or 0
        if n > 0 then
            local p = n / total
            e = e - p * (math.log(p) / LOG2)
        end
    end
    return e
end

-- ============================================================================
--  FEATURE EXTRACTION (15-dim, matches moabi-ml.lua schema)
-- ============================================================================
local FEATURE_NAMES = {
    "size_log", "entropy", "byte_mean", "byte_stddev", "null_ratio",
    "printable_ratio", "is_elf", "elf_class_num", "elf_type_num",
    "entropy_variance", "high_entropy_ratio", "low_entropy_ratio",
    "top_byte_ratio", "ff_ratio", "packer_detected",
    "dependency_count",
    "has_libssl",
    "has_libcrypto",
    "has_libcurl",
    "has_libz",
    "has_liblzma",
    "has_ncurses",
    "has_readline",
    "has_python",
    "has_perl",
    "has_ruby",
}
local N_FEATURES = #FEATURE_NAMES

local function extract_features_lua(data)
    local size = #data
    local feat = {}
    feat.size_log = math.log(size + 1)

    local hist = {}
    for i = 0, 255 do hist[i] = 0 end
    local byte_sum, byte_sq = 0, 0
    local null_c, ff_c, print_c = 0, 0, 0

    for i = 1, size do
        local b = data:byte(i)
        hist[b] = hist[b] + 1
        byte_sum = byte_sum + b
        byte_sq = byte_sq + b * b
        if b == 0 then null_c = null_c + 1 end
        if b == 255 then ff_c = ff_c + 1 end
        if b >= 0x20 and b <= 0x7e then print_c = print_c + 1 end
    end

    local mean = byte_sum / size
    local var = math.max(0, byte_sq / size - mean * mean)
    local top = 0
    for i = 0, 255 do if hist[i] > top then top = hist[i] end end

    feat.entropy = entropy_from_hist(hist, size)
    feat.byte_mean = mean
    feat.byte_stddev = math.sqrt(var)
    feat.null_ratio = null_c / size
    feat.printable_ratio = print_c / size
    feat.top_byte_ratio = top / size
    feat.ff_ratio = ff_c / size
    feat.dependency_count = feat.dependency_count or 0.0
    feat.has_libssl      = feat.has_libssl      or 0.0
    feat.has_libcrypto   = feat.has_libcrypto   or 0.0
    feat.has_libcurl     = feat.has_libcurl     or 0.0
    feat.has_libz        = feat.has_libz        or 0.0
    feat.has_liblzma     = feat.has_liblzma     or 0.0
    feat.has_ncurses     = feat.has_ncurses     or 0.0
    feat.has_readline    = feat.has_readline    or 0.0
    feat.has_python      = feat.has_python      or 0.0
    feat.has_perl        = feat.has_perl        or 0.0
    feat.has_ruby        = feat.has_ruby        or 0.0

    -- ELF
    if size >= 5 and data:byte(1) == 0x7f and data:byte(2) == 0x45
       and data:byte(3) == 0x4c and data:byte(4) == 0x46 then
        feat.is_elf = 1.0
        feat.elf_class_num = 0.0 + data:byte(5)
        feat.elf_type_num = 0.0
        if size >= 18 then
            local ei = data:byte(6)
            if ei == 1 then
                feat.elf_type_num = 0.0 + data:byte(17) + data:byte(18) * 256
            elseif ei == 2 then
                feat.elf_type_num = 0.0 + data:byte(17) * 256 + data:byte(18)
            end
        end
    else
        feat.is_elf = 0.0
        feat.elf_class_num = 0.0
        feat.elf_type_num = 0.0
    end

    -- Windowed entropy
    local nw = math.floor(size / WINDOW_SIZE)
    if nw >= 2 then
        local we = {}
        for w = 0, nw - 1 do
            local wh = {}
            for i = 0, 255 do wh[i] = 0 end
            local s = w * WINDOW_SIZE + 1
            for i = s, s + WINDOW_SIZE - 1 do
                local b = data:byte(i)
                wh[b] = wh[b] + 1
            end
            we[#we + 1] = entropy_from_hist(wh, WINDOW_SIZE)
        end
        local esum = 0
        for _, v in ipairs(we) do esum = esum + v end
        local emean = esum / #we
        local evar, hi, lo = 0, 0, 0
        for _, v in ipairs(we) do
            evar = evar + (v - emean) * (v - emean)
            if v > 7.0 then hi = hi + 1 end
            if v < 2.0 then lo = lo + 1 end
        end
        feat.entropy_variance = evar / #we
        feat.high_entropy_ratio = hi / #we
        feat.low_entropy_ratio = lo / #we
    else
        feat.entropy_variance = 0.0
        feat.high_entropy_ratio = 0.0
        feat.low_entropy_ratio = 0.0
    end

    feat.packer_detected = 0.0
    if feat.entropy > 7.2 and feat.null_ratio < 0.05 and feat.printable_ratio < 0.10 then
        feat.packer_detected = 1.0
    end

    return feat
end

local function extract_features(target_path)
    -- Try FFI path first
    if ffi_mod and type(ffi_mod.read_buffer) == "function"
       and type(ffi_mod.extract_byte_stats) == "function" then
        local ok, buf, len, raw = pcall(ffi_mod.read_buffer, target_path)
        if ok and buf and len and raw then
            local ok2, stats = pcall(ffi_mod.extract_byte_stats, buf, len, raw)
            if ok2 and stats then
                -- Build full 15-dim vector using FFI stats + Lua ELF/window
                local feat = extract_features_lua(raw)
                -- Override byte-level stats with FFI values
                feat.entropy = stats.entropy or feat.entropy
                feat.byte_mean = stats.byte_mean or feat.byte_mean
                feat.byte_stddev = stats.byte_stddev or feat.byte_stddev
                feat.null_ratio = stats.null_ratio or feat.null_ratio
                feat.printable_ratio = stats.printable_ratio or feat.printable_ratio
                feat.ff_ratio = stats.ff_ratio or feat.ff_ratio
                feat.top_byte_ratio = stats.top_byte_ratio or feat.top_byte_ratio
                return feat, "moabi-ffi2"
                if ffi_mod and type(ffi_mod.extract_dependency_features) == "function" then
                    local ok_dep, dep = pcall(ffi_mod.extract_dependency_features, target_path)
                    if ok_dep and dep then
                        feat.dependency_count = dep.dependency_count or 0.0
                        feat.has_libssl      = dep.has_libssl      or 0.0
                        feat.has_libcrypto   = dep.has_libcrypto   or 0.0
                        feat.has_libcurl     = dep.has_libcurl     or 0.0
                        feat.has_libz        = dep.has_libz        or 0.0
                        feat.has_liblzma     = dep.has_liblzma     or 0.0
                        feat.has_ncurses     = dep.has_ncurses     or 0.0
                        feat.has_readline    = dep.has_readline    or 0.0
                        feat.has_python      = dep.has_python      or 0.0
                        feat.has_perl        = dep.has_perl        or 0.0
                        feat.has_ruby        = dep.has_ruby        or 0.0
                    end
                end
            end
        end
    end

    -- Pure Lua fallback
    local data, err = read_file(target_path)
    if not data then return nil, err end
    local feat = extract_features_lua(data)
    return feat, "lua-fallback"
end

local function features_to_vector(feat)
    local v = {}
    for i = 1, N_FEATURES do
        v[i] = feat[FEATURE_NAMES[i]] or 0.0
    end
    return v
end

-- ============================================================================
--  MODEL LOAD + k-NN
-- ============================================================================
local function load_model(path)
    local chunk, err = loadfile(path)
    if not chunk then fail("Cannot load model: " .. path .. " " .. tostring(err)) end
    local model = chunk()
    if type(model) ~= "table" then fail("Model not a table: " .. path) end
    if type(model.samples) ~= "table" then fail("Model has no samples: " .. path) end
    if type(model.normalization) ~= "table" then fail("Model has no normalization: " .. path) end
    return model
end

local function normalize_vec(model, vec)
    local out = {}
    for i = 1, N_FEATURES do
        local m = model.normalization.mean[i] or 0.0
        local s = model.normalization.std[i] or 1.0
        if math.abs(s) < EPSILON then s = 1.0 end
        out[i] = (vec[i] - m) / s
    end
    return out
end

local function euclid(a, b)
    local s = 0.0
    for i = 1, N_FEATURES do
        local d = a[i] - b[i]
        s = s + d * d
    end
    return math.sqrt(s)
end

local function classify(model, feat)
    local raw = features_to_vector(feat)
    local nv = normalize_vec(model, raw)
    local nbs = {}
    for i = 1, #model.samples do
        local sv = normalize_vec(model, model.samples[i].vec)
        nbs[#nbs + 1] = {
            dist = euclid(nv, sv),
            label = model.samples[i].label,
            filename = model.samples[i].filename or "?",
        }
    end
    if #nbs == 0 then fail("Model has no samples") end
    table.sort(nbs, function(a, b) return a.dist < b.dist end)

    local k = math.min(model.k or DEFAULT_K, #nbs)
    local scores = {}
    local tw, sd = 0.0, 0.0
    for i = 1, k do
        local w = 1.0 / (nbs[i].dist + EPSILON)
        scores[nbs[i].label] = (scores[nbs[i].label] or 0.0) + w
        tw = tw + w
        sd = sd + nbs[i].dist
    end

    local best_label, best_score = nil, -math.huge
    for lbl, sc in pairs(scores) do
        if sc > best_score then best_label, best_score = lbl, sc end
    end
    local conf = tw > 0 and (best_score / tw) * 100.0 or 0.0

    local cds, cc = {}, {}
    for _, nb in ipairs(nbs) do
        cds[nb.label] = (cds[nb.label] or 0.0) + nb.dist
        cc[nb.label] = (cc[nb.label] or 0) + 1
    end
    local class_dist = {}
    for lbl, s in pairs(cds) do class_dist[lbl] = s / cc[lbl] end

    local avg = sd / k
    local thresh = model.anomaly_threshold or math.huge
    if model.info and model.info.anomaly_threshold then
        thresh = model.info.anomaly_threshold
    end

    local topk = {}
    for i = 1, k do topk[i] = nbs[i] end

    return {
        label = best_label,
        confidence = conf,
        neighbours = topk,
        k = k,
        class_distances = class_dist,
        avg_dist = avg,
        threshold = thresh,
        anomaly = avg > thresh,
        raw_vector = raw,
    }
end

-- ============================================================================
--  DYNAMIC PROFILING
-- ============================================================================
local NET_SC = {
    socket=1, connect=1, accept=1, accept4=1, bind=1, listen=1,
    sendto=1, recvfrom=1, sendmsg=1, recvmsg=1, shutdown=1,
    getpeername=1, getsockname=1, setsockopt=1, getsockopt=1,
}
local FILE_SC = {
    open=1, openat=1, openat2=1, creat=1, read=1, pread64=1,
    write=1, pwrite64=1, close=1, stat=1, fstat=1, lstat=1,
    newfstatat=1, access=1, faccessat=1, readlink=1, unlink=1,
    unlinkat=1, rename=1, renameat=1, getdents=1, getdents64=1,
}
local PROC_SC = {
    execve=1, execveat=1, fork=1, vfork=1, clone=1, clone3=1,
    wait4=1, waitid=1,
}

local function parse_trace(path)
    local f = io.open(path, "r")
    if not f then return nil, "no trace" end
    local counts, total = {}, 0
    for line in f:lines() do
        local sc = line:match("^%s*%d+%s+([%a_][%w_]*)%(")
            or line:match("^%s*([%a_][%w_]*)%(")
        if sc then
            counts[sc] = (counts[sc] or 0) + 1
            total = total + 1
        end
    end
    f:close()
    return { counts = counts, total = total }
end

local function sc_entropy(counts, total)
    if total <= 0 then return 0.0 end
    local e = 0.0
    for _, n in pairs(counts) do
        local p = n / total
        e = e - p * (math.log(p) / LOG2)
    end
    return e
end

local function profile_target(target, targs)
    local trace = os.tmpname() .. ".moabi"
    local parts = {
        "timeout", "3s", "strace", "-f", "-qq",
        "-o", shq(trace), "--", shq(target),
    }
    for _, a in ipairs(targs) do parts[#parts + 1] = shq(a) end
    os.execute(table.concat(parts, " ") .. " >/dev/null 2>&1")

    local parsed, err = parse_trace(trace)
    os.remove(trace)
    if not parsed then return nil, err end

    local net, fil, prc, uniq = 0, 0, 0, 0
    for sc, n in pairs(parsed.counts) do
        uniq = uniq + 1
        if NET_SC[sc] then net = net + n end
        if FILE_SC[sc] then fil = fil + n end
        if PROC_SC[sc] then prc = prc + n end
    end
    local tot = parsed.total
    local function r(v) return tot > 0 and v / tot or 0.0 end

    return {
        counts = parsed.counts,
        total = tot,
        unique = uniq,
        entropy = sc_entropy(parsed.counts, tot),
        net_count = net,
        file_count = fil,
        proc_count = prc,
        exec_count = parsed.counts.execve or 0,
        net_ratio = r(net),
        file_ratio = r(fil),
        proc_ratio = r(prc),
    }
end

-- ============================================================================
--  RUNTIME VERIFICATION (execve tuning)
-- ============================================================================
local function verify(label, dyn)
    local alerts = {}

    -- execve tuning: single execve is normal (process launch).
    -- Alert only on multiple or suspiciously early single call.
    if dyn.exec_count > 1 then
        alerts[#alerts + 1] = "target invoked execve " .. dyn.exec_count .. " times"
    elseif dyn.exec_count == 1 and dyn.total < 10 then
        alerts[#alerts + 1] = "execve with only " .. dyn.total .. " total syscalls (suspicious)"
    end

    if label == "system_utility" and dyn.net_ratio > 0.25 then
        alerts[#alerts + 1] = "system_utility performed significant network I/O"
    end
    if label == "network_tool" and dyn.net_count == 0 then
        alerts[#alerts + 1] = "network_tool made zero network syscalls"
    end
    if dyn.entropy > 4.5 then
        alerts[#alerts + 1] = "high syscall entropy (" .. string.format("%.2f", dyn.entropy) .. ")"
    end

    return { status = #alerts > 0 and "ALERT" or "OK", alerts = alerts }
end

-- ============================================================================
--  OUTPUT
-- ============================================================================
local function sorted_dists(d)
    local t = {}
    for k, v in pairs(d) do t[#t + 1] = { label = k, dist = v } end
    table.sort(t, function(a, b) return a.dist < b.dist end)
    return t
end

local function print_header(model_path, target, profile)
    print("========================================================")
    print("  MOABI GATEKEEPER: PRE-EXECUTION ML TRIAGE")
    print("========================================================")
    print()
    print("  Model:       " .. model_path)
    print("  Target:      " .. target)
    print("  Policy:      " .. profile.color .. profile.name .. RESET)
    print("  Description: " .. profile.desc)
end

local function print_static(target, res, source)
    print()
    print("--------------------------------------------------------")
    print("  STATIC ML RESULT")
    print("--------------------------------------------------------")
    print("  Target:      " .. target)
    print("  Classified:  " .. tostring(res.label))
    print(string.format("  Confidence:  %.1f%%", res.confidence))

    -- Leakage warning (result is a local parameter here)
    if res.neighbours and res.neighbours[1]
       and res.neighbours[1].dist <= EPSILON then
        print("  Validation:  EXACT TRAINING MATCH (d=0)")
        print("               Identity, not held-out inference.")
    end

    print("  Static flag: " .. (res.anomaly and "ANOMALY" or "CLEAN PROFILE"))
    print("  Feature src: " .. tostring(source))

    print()
    print("  Nearest neighbors (k=" .. res.k .. "):")
    for i = 1, res.k do
        local nb = res.neighbours[i]
        print(string.format("    %d. [%-18s] d=%.4f  %s",
            i, nb.label, nb.dist, nb.filename))
    end

    print()
    print("  Class distances (mean):")
    for _, item in ipairs(sorted_dists(res.class_distances)) do
        local mk = item.label == res.label and " <--" or ""
        print(string.format("    %-20s %.4f%s", item.label, item.dist, mk))
    end

    print()
    print(string.format("  Avg neighbour dist: %.4f", res.avg_dist))
    print(string.format("  Anomaly threshold:  %.4f", res.threshold))
end

local function print_dynamic(dyn, ver)
    print()
    print("--------------------------------------------------------")
    print("  DYNAMIC SYSCALL PROFILE")
    print("--------------------------------------------------------")
    if not dyn then
        print("  Status: unavailable")
        return
    end
    print(string.format("  Syscalls:        %d total, %d unique", dyn.total, dyn.unique))
    print(string.format("  Syscall entropy: %.4f", dyn.entropy))
    print(string.format("  Network:         %d (%.2f%%)", dyn.net_count, dyn.net_ratio * 100))
    print(string.format("  File I/O:        %d (%.2f%%)", dyn.file_count, dyn.file_ratio * 100))
    print(string.format("  Process:         %d (%.2f%%)", dyn.proc_count, dyn.proc_ratio * 100))
    print(string.format("  execve() calls:  %d", dyn.exec_count))
    print()
    print("  Runtime verification: " .. ver.status)
    if #ver.alerts > 0 then
        for _, a in ipairs(ver.alerts) do
            print("    ALERT: " .. a)
        end
    else
        print("    No runtime anomalies detected.")
    end
end

-- ============================================================================
--  MAIN
-- ============================================================================
local function usage()
    print("MOABI-DYNAMIC2 v1.3 — CRA Runtime Gatekeeper")
    print()
    print("Usage:")
    print("  luajit moabi-dynamic2.lua MODEL TARGET [ARGS...]")
    print("  luajit moabi-dynamic2.lua MODEL TARGET --static-only")
    print()
    print("Examples:")
    print("  luajit moabi-dynamic2.lua /mnt/d/moabi/reports/system.model /usr/bin/ls /tmp")
    print("  luajit moabi-dynamic2.lua /mnt/d/moabi/reports/system.model /usr/bin/ping -c 1 127.0.0.1")
end

local function main()
    local model_path = arg[1]
    local target_path = arg[2]

    if not model_path or not target_path then
        usage()
        return 1
    end

    if model_path == "-h" or model_path == "--help" then
        usage()
        return 0
    end

    local targs = {}
    local static_only = false
    for i = 3, #arg do
        if i == 3 and arg[i] == "--static-only" then
            static_only = true
        else
            targs[#targs + 1] = arg[i]
        end
    end

    if not file_exists(model_path) then
        fail("Model not found: " .. model_path)
    end
    if not file_exists(target_path) then
        fail("Target not found: " .. target_path)
    end

    -- Load model
    local model = load_model(model_path)

    -- Extract features
    local feat, source = extract_features(target_path)
    if not feat then
        fail("Feature extraction failed for " .. target_path)
    end

    -- Classify
    local res = classify(model, feat)

    -- Policy tier
    local profile = PROFILES.ANOMALY
    if not res.anomaly and res.confidence >= 80.0 then
        profile = PROFILES.TRUSTED
    elseif not res.anomaly and res.confidence >= 40.0 then
        profile = PROFILES.UNCERTAIN
    end

    -- Print static
    print_header(model_path, target_path, profile)
    print_static(target_path, res, source)

    -- Dynamic
    if static_only then
        print()
        print("  Dynamic execution: skipped (--static-only)")
        print()
        print("========================================================")
        print("  GATEKEEPER COMPLETE (static only)")
        print("========================================================")
        print()
        return 0
    end

    if not is_executable(target_path) then
        print()
        print("--------------------------------------------------------")
        print("  DYNAMIC EXECUTION: SKIPPED (not executable)")
        print("--------------------------------------------------------")
        print()
        print("========================================================")
        print("  GATEKEEPER COMPLETE")
        print("========================================================")
        print()
        return 0
    end

    print()
    print("--------------------------------------------------------")
    print("  DYNAMIC EXECUTION")
    print("--------------------------------------------------------")
    print("  Running target under 3s strace timeout.")
    print()

    local dyn, derr = profile_target(target_path, targs)
    if not dyn then
        print("  Dynamic error: " .. tostring(derr))
        print("  Ensure strace and timeout are installed.")
        print()
        print("========================================================")
        print("  GATEKEEPER COMPLETE (dynamic unavailable)")
        print("========================================================")
        print()
        return 2
    end

    local ver = verify(res.label, dyn)
    print_dynamic(dyn, ver)

    print()
    print("========================================================")
    print("  GATEKEEPER COMPLETE")
    print("========================================================")
    print()
    return 0
end

local ok, ret = pcall(main)
if not ok then
    io.stderr:write("\nERROR: " .. tostring(ret) .. "\n")
    os.exit(1)
end
os.exit(ret or 0)
