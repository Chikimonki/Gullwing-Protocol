#!/usr/bin/env luajit
--============================================================================
--  MOABI-DELTA v1.0 — Binary Supply Chain Differential Comparator
--============================================================================

local json = require("json")

local function load_evidence(path)
    local f = io.open(path, "r")
    if not f then return nil, "Cannot open: " .. path end
    local content = f:read("*a")
    f:close()
    local ok, data = pcall(json.decode, content)
    if not ok then return nil, "Invalid JSON: " .. tostring(data) end
    return data
end

-- ============================================================================
--  CHANGE DETECTION RULES
-- ============================================================================

local RULES = {
    { path = "structure.section_count",    label = "Section count changed",           weight = 1.0 },
    { path = "structure.import_count",     label = "Import count changed",            weight = 1.5 },
    { path = "structure.export_count",     label = "Export count changed",            weight = 1.0 },
    { path = "structure.is_elf",           label = "ELF status changed",              weight = 3.0 },
    { path = "structure.elf_type",         label = "ELF type changed",                weight = 2.0 },
    { path = "structure.has_debug",        label = "Debug info toggled",              weight = 0.5 },
    { path = "semantics.libraries.libssl",    label = "libssl dependency toggled",    weight = 3.0 },
    { path = "semantics.libraries.libcrypto", label = "libcrypto dependency toggled", weight = 3.0 },
    { path = "semantics.libraries.libcurl",   label = "libcurl dependency toggled",   weight = 2.5 },
    { path = "semantics.libraries.libz",      label = "libz dependency toggled",      weight = 1.5 },
    { path = "semantics.libraries.lzma",      label = "lzma dependency toggled",      weight = 1.5 },
    { path = "semantics.libraries.ncurses",   label = "ncurses dependency toggled",   weight = 1.0 },
    { path = "semantics.libraries.readline",  label = "readline dependency toggled",  weight = 1.0 },
    { path = "semantics.libraries.python",    label = "Python dependency toggled",    weight = 2.5 },
    { path = "semantics.libraries.perl",      label = "Perl dependency toggled",      weight = 2.0 },
    { path = "semantics.libraries.ruby",      label = "Ruby dependency toggled",      weight = 2.0 },
    { path = "semantics.symbols.has_py_eval",   label = "CPython symbols toggled",   weight = 2.0 },
    { path = "semantics.symbols.has_curl_easy", label = "libcurl symbols toggled",   weight = 2.0 },
    { path = "semantics.symbols.has_ssl_ctx",   label = "OpenSSL symbols toggled",   weight = 2.5 },
    { path = "entropy_profile.global",        label = "Global entropy shift",         weight = 1.5, threshold = 0.5 },
    { path = "entropy_profile.byte_mean",     label = "Byte mean shift",              weight = 0.5, threshold = 10 },
    { path = "entropy_profile.byte_stddev",   label = "Byte stddev shift",            weight = 0.5, threshold = 10 },
    { path = "runtime.total",      label = "Syscall count changed",       weight = 1.5 },
    { path = "runtime.unique",     label = "Syscall diversity changed",   weight = 1.0 },
    { path = "runtime.net_count",  label = "Network activity changed",    weight = 2.5 },
    { path = "runtime.file_count", label = "File I/O changed",            weight = 1.0 },
    { path = "runtime.exec_count", label = "Process creation changed",    weight = 3.0 },
    { path = "runtime.entropy",    label = "Syscall entropy shift",       weight = 1.0, threshold = 0.5 },
    { path = "memory.regions_total",     label = "Memory regions changed",        weight = 1.0 },
    { path = "memory.exec_regions",      label = "Executable regions changed",    weight = 2.0 },
    { path = "memory.rwx_regions",       label = "RWX regions appeared",          weight = 4.0 },
    { path = "memory.anon_exec_regions", label = "Anonymous exec regions appeared", weight = 4.0 },
    { path = "memory.max_exec_entropy",  label = "Max exec entropy shift",        weight = 1.5, threshold = 1.0 },
    { path = "memory.entropy_delta",     label = "Memory entropy delta shift",    weight = 2.0, threshold = 0.5 },
    { path = "ml.class",      label = "ML classification changed",  weight = 3.0 },
    { path = "ml.anomaly",    label = "ML anomaly status changed",   weight = 2.0 },
    { path = "ml.confidence", label = "ML confidence shift",         weight = 1.0, threshold = 10 },
    { path = "ml.avg_dist",   label = "ML distance shift",           weight = 1.5, threshold = 2.0 },
    { path = "ml.threshold",  label = "ML anomaly threshold changed", weight = 1.0 },
}

-- ============================================================================
--  UTILITIES
-- ============================================================================

local function deep_get(t, path)
    local cur = t
    for k in path:gmatch("[^%.]+") do
        if type(cur) ~= "table" then return nil end
        cur = cur[k]
    end
    return cur
end

local function fmt_val(v)
    if type(v) == "number" then
        if v == math.floor(v) then return tostring(math.floor(v))
        else return string.format("%.4f", v) end
    elseif type(v) == "boolean" then return v and "true" or "false"
    elseif type(v) == "string" then return v
    elseif v == nil then return "nil"
    end
    return tostring(v)
end

local function fmt_diff(old, new)
    return string.format("%s → %s", fmt_val(old), fmt_val(new))
end

-- ============================================================================
--  DELTA ENGINE
-- ============================================================================

local function delta(old_path, new_path)
    local old_data = load_evidence(old_path)
    if type(old_data) ~= "table" then return nil, "Cannot load: " .. old_path end
    local new_data = load_evidence(new_path)
    if type(new_data) ~= "table" then return nil, "Cannot load: " .. new_path end

    local old_id = old_data.identity or {}
    local new_id = new_data.identity or {}
    local same_binary = (old_id.sha256 == new_id.sha256)

    local changes = {}
    local total_weight = 0
    local critical_signals = {}

    for _, rule in ipairs(RULES) do
        local old_val = deep_get(old_data, rule.path)
        local new_val = deep_get(new_data, rule.path)
        if old_val == nil and new_val == nil then goto continue end

        local changed = false
        local detail = ""
        if rule.threshold then
            local a = tonumber(old_val) or 0
            local b = tonumber(new_val) or 0
            if math.abs(b - a) >= rule.threshold then
                changed = true
                detail = fmt_diff(a, b) .. string.format(" (Δ=%.4f)", b - a)
            end
        else
            if old_val ~= new_val then
                changed = true
                detail = fmt_diff(old_val, new_val)
            end
        end

        if changed then
            local signal = { path = rule.path, label = rule.label, detail = detail, weight = rule.weight }
            changes[#changes + 1] = signal
            total_weight = total_weight + rule.weight
            if rule.weight >= 3.0 then critical_signals[#critical_signals + 1] = signal end
        end
        ::continue::
    end

    local verdict = "NO CHANGE"
    if total_weight > 0 then
        if #critical_signals > 0 then verdict = "SUPPLY CHAIN CHANGE — CRITICAL"
        elseif total_weight >= 5.0 then verdict = "SUPPLY CHAIN CHANGE — NOTABLE"
        else verdict = "SUPPLY CHAIN CHANGE — MINOR" end
    end

    return {
        old_path = old_path, new_path = new_path,
        old_sha256 = old_id.sha256, new_sha256 = new_id.sha256,
        old_name = old_id.path, new_name = new_id.path,
        same_binary = same_binary, changes = changes,
        change_count = #changes, total_weight = total_weight,
        critical_count = #critical_signals, critical_signals = critical_signals,
        verdict = verdict,
    }
end

-- ============================================================================
--  REPORT
-- ============================================================================

local function print_report(d)
    local line = string.rep("=", 64)
    local thin = string.rep("-", 64)
    print(line)
    print("  MOABI-DELTA — Supply Chain Differential Report")
    print(line)
    print()
    print("  Old: " .. (d.old_name or "?") .. "  (" .. (d.old_sha256 or "?") .. ")")
    print("  New: " .. (d.new_name or "?") .. "  (" .. (d.new_sha256 or "?") .. ")")
    print()
    if d.same_binary then
        print("  Status: IDENTICAL — no changes detected")
    elseif d.change_count == 0 then
        print("  Status: Hash changed but no structural/behavioral differences")
    else
        print("  Status: " .. d.change_count .. " change(s) detected")
        print()
        local groups = {}
        for _, ch in ipairs(d.changes) do
            local cat = ch.path:match("^([^%.]+)") or "other"
            if not groups[cat] then groups[cat] = {} end
            groups[cat][#groups[cat] + 1] = ch
        end
        for cat, items in pairs(groups) do
            print("  [" .. cat:upper() .. "]")
            for _, ch in ipairs(items) do
                local marker = (ch.weight >= 3.0) and " ⚠" or ""
                print(string.format("    %s: %s (weight %.1f)%s", ch.label, ch.detail, ch.weight, marker))
            end
            print()
        end
        print(thin)
        print("  [VERDICT]  " .. d.verdict)
        print(string.format("  Weight: %.1f  |  Changes: %d  |  Critical: %d",
            d.total_weight, d.change_count, d.critical_count))
        print()
    end
    print(line)
end

-- ============================================================================
--  MAIN
-- ============================================================================

local function main()
    if not arg[1] or not arg[2] or arg[1] == "-h" or arg[1] == "--help" then
        print("MOABI-DELTA v1.0 — Binary Supply Chain Differential Comparator")
        print("Usage: luajit moabi-delta.lua OLD.json NEW.json")
        return 0
    end
    local d, err = delta(arg[1], arg[2])
    if not d then io.stderr:write("ERROR: " .. tostring(err) .. "\n"); return 1 end
    print_report(d)
    return d.change_count > 0 and 1 or 0
end

local ok, ret = pcall(main)
if not ok then io.stderr:write("\nERROR: " .. tostring(ret) .. "\n"); os.exit(1) end
os.exit(ret or 0)
