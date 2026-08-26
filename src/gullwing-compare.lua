#!/usr/bin/env luajit
--============================================================================
--  GULLWING-COMPARE v1.0 — Cross-Vendor Binary Equivalence
--  Answers: do these two binaries do the same thing?
--============================================================================

local json = require("json")
local DELTA = "/mnt/d/moabi/src/moabi-delta.lua"

-- ============================================================================
--  EQUIVALENCE SCORING WEIGHTS
--  Behavioral similarity counts more than structural identity.
-- ============================================================================

local WEIGHTS = {
    -- Structural (lower weight — compilers differ)
    section_count_match      = 0.5,
    elf_type_match           = 1.0,
    is_elf_match             = 1.0,
    import_count_close       = 0.5,  -- within 20%
    export_count_close       = 0.5,

    -- Semantic (high weight — libraries reveal intent)
    library_intersection     = 3.0,  -- shared libraries
    library_symmetry         = 2.0,  -- both have same count
    symbol_families_match    = 2.0,

    -- Behavioral (highest weight — runtime tells truth)
    syscall_profile_similar  = 4.0,  -- same syscall distribution
    network_behavior_match   = 3.0,
    file_io_behavior_match   = 2.0,
    process_behavior_match   = 3.0,

    -- ML (moderate weight — statistical similarity)
    class_match              = 2.0,
    confidence_both_high     = 1.0,
    anomaly_agreement        = 1.0,

    -- Entropy (low weight — compiler artifacts)
    entropy_close            = 0.5,  -- within 0.5
}

-- ============================================================================
--  HELPERS
-- ============================================================================

local function load_evidence(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    local ok, data = pcall(json.decode, content)
    if not ok then return nil end
    return data
end

local function percent_close(a, b, threshold)
    if a == 0 and b == 0 then return true end
    if a == 0 or b == 0 then return false end
    local ratio = math.max(a, b) / math.min(a, b)
    return ratio <= (1 + threshold)
end

local function approx_equal(a, b, tolerance)
    return math.abs((a or 0) - (b or 0)) <= (tolerance or 0.5)
end

-- ============================================================================
--  COMPARISON ENGINE
-- ============================================================================

local function compare(path_a, path_b)
    local a = load_evidence(path_a)
    local b = load_evidence(path_b)
    if not a then return nil, "Cannot load: " .. path_a end
    if not b then return nil, "Cannot load: " .. path_b end

    local score = 0
    local max_score = 0
    local matches = {}
    local mismatches = {}

    local function add(category, label, weight, is_match, detail)
        max_score = max_score + weight
        if is_match then
            score = score + weight
            matches[#matches + 1] = { category = category, label = label, detail = detail, weight = weight }
        else
            mismatches[#mismatches + 1] = { category = category, label = label, detail = detail, weight = weight }
        end
    end

    -- === STRUCTURE ===
    local st_a = a.structure or {}
    local st_b = b.structure or {}

    add("STRUCTURE", "ELF status", WEIGHTS.is_elf_match,
        st_a.is_elf == st_b.is_elf,
        (st_a.is_elf and "ELF" or "non-ELF") .. " vs " .. (st_b.is_elf and "ELF" or "non-ELF"))

    add("STRUCTURE", "ELF type", WEIGHTS.elf_type_match,
        st_a.elf_type == st_b.elf_type,
        (st_a.elf_type or "?") .. " vs " .. (st_b.elf_type or "?"))

    add("STRUCTURE", "Section count close", WEIGHTS.section_count_match,
        percent_close(st_a.section_count or 0, st_b.section_count or 0, 0.3),
        (st_a.section_count or 0) .. " vs " .. (st_b.section_count or 0))

    add("STRUCTURE", "Import count close", WEIGHTS.import_count_close,
        percent_close(st_a.import_count or 0, st_b.import_count or 0, 0.2),
        (st_a.import_count or 0) .. " vs " .. (st_b.import_count or 0))

    add("STRUCTURE", "Export count close", WEIGHTS.export_count_close,
        percent_close(st_a.export_count or 0, st_b.export_count or 0, 0.5),
        (st_a.export_count or 0) .. " vs " .. (st_b.export_count or 0))

    -- === SEMANTICS ===
    local lib_a = (a.semantics and a.semantics.libraries) or {}
    local lib_b = (b.semantics and b.semantics.libraries) or {}

    local shared_libs = 0
    local total_libs_a = 0
    local total_libs_b = 0
    for k, v in pairs(lib_a) do if v then total_libs_a = total_libs_a + 1 end end
    for k, v in pairs(lib_b) do if v then total_libs_b = total_libs_b + 1 end end
    for k, v in pairs(lib_a) do
        if v and lib_b[k] then shared_libs = shared_libs + 1 end
    end

    local lib_intersection = (total_libs_a > 0 or total_libs_b > 0) and
        (shared_libs / math.max(total_libs_a, total_libs_b)) or 1.0

    add("SEMANTICS", "Library intersection", WEIGHTS.library_intersection,
        lib_intersection >= 0.7,
        string.format("%d/%d shared (%.0f%%)", shared_libs, math.max(total_libs_a, total_libs_b), lib_intersection * 100))

    add("SEMANTICS", "Library count symmetry", WEIGHTS.library_symmetry,
        percent_close(total_libs_a, total_libs_b, 0.5),
        total_libs_a .. " vs " .. total_libs_b)

    local sym_a = (a.semantics and a.semantics.symbols) or {}
    local sym_b = (b.semantics and b.semantics.symbols) or {}
    local sym_match = (sym_a.has_py_eval == sym_b.has_py_eval) and
                      (sym_a.has_curl_easy == sym_b.has_curl_easy) and
                      (sym_a.has_ssl_ctx == sym_b.has_ssl_ctx)
    add("SEMANTICS", "Symbol families match", WEIGHTS.symbol_families_match, sym_match,
        "Python: " .. tostring(sym_a.has_py_eval) .. "/" .. tostring(sym_b.has_py_eval) ..
        " curl: " .. tostring(sym_a.has_curl_easy) .. "/" .. tostring(sym_b.has_curl_easy))

    -- === BEHAVIORAL (RUNTIME) ===
    local rt_a = a.runtime or {}
    local rt_b = b.runtime or {}

    local both_attempted = (rt_a.attempted and rt_b.attempted)
    if both_attempted then
        add("RUNTIME", "Syscall profile similar", WEIGHTS.syscall_profile_similar,
            percent_close(rt_a.total or 0, rt_b.total or 0, 0.3) and
            percent_close(rt_a.unique or 0, rt_b.unique or 0, 0.3),
            string.format("total: %d vs %d, unique: %d vs %d",
                rt_a.total or 0, rt_b.total or 0, rt_a.unique or 0, rt_b.unique or 0))

        local net_a = (rt_a.net_count or 0) > 0
        local net_b = (rt_b.net_count or 0) > 0
        add("RUNTIME", "Network behavior match", WEIGHTS.network_behavior_match,
            net_a == net_b,
            net_a and "network active" or "no network" .. " vs " .. (net_b and "network active" or "no network"))

        add("RUNTIME", "File I/O behavior match", WEIGHTS.file_io_behavior_match,
            percent_close(rt_a.file_count or 0, rt_b.file_count or 0, 0.4),
            (rt_a.file_count or 0) .. " vs " .. (rt_b.file_count or 0))

        add("RUNTIME", "Process behavior match", WEIGHTS.process_behavior_match,
            (rt_a.exec_count or 0) == (rt_b.exec_count or 0),
            (rt_a.exec_count or 0) .. " vs " .. (rt_b.exec_count or 0))
    end

    -- === ML ===
    local ml_a = a.ml or {}
    local ml_b = b.ml or {}

    add("ML", "Class match", WEIGHTS.class_match,
        ml_a.class == ml_b.class,
        (ml_a.class or "?") .. " vs " .. (ml_b.class or "?"))

    add("ML", "Both high confidence", WEIGHTS.confidence_both_high,
        (ml_a.confidence or 0) > 90 and (ml_b.confidence or 0) > 90,
        string.format("%.1f%% vs %.1f%%", ml_a.confidence or 0, ml_b.confidence or 0))

    add("ML", "Anomaly agreement", WEIGHTS.anomaly_agreement,
        (ml_a.anomaly == ml_b.anomaly),
        (ml_a.anomaly and "anomalous" or "normal") .. " vs " .. (ml_b.anomaly and "anomalous" or "normal"))

    -- === ENTROPY ===
    local ep_a = a.entropy_profile or {}
    local ep_b = b.entropy_profile or {}
    add("ENTROPY", "Global entropy close", WEIGHTS.entropy_close,
        approx_equal(ep_a.global, ep_b.global, 0.5),
        string.format("%.4f vs %.4f", ep_a.global or 0, ep_b.global or 0))

    -- === VERDICT ===
    local pct = max_score > 0 and (score / max_score) * 100 or 0
    local verdict
    if pct >= 85 then verdict = "FUNCTIONALLY EQUIVALENT — high confidence"
    elseif pct >= 65 then verdict = "LIKELY EQUIVALENT — minor differences"
    elseif pct >= 45 then verdict = "PARTIALLY EQUIVALENT — significant differences"
    else verdict = "NOT EQUIVALENT — different behavior detected"
    end

    return {
        path_a = path_a, path_b = path_b,
        name_a = (a.identity or {}).path or path_a,
        name_b = (b.identity or {}).path or path_b,
        sha_a = (a.identity or {}).sha256 or "?",
        sha_b = (b.identity or {}).sha256 or "?",
        matches = matches, mismatches = mismatches,
        score = score, max_score = max_score,
        percentage = pct, verdict = verdict,
        runtime_available = both_attempted,
    }
end

-- ============================================================================
--  REPORT
-- ============================================================================

local function print_report(r)
    local line = string.rep("=", 64)
    local thin = string.rep("-", 64)

    print(line)
    print("  GULLWING-COMPARE — Cross-Vendor Binary Equivalence")
    print(line)
    print()
    print("  Binary A: " .. (r.name_a or "?") .. "  (" .. (r.sha_a or "?") .. ")")
    print("  Binary B: " .. (r.name_b or "?") .. "  (" .. (r.sha_b or "?") .. ")")
    print()

    print("  [MATCHES] " .. #r.matches .. " signals")
    local by_cat = {}
    for _, m in ipairs(r.matches) do
        local cat = m.category
        if not by_cat[cat] then by_cat[cat] = {} end
        by_cat[cat][#by_cat[cat] + 1] = m
    end
    for cat, items in pairs(by_cat) do
        print("    [" .. cat .. "]")
        for _, m in ipairs(items) do
            print(string.format("      ✓ %s: %s (weight %.1f)", m.label, m.detail, m.weight))
        end
    end
    print()

    if #r.mismatches > 0 then
        print("  [MISMATCHES] " .. #r.mismatches .. " signals")
        local by_cat_m = {}
        for _, m in ipairs(r.mismatches) do
            local cat = m.category
            if not by_cat_m[cat] then by_cat_m[cat] = {} end
            by_cat_m[cat][#by_cat_m[cat] + 1] = m
        end
        for cat, items in pairs(by_cat_m) do
            print("    [" .. cat .. "]")
            for _, m in ipairs(items) do
                print(string.format("      ✗ %s: %s (weight %.1f)", m.label, m.detail, m.weight))
            end
        end
        print()
    end

    if not r.runtime_available then
        print("  ⚠ Runtime data unavailable — behavioral comparison limited")
        print()
    end

    print(thin)
    print(string.format("  Score: %.1f / %.1f  (%.0f%%)", r.score, r.max_score, r.percentage))
    print("  Verdict: " .. r.verdict)
    print()
    print(line)
end

-- ============================================================================
--  MAIN
-- ============================================================================

local function usage()
    print("GULLWING-COMPARE v1.0 — Cross-Vendor Binary Equivalence")
    print("Usage: luajit gullwing-compare.lua EVIDENCE_A.json EVIDENCE_B.json")
end

local function main()
    if not arg[1] or not arg[2] or arg[1] == "-h" then usage(); return 0 end
    local r, err = compare(arg[1], arg[2])
    if not r then io.stderr:write("ERROR: " .. tostring(err) .. "\n"); return 1 end
    print_report(r)
    return 0
end

main()
