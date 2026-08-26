#!/usr/bin/env luajit
--============================================================================
--  MOABI-SBOM v1.0 — Software Bill of Materials Generator
--  Generates JSONL audit trail from direct evidence analysis.
--  No subprocess overhead. No broken paths.
--============================================================================

package.path = "/mnt/d/moabi/src/?.lua;" .. package.path

local ev = require("moabi-evidence")
local MF = require("moabi-features")

local MODEL_PATH = "/mnt/d/moabi/reports/system.model"
local EPSILON = 1e-10

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function file_exists(p) local f=io.open(p,"rb"); if f then f:close(); return true end; return false end
local function is_exec(p)
    local h = io.popen("test -x " .. shq(p) .. " && echo 1")
    if not h then return false end
    local r = h:read("*l"); h:close()
    return r == "1"
end
local function sha256(p)
    local h = io.popen("sha256sum " .. shq(p) .. " 2>/dev/null")
    if not h then return nil end
    local line = h:read("*l"); h:close()
    if line then return line:match("^(%x+)") end
    return nil
end

-- Inline classification using the trained model
local function classify(vec, model)
    local n = MF.N
    local mean = model.normalization.mean
    local std = model.normalization.std
    
    local nv = {}
    for i = 1, n do
        local m = mean[i] or 0
        local s = std[i] or 1
        if math.abs(s) < EPSILON then s = 1 end
        nv[i] = (vec[i] - m) / s
    end
    
    local nbs = {}
    for _, s in ipairs(model.samples) do
        local sv = {}
        for i = 1, n do
            local m = mean[i] or 0
            local s2 = std[i] or 1
            if math.abs(s2) < EPSILON then s2 = 1 end
            sv[i] = (s.vec[i] - m) / s2
        end
        local d = 0
        for i = 1, n do d = d + (nv[i] - sv[i])^2 end
        nbs[#nbs+1] = { dist = math.sqrt(d), label = s.label }
    end
    table.sort(nbs, function(a,b) return a.dist < b.dist end)
    
    local k = math.min(model.k or 5, #nbs)
    local scores, tw, sd = {}, 0, 0
    local cc = model.class_counts or (model.info and model.info.class_counts) or {}
    for i = 1, k do
        local label = nbs[i].label
        local sz = cc[label] or 1
        local w = (1 / (nbs[i].dist + EPSILON)) / sz
        scores[label] = (scores[label] or 0) + w
        tw = tw + w; sd = sd + nbs[i].dist
    end
    local best, bs = "unknown", -1
    for l, s in pairs(scores) do if s > bs then best, bs = l, s end end
    
    local avg = sd / k
    local thr = model.anomaly_threshold or (model.info and model.info.anomaly_threshold) or 7.5
    return {
        class = best,
        confidence = tw > 0 and (bs/tw)*100 or 0,
        anomaly = avg > thr,
        avg_dist = avg,
        threshold = thr,
    }
end

local function analyze(path, model)
    local e = ev.new(path)
    local r = MF.extract(path)
    if not r then return nil end
    
    local id = { path = path, size = r.size, sha256 = sha256(path), executable = is_exec(path) }
    local st = { is_elf = r.feat.is_elf == 1.0 }
    if st.is_elf then
        st.elf_class = (r.feat.elf_class_num == 2) and "ELF64" or "ELF32"
        st.section_count = r.feat.section_count
        st.import_count = r.feat.import_count
        st.export_count = r.feat.export_count
    end
    local sem = { libraries = {} }
    if r.feat.has_libssl == 1 then sem.libraries.libssl = true end
    if r.feat.has_libcrypto == 1 then sem.libraries.libcrypto = true end
    if r.feat.has_libcurl == 1 then sem.libraries.libcurl = true end
    if r.feat.has_libz == 1 then sem.libraries.libz = true end
    if r.feat.has_lzma == 1 then sem.libraries.lzma = true end
    if r.feat.has_ncurses == 1 then sem.libraries.ncurses = true end
    if r.feat.has_readline == 1 then sem.libraries.readline = true end
    if r.feat.has_libpython == 1 then sem.libraries.python = true end
    if r.feat.has_libperl == 1 then sem.libraries.perl = true end
    if r.feat.has_libruby == 1 then sem.libraries.ruby = true end
    
    ev.set_identity(e, id, "moabi-sbom", 0)
    ev.set_structure(e, st, "moabi-features", 0)
    ev.set_semantics(e, sem, "moabi-features", 0)
    
    if model then
        local ml = classify(r.vec, model)
        ev.set_ml(e, ml, "moabi-ml", 0)
    end
    
    ev.converge(e)
    return e
end

local function record(e)
    local c = e.convergence or {}
    local id = e.identity or {}
    local st = e.structure or {}
    local sem = e.semantics or {}
    local ml = e.ml or {}
    local libs = {}
    if sem.libraries then for k, v in pairs(sem.libraries) do if v then libs[#libs+1] = k end end end
    table.sort(libs)
    
    return {
        artifact = id.path and id.path:match("([^/]+)$") or "unknown",
        path = id.path,
        sha256 = id.sha256,
        size = id.size,
        executable = id.executable,
        elf = st.is_elf,
        sections = st.section_count,
        imports = st.import_count,
        exports = st.export_count,
        libraries = libs,
        classification = ml.class or "unknown",
        confidence = ml.confidence,
        risk_tier = c.risk_tier or "UNKNOWN",
        novelty_tier = c.novelty_tier or "UNKNOWN",
        anomaly = ml.anomaly or false,
        timestamp = os.time(),
    }
end

local function to_json(obj)
    local function val(v)
        local t = type(v)
        if t == "table" then
            local is_arr = #v > 0
            for k, _ in pairs(v) do if type(k) ~= "number" then is_arr = false; break end end
            local parts = {}
            if is_arr then
                for _, x in ipairs(v) do parts[#parts+1] = val(x) end
                return "[" .. table.concat(parts, ",") .. "]"
            else
                for k, x in pairs(v) do parts[#parts+1] = string.format("%q:%s", tostring(k), val(x)) end
                return "{" .. table.concat(parts, ",") .. "}"
            end
        elseif t == "string" then return string.format("%q", v)
        elseif t == "number" then return string.format("%.10g", v)
        elseif t == "boolean" then return tostring(v)
        else return "null" end
    end
    return val(obj)
end

-- Main
local function main()
    local dir = arg[1] or "/mnt/d/moabi/bin"
    local out = arg[2] or ("/mnt/d/moabi/reports/sbom-" .. os.date("%Y%m%d-%H%M%S") .. ".jsonl")
    
    if not file_exists(dir) then
        io.stderr:write("Directory not found: " .. dir .. "\n")
        os.exit(1)
    end
    
    print("MOABI SBOM scan: " .. dir .. " -> " .. out)
    
    -- Load model once
    local model = nil
    if file_exists(MODEL_PATH) then
        local chunk, _ = loadfile(MODEL_PATH)
        if chunk then
            local ok, m = pcall(chunk)
            if ok and m and m.samples then model = m end
        end
    end
    
    local outf = io.open(out, "w")
    if not outf then error("Cannot write: " .. out) end
    
    local p = io.popen("ls -1 " .. shq(dir))
    if not p then error("Cannot list: " .. dir) end
    
    local stats = { total = 0, clear = 0, notable = 0, suspicious = 0, hostile = 0 }
    
    for fname in p:lines() do
        local fpath = dir .. "/" .. fname
        local check = io.popen("test -f " .. shq(fpath) .. " && echo 1")
        if check and check:read("*l") == "1" then
            check:close()
            local e = analyze(fpath, model)
            if e then
                local rec = record(e)
                outf:write(to_json(rec) .. "\n")
                stats.total = stats.total + 1
                local tier = (rec.risk_tier or "UNKNOWN"):lower()
                stats[tier] = (stats[tier] or 0) + 1
            end
        else
            if check then check:close() end
        end
    end
    p:close()
    outf:close()
    
    print("Records: " .. stats.total)
    print("Verdicts:")
    for _, tier in ipairs({"clear", "notable", "suspicious", "hostile"}) do
        local n = stats[tier] or 0
        if n > 0 then print("  " .. tier:upper() .. ": " .. n) end
    end
end

local ok, ret = pcall(main)
if not ok then io.stderr:write("\nERROR: " .. tostring(ret) .. "\n"); os.exit(1) end
