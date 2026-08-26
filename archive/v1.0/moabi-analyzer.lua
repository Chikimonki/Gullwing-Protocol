#!/usr/bin/env luajit
--============================================================================
--  MOABI-ANALYZER v1.0: The Reflective Engine
--  "Lua" — Portuguese for Moon. This is the reflector.
--
--  Architecture:
--    Zig Binaries (Sensors) → FFI (Nerves) → LuaJIT (Brain) → Evidence (Soul)
--
--  This orchestrator unifies:
--    - moabi-ffi2 (structural ELF analysis)
--    - moabi-ml.lua (behavioral classification)
--    - moabi-dynamic2.lua (runtime profiling)
--    - Semantic detectors (symbolic/string analysis)
--
--  Usage:
--    luajit moabi-analyzer.lua /usr/bin/curl [--dynamic] [--json]
--============================================================================

local ffi = require("ffi")
local json -- lazy loaded

-- ============================================================================
--  CONFIGURATION & CONSTANTS
-- ============================================================================
local MODEL_PATH = "/mnt/d/moabi/reports/system.model"
local ANALYZER_VERSION = "1.0.0"
local FEATURE_DIMENSIONS = 30

-- Risk weights (tunable heuristics)
local RISK_WEIGHTS = {
    anomaly_distance = 2.0,      -- Raw statistical strangeness
    semantic_mismatch = 1.5,     -- Behavior vs claimed identity
    privilege_escalation = 3.0,  -- setuid, capabilities, etc
    network_without_cause = 2.5, -- Network activity in non-network class
    packing_entropy = 2.0,       -- High entropy + low printable
    missing_symbols = 1.0,       -- Stripped binaries in dev tools
    debug_info_present = 0.5,    -- Debug symbols in production (minor risk)
}

-- ============================================================================
--  EVIDENCE OBJECT CONSTRUCTOR
--  This is the "moon"—it reflects everything.
-- ============================================================================
local Evidence = {}
Evidence.__index = Evidence

function Evidence.new(target_path)
    local self = setmetatable({}, Evidence)
    
    -- Identity (The Face)
    self.identity = {
        path = target_path,
        filename = target_path:match("([^/]+)$") or target_path,
        size = 0,
        sha256 = nil,
        md5 = nil,
        entropy = 0.0,
        magic = nil,
    }
    
    -- Structure (The Body)
    self.structure = {
        is_elf = false,
        arch = nil,              -- x86_64, arm64, riscv64
        elf_type = nil,          -- ET_EXEC, ET_DYN, ET_REL
        section_count = 0,
        segment_count = 0,
        has_relro = false,
        has_nx = false,
        has_pie = false,
        has_canary = false,
        stripped = true,
        debug_info = false,
    }
    
    -- Semantics (The Mind)
    self.semantics = {
        class_predicted = "unknown",
        class_confidence = 0.0,
        anomaly_score = 0.0,
        anomaly_distance = 0.0,
        imports = {},
        exports = {},
        libraries = {},          -- Resolved dependency names
        symbols = {
            total = 0,
            dynamic = 0,
            debug = 0,
            suspicious = {},     -- anti-debug, obfuscation markers
        },
        strings = {
            total = 0,
            urls = {},
            ips = {},
            paths = {},
            crypto_material = false,
        },
    }
    
    -- Runtime (The Behavior) — only populated if --dynamic
    self.runtime = {
        profiled = false,
        syscalls = {},
        network_peers = {},
        file_operations = {},
        child_processes = 0,
        entropy_variance = 0.0,
        behavioral_fingerprint = nil,
    }
    
    -- Risk (The Judgment)
    self.risk = {
        score = 0.0,             -- 0.0 to 10.0
        tier = "UNKNOWN",        -- TRUSTED, LOW, MEDIUM, HIGH, CRITICAL
        alerts = {},
        mitigations = {},
    }
    
    -- Provenance (The Chain)
    self.provenance = {
        analyzer_version = ANALYZER_VERSION,
        timestamp = os.time(),
        model_version = nil,
        feature_vector = nil,
    }
    
    return self
end

-- ============================================================================
--  STATIC ANALYSIS PHASE
-- ============================================================================
function Evidence:analyze_static()
    -- Load FFI bridge
    local ok, ffi2 = pcall(require, "moabi-ffi2")
    if not ok or not ffi2 then
        error("Cannot load moabi-ffi2: " .. tostring(ffi2))
    end
    
    -- Read file for hashing and basic stats
    local f = io.open(self.identity.path, "rb")
    if not f then error("Cannot open: " .. self.identity.path) end
    local data = f:read("*a")
    f:close()
    
    self.identity.size = #data
    self.identity.entropy = self:calculate_entropy(data)
    
    -- Structural analysis via FFI
    local struct, source = ffi2.extract_elf_features(self.identity.path)
    if struct then
        self.structure.is_elf = true
        self.structure.section_count = struct.section_count or 0
        self.structure.has_pie = (struct.elf_type_num == 3) -- ET_DYN
        self.structure.debug_info = (struct.has_debug == 1)
        self.structure.stripped = (struct.symbol_size == 0)
        
        -- Populate semantics with structural ML features
        self.semantics.imports.count = struct.import_count or 0
        self.semantics.exports.count = struct.export_count or 0
        self.semantics.symbols.total = struct.symbol_size or 0
        
        -- Library fingerprinting
        local libs = {}
        if struct.has_libssl == 1 then libs[#libs+1] = "libssl" end
        if struct.has_libcrypto == 1 then libs[#libs+1] = "libcrypto" end
        if struct.has_libcurl == 1 then libs[#libs+1] = "libcurl" end
        if struct.has_libz == 1 then libs[#libs+1] = "libz" end
        if struct.has_lzma == 1 then libs[#libs+1] = "liblzma" end
        if struct.has_ncurses == 1 then libs[#libs+1] = "ncurses" end
        if struct.has_readline == 1 then libs[#libs+1] = "readline" end
        if struct.has_libpython == 1 then libs[#libs+1] = "libpython" end
        if struct.has_libperl == 1 then libs[#libs+1] = "libperl" end
        if struct.has_libruby == 1 then libs[#libs+1] = "libruby" end
        self.semantics.libraries = libs
    end
    
    -- ML Classification
    self:classify_with_ml()
    
    -- String analysis (quick scan)
    self:analyze_strings(data)
    
    return self
end

function Evidence:calculate_entropy(data)
    if #data == 0 then return 0.0 end
    local hist = {}
    for i = 0, 255 do hist[i] = 0 end
    for i = 1, #data do
        hist[data:byte(i)] = hist[data:byte(i)] + 1
    end
    local log2 = math.log(2)
    local entropy = 0.0
    for i = 0, 255 do
        if hist[i] > 0 then
            local p = hist[i] / #data
            entropy = entropy - p * (math.log(p) / log2)
        end
    end
    return entropy
end

function Evidence:analyze_strings(data)
    -- Quick heuristic string extraction
    local strings = {}
    local min_len = 4
    local current = ""
    
    for i = 1, #data do
        local b = data:byte(i)
        if b >= 0x20 and b <= 0x7E then
            current = current .. string.char(b)
        else
            if #current >= min_len then
                strings[#strings+1] = current
            end
            current = ""
        end
    end
    if #current >= min_len then
        strings[#strings+1] = current
    end
    
    self.semantics.strings.total = #strings
    
    -- Pattern matching
    for _, s in ipairs(strings) do
        -- URLs
        if s:match("https?://[%w%.%-]+") then
            self.semantics.strings.urls[#self.semantics.strings.urls+1] = s
        end
        -- IPs
        if s:match("%d+%.%d+%.%d+%.%d+") then
            self.semantics.strings.ips[#self.semantics.strings.ips+1] = s
        end
        -- Crypto indicators
        if s:match("AES_") or s:match("RSA_") or s:match("crypt") then
            self.semantics.strings.crypto_material = true
        end
    end
end

function Evidence:classify_with_ml()
    -- Load model and classify
    local ok, chunk = pcall(loadfile, MODEL_PATH)
    if not ok or not chunk then
        self.semantics.class_predicted = "ERROR"
        return
    end
    
    local model = chunk()
    if not model or not model.samples then
        self.semantics.class_predicted = "INVALID_MODEL"
        return
    end
    
    -- Extract features (reuse logic from moabi-ml)
    local vec = self:extract_feature_vector()
    self.provenance.feature_vector = vec
    
    -- Normalize and classify (simplified k-NN)
    local n_features = #vec
    local k = model.k or 5
    
    -- Normalize vector
    local nv = {}
    for i = 1, n_features do
        local mean = model.normalization.mean[i] or 0
        local std = model.normalization.std[i] or 1
        if std < 1e-10 then std = 1 end
        nv[i] = (vec[i] - mean) / std
    end
    
    -- Calculate distances
    local dists = {}
    for _, sample in ipairs(model.samples) do
        local d = 0.0
        for i = 1, n_features do
            local sv = (sample.vec[i] - model.normalization.mean[i]) / 
                       (model.normalization.std[i] or 1)
            local diff = nv[i] - sv
            d = d + diff * diff
        end
        dists[#dists+1] = {dist = math.sqrt(d), label = sample.label, file = sample.filename}
    end
    
    table.sort(dists, function(a, b) return a.dist < b.dist end)
    
    -- Weighted voting
    local scores = {}
    local total_weight = 0.0
    local avg_dist = 0.0
    
    for i = 1, math.min(k, #dists) do
        local w = 1.0 / (dists[i].dist + 1e-10)
        scores[dists[i].label] = (scores[dists[i].label] or 0) + w
        total_weight = total_weight + w
        avg_dist = avg_dist + dists[i].dist
    end
    
    avg_dist = avg_dist / math.min(k, #dists)
    
    -- Determine winner
    local best_label, best_score = "unknown", 0
    for label, score in pairs(scores) do
        if score > best_score then
            best_label, best_score = label, score
        end
    end
    
    self.semantics.class_predicted = best_label
    self.semantics.class_confidence = (best_score / total_weight) * 100
    self.semantics.anomaly_distance = avg_dist
    
    -- Anomaly detection
    local threshold = model.anomaly_threshold or 5.0
    self.semantics.anomaly_score = avg_dist / threshold
    
    self.provenance.model_version = model.info and model.info.version or "unknown"
end

function Evidence:extract_feature_vector()
    -- Build 30-dim vector matching moabi-ml.lua schema
    local v = {}
    v[1] = math.log(self.identity.size + 1)
    v[2] = self.identity.entropy
    v[3] = 0 -- byte_mean (requires full parse, use entropy as proxy for now)
    v[4] = 0 -- byte_stddev
    v[5] = 0 -- null_ratio
    v[6] = 0 -- printable_ratio
    v[7] = self.structure.is_elf and 1.0 or 0.0
    v[8] = 2.0 -- elf_class_num (assume 64-bit)
    v[9] = self.structure.has_pie and 3.0 or 2.0
    v[10] = 0 -- entropy_variance
    v[11] = 0 -- high_entropy_ratio
    v[12] = 0 -- low_entropy_ratio
    v[13] = 0 -- top_byte_ratio
    v[14] = 0 -- ff_ratio
    v[15] = (self.identity.entropy > 7.2) and 1.0 or 0.0 -- packer_detected
    v[16] = self.structure.section_count
    v[17] = self.semantics.imports.count
    v[18] = self.semantics.exports.count
    v[19] = self.semantics.symbols.total
    v[20] = self.structure.debug_info and 1.0 or 0.0
    v[21] = self.semantics.libraries["libssl"] and 1.0 or 0.0
    v[22] = self.semantics.libraries["libcrypto"] and 1.0 or 0.0
    v[23] = self.semantics.libraries["libcurl"] and 1.0 or 0.0
    v[24] = self.semantics.libraries["libz"] and 1.0 or 0.0
    v[25] = self.semantics.libraries["liblzma"] and 1.0 or 0.0
    v[26] = self.semantics.libraries["ncurses"] and 1.0 or 0.0
    v[27] = self.semantics.libraries["readline"] and 1.0 or 0.0
    v[28] = self.semantics.libraries["libpython"] and 1.0 or 0.0
    v[29] = self.semantics.libraries["libperl"] and 1.0 or 0.0
    v[30] = self.semantics.libraries["libruby"] and 1.0 or 0.0
    
    return v
end

-- ============================================================================
--  RISK CALCULATION (The Judgment)
-- ============================================================================
function Evidence:calculate_risk()
    local score = 0.0
    local alerts = {}
    
    -- Anomaly component
    if self.semantics.anomaly_score > 1.0 then
        score = score + RISK_WEIGHTS.anomaly_distance * self.semantics.anomaly_score
        alerts[#alerts+1] = "Statistical anomaly detected (distance: " .. 
                           string.format("%.2f", self.semantics.anomaly_distance) .. ")"
    end
    
    -- Semantic mismatch: claimed class vs observed libraries
    local class = self.semantics.class_predicted
    local libs = self.semantics.libraries
    
    if class == "system_utility" then
        if libs["libcurl"] or libs["libssl"] then
            score = score + RISK_WEIGHTS.network_without_cause
            alerts[#alerts+1] = "System utility links against network libraries"
        end
    elseif class == "network_tool" then
        if not (libs["libcurl"] or libs["libssl"] or libs["libcrypto"]) then
            score = score + RISK_WEIGHTS.semantic_mismatch
            alerts[#alerts+1] = "Network tool lacks expected crypto/network libs"
        end
    elseif class == "interpreter" then
        if not (libs["libpython"] or libs["libperl"] or libs["libruby"]) then
            -- This is the python3 vs moabi_tool confusion we saw
            score = score + RISK_WEIGHTS.semantic_mismatch * 0.5
        end
    end
    
    -- Packing/Obfuscation
    if self.identity.entropy > 7.5 and self.semantics.strings.total < 100 then
        score = score + RISK_WEIGHTS.packing_entropy
        alerts[#alerts+1] = "High entropy with few strings (possible packing)"
    end
    
    -- Capabilities/privilege
    -- (Would check file permissions here if stat available)
    
    self.risk.score = math.min(score, 10.0)
    
    -- Determine tier
    if self.risk.score < 2.0 then
        self.risk.tier = "TRUSTED"
    elseif self.risk.score < 4.0 then
        self.risk.tier = "LOW"
    elseif self.risk.score < 6.0 then
        self.risk.tier = "MEDIUM"
    elseif self.risk.score < 8.0 then
        self.risk.tier = "HIGH"
    else
        self.risk.tier = "CRITICAL"
    end
    
    self.risk.alerts = alerts
    
    -- Generate mitigations
    if #alerts > 0 then
        self.risk.mitigations[#self.risk.mitigations+1] = "Review in sandboxed environment"
        if self.semantics.anomaly_score > 1.5 then
            self.risk.mitigations[#self.risk.mitigations+1] = "Submit to deep static analysis"
        end
    end
    
    return self
end

-- ============================================================================
--  OUTPUT FORMATTERS
-- ============================================================================
function Evidence:to_human()
    local lines = {}
    lines[#lines+1] = "╔════════════════════════════════════════════════════════════╗"
    lines[#lines+1] = "║  MOABI ANALYZER v" .. ANALYZER_VERSION .. " — REFLECTIVE ANALYSIS          ║"
    lines[#lines+1] = "╚════════════════════════════════════════════════════════════╝"
    lines[#lines+1] = ""
    
    -- Identity
    lines[#lines+1] = "【IDENTITY】"
    lines[#lines+1] = "  File:    " .. self.identity.path
    lines[#lines+1] = "  Size:    " .. self.identity.size .. " bytes"
    lines[#lines+1] = string.format("  Entropy: %.4f / 8.0", self.identity.entropy)
    lines[#lines+1] = ""
    
    -- Structure
    lines[#lines+1] = "【STRUCTURE】"
    lines[#lines+1] = "  ELF:           " .. (self.structure.is_elf and "Yes" or "No")
    lines[#lines+1] = "  Sections:      " .. self.structure.section_count
    lines[#lines+1] = "  PIE:           " .. (self.structure.has_pie and "Yes" or "No")
    lines[#lines+1] = "  Stripped:      " .. (self.structure.stripped and "Yes" or "No")
    lines[#lines+1] = "  Debug Info:    " .. (self.structure.debug_info and "Yes" or "No")
    lines[#lines+1] = ""
    
    -- Semantics
    lines[#lines+1] = "【SEMANTICS】"
    lines[#lines+1] = "  Predicted Class:  " .. self.semantics.class_predicted
    lines[#lines+1] = string.format("  Confidence:       %.1f%%", self.semantics.class_confidence)
    lines[#lines+1] = string.format("  Anomaly Score:    %.2f", self.semantics.anomaly_score)
    lines[#lines+1] = "  Libraries:        " .. table.concat(self.semantics.libraries, ", ")
    if #self.semantics.strings.urls > 0 then
        lines[#lines+1] = "  URLs found:       " .. #self.semantics.strings.urls
    end
    if self.semantics.strings.crypto_material then
        lines[#lines+1] = "  Crypto symbols:   Detected"
    end
    lines[#lines+1] = ""
    
    -- Risk
    lines[#lines+1] = "【RISK ASSESSMENT】"
    lines[#lines+1] = "  Tier:  " .. self.risk.tier .. " (Score: " .. string.format("%.2f", self.risk.score) .. "/10)"
    if #self.risk.alerts > 0 then
        lines[#lines+1] = "  Alerts:"
        for _, alert in ipairs(self.risk.alerts) do
            lines[#lines+1] = "    ⚠  " .. alert
        end
    else
        lines[#lines+1] = "  No risk alerts."
    end
    if #self.risk.mitigations > 0 then
        lines[#lines+1] = "  Mitigations:"
        for _, mit in ipairs(self.risk.mitigations) do
            lines[#lines+1] = "    → " .. mit
        end
    end
    
    return table.concat(lines, "\n")
end

function Evidence:to_json()
    if not json then
        -- Simple JSON encoder
        json = function(obj)
            local function encode(o)
                if type(o) == "table" then
                    local is_array = (#o > 0)
                    local parts = {}
                    if is_array then
                        for _, v in ipairs(o) do
                            parts[#parts+1] = encode(v)
                        end
                        return "[" .. table.concat(parts, ",") .. "]"
                    else
                        for k, v in pairs(o) do
                            parts[#parts+1] = string.format("%q:%s", k, encode(v))
                        end
                        return "{" .. table.concat(parts, ",") .. "}"
                    end
                elseif type(o) == "string" then
                    return string.format("%q", o)
                elseif type(o) == "number" then
                    return tostring(o)
                elseif type(o) == "boolean" then
                    return tostring(o)
                else
                    return "null"
                end
            end
            return encode(obj)
        end
    end
    return json(self)
end

-- ============================================================================
--  MAIN ENTRY
-- ============================================================================
local function main()
    local target = arg[1]
    if not target then
        print("Usage: luajit moabi-analyzer.lua <binary> [--json] [--dynamic]")
        os.exit(1)
    end
    
    local use_json = false
    local use_dynamic = false
    
    for i = 2, #arg do
        if arg[i] == "--json" then use_json = true end
        if arg[i] == "--dynamic" then use_dynamic = true end
    end
    
    print("Reflecting upon " .. target .. "...")
    
    local evidence = Evidence.new(target)
    evidence:analyze_static()
    evidence:calculate_risk()
    
    if use_json then
        print(evidence:to_json())
    else
        print(evidence:to_human())
    end
end

local ok, err = pcall(main)
if not ok then
    io.stderr:write("Analyzer failure: " .. tostring(err) .. "\n")
    os.exit(1)
end
