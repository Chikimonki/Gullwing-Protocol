#!/usr/bin/env luajit
--============================================================================
--  GULLWING-STIX v1.0 — STIX 2.1 Export for SOC/Regulatory Compliance
--============================================================================

local SRC = "/mnt/d/moabi/src"
local json = require("json")

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function file_exists(p) local f=io.open(p,"rb"); if f then f:close() return true end; return false end

local function generate_stix_id(prefix)
    return prefix .. "--" .. string.format("%08x-%04x-%04x-%04x-%012x",
        math.random(0,0xffffffff), math.random(0,0xffff), math.random(0,0xffff),
        math.random(0,0xffffffff), math.random(0,0xffffffff))
end

local function evidence_to_stix(evidence_path, output_path)
    if not file_exists(evidence_path) then
        io.stderr:write("Evidence not found: " .. evidence_path .. "\n")
        return nil
    end
    
    local f = io.open(evidence_path)
    local evidence = json.decode(f:read("*a"))
    f:close()
    
    local c = evidence.convergence or {}
    local ml = evidence.ml or {}
    local id = evidence.identity or {}
    local sem = evidence.semantics or {}
    local st = evidence.structure or {}
    
    local now = os.date("!%Y-%m-%dT%H:%M:%SZ")
    local bundle_id = generate_stix_id("bundle")
    local indicator_id = generate_stix_id("indicator")
    local malware_id = generate_stix_id("malware")
    local identity_id = generate_stix_id("identity")
    local report_id = generate_stix_id("report")
    local observed_id = generate_stix_id("observed-data")
    
    -- Map risk to STIX severity
    local severity = {CLEAR=10, NOTABLE=40, SUSPICIOUS=70, HOSTILE=100}
    
    -- Build libraries list
    local libs = {}
    if sem.libraries then
        for lib, present in pairs(sem.libraries) do
            if present then libs[#libs+1] = lib end
        end
    end
    
    local bundle = {
        type = "bundle",
        id = bundle_id,
        spec_version = "2.1",
        objects = {
            -- Indicator: what was detected
            {
                type = "indicator",
                id = indicator_id,
                created = now,
                modified = now,
                name = string.format("Gullwing Analysis: %s", id.path or "unknown"),
                description = string.format("Binary classified as %s with %.1f%% confidence. Risk: %s, Novelty: %s.",
                    ml.class or "unknown", ml.confidence or 0, c.risk_tier or "?", c.novelty_tier or "?"),
                indicator_types = {"malicious-activity", "anomalous-activity"},
                pattern = string.format("[file:hashes.'SHA-256' = '%s']", id.sha256 or "unknown"),
                pattern_type = "stix",
                valid_from = now,
                labels = {ml.class or "unknown", c.risk_tier or "?"},
                confidence = math.floor((ml.confidence or 0) / 100 * 99) + 1,
                extensions = {
                    ["extension-definition--" .. generate_stix_id("ext")] = {
                        extension_type = "property-extension",
                        gullwing_risk_score = c.risk_score or 0,
                        gullwing_novelty_score = c.novelty_score or 0,
                        gullwing_novelty_ratio = c.novelty_ratio or 0,
                        gullwing_signals = c.signals or {},
                        gullwing_libraries = libs,
                        gullwing_elf_type = st.elf_type or "?",
                        gullwing_entropy = (evidence.entropy_profile or {}).global or 0,
                    }
                }
            },
            -- Malware: analysis result
            {
                type = "malware",
                id = malware_id,
                created = now,
                modified = now,
                name = ml.class or "unknown",
                description = string.format("Analyzed by Gullwing. %d signals: %s",
                    #(c.signals or {}), table.concat(c.signals or {}, "; ")),
                malware_types = {ml.class or "unknown"},
                is_family = false,
                sample_refs = {observed_id},
                analysis_conclusion = c.verdict or c.risk_tier or "?",
            },
            -- Observed Data: the binary itself
            {
                type = "observed-data",
                id = observed_id,
                created = now,
                modified = now,
                first_observed = now,
                last_observed = now,
                number_observed = 1,
                object_refs = {indicator_id},
                extensions = {
                    ["extension-definition--" .. generate_stix_id("ext2")] = {
                        extension_type = "property-extension",
                        file_name = id.path:match("([^/]+)$") or id.path,
                        file_size = id.size or 0,
                        file_sha256 = id.sha256 or "?",
                        file_executable = id.executable or false,
                    }
                }
            },
            -- Report: human-readable summary
            {
                type = "report",
                id = report_id,
                created = now,
                modified = now,
                name = string.format("Gullwing Convergent Analysis: %s", id.path:match("([^/]+)$") or id.path),
                description = string.format("Risk: %s | Novelty: %s | Class: %s | Confidence: %.1f%% | Signals: %s",
                    c.risk_tier or "?", c.novelty_tier or "?",
                    ml.class or "?", ml.confidence or 0,
                    table.concat(c.signals or {}, "; ")),
                report_types = {"analysis", "malware-analysis"},
                published = now,
                object_refs = {indicator_id, malware_id, observed_id},
                labels = {"gullwing", "convergent-reflection", ml.class or "unknown"},
                external_references = {{
                    source_name = "Gullwing",
                    description = "Convergent Binary Intelligence Platform",
                    url = "https://github.com/forgottennord-ship-it/GullWing",
                }}
            }
        }
    }
    
    -- Add risk score to indicator
    bundle.objects[1].extensions["extension-definition--" .. generate_stix_id("ext3")] = {
        extension_type = "property-extension",
        risk_severity = severity[c.risk_tier] or 50,
    }
    
    -- Write output
    local out = output_path or (evidence_path:gsub("%.json$", ".stix.json"))
    local of = io.open(out, "w")
    of:write(json.encode(bundle))
    of:close()
    
    return out
end

local function usage()
    print("GULLWING-STIX v1.0 — STIX 2.1 Export")
    print()
    print("Usage:")
    print("  gullwing stix <evidence.json> [output.stix.json]")
    print()
    print("Converts Gullwing evidence to STIX 2.1 format.")
    print("Compatible with Splunk, Elastic, MISP, and government systems.")
end

local function main()
    if not arg[1] or arg[1] == "-h" then usage(); return 0 end
    
    local out = evidence_to_stix(arg[1], arg[2])
    if out then
        print("STIX 2.1 bundle written: " .. out)
        print()
        print("Import this into any STIX-compatible system:")
        print("  - MISP: Upload via REST API")
        print("  - Elastic: Filebeat STIX module")
        print("  - Splunk: STIX add-on")
        print("  - TAXII server: curl -X POST")
    end
end

main()
