#!/usr/bin/env luajit
--============================================================================
--  GULLWING-YARA v1.0 — YARA Rule Scanner + LLM Rule Generation
--============================================================================

local SRC = "/mnt/d/moabi/src"
local REFLECT = SRC .. "/moabi-reflect.lua"
local RULES_DIR = "/mnt/d/moabi/reports/yara"
local COMMUNITY_RULES = RULES_DIR .. "/community"

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function file_exists(p) local f=io.open(p,"rb"); if f then f:close() return true end; return false end

-- Download community YARA rules if not present
local function ensure_community_rules()
    if not file_exists(COMMUNITY_RULES .. "/index.yar") then
        print("Downloading community YARA rules...")
        os.execute("mkdir -p " .. shq(COMMUNITY_RULES))
        os.execute("git clone --depth 1 https://github.com/Yara-Rules/rules.git " .. shq(COMMUNITY_RULES) .. " 2>/dev/null")
        if file_exists(COMMUNITY_RULES .. "/index.yar") then
            print("Community rules downloaded.")
        else
            print("Could not download community rules — using local only.")
        end
    end
end

local function scan_with_yara(target, rule_path)
    local cmd = string.format("yara -r %s %s 2>/dev/null", shq(rule_path or RULES_DIR), shq(target))
    local h = io.popen(cmd)
    local matches = {}
    for line in h:lines() do
        local rule, path = line:match("^(.+)%s+(.+)$")
        if rule and path then
            matches[#matches + 1] = {
                rule = rule,
                file = path,
            }
        end
    end
    h:close()
    return matches
end

local function generate_yara_rule(evidence)
    -- Use phi3:mini to generate a YARA rule from evidence
    local prompt = string.format(
        "Generate a YARA rule based on this binary analysis. Return ONLY the YARA rule, no explanation.\n\n" ..
        "Binary: %s\nClass: %s\nRisk: %s\nLibraries: %s\nSignals: %s\n\n" ..
        "rule name: detect_%s\nstrings:\ncondition:",
        evidence.name or "unknown",
        evidence.class or "unknown",
        evidence.risk or "?",
        evidence.libraries or "none",
        table.concat(evidence.signals or {}, ", "),
        (evidence.class or "unknown"):gsub("[^%w]", "_")
    )
    
    local tmp = os.tmpname()
    local f = io.open(tmp, "w")
    f:write(prompt)
    f:close()
    
    local cmd = string.format("ollama run phi3:mini < %s 2>/dev/null", shq(tmp))
    local h = io.popen(cmd)
    local generated = h:read("*a")
    h:close()
    os.remove(tmp)
    
    -- Clean up the output to extract just the YARA rule
    local rule = generated:match("(rule%s+.-\n})") or generated
    return rule
end

local function usage()
    print("GULLWING-YARA v1.0 — YARA Rule Scanner")
    print()
    print("Commands:")
    print("  gullwing yara scan <binary>            — Scan with community rules")
    print("  gullwing yara generate <binary>        — Generate a YARA rule via phi3:mini")
    print("  gullwing yara full <binary>            — Full analysis + YARA + rule generation")
    print("  gullwing yara rules                    — Update community rule database")
end

local function cmd_scan(target)
    ensure_community_rules()
    print("GULLWING-YARA SCAN: " .. target)
    print()
    
    local matches = scan_with_yara(target)
    print(string.format("  Rules matched: %d", #matches))
    print()
    
    if #matches > 0 then
        local seen = {}
        for _, m in ipairs(matches) do
            if not seen[m.rule] then
                seen[m.rule] = true
                print(string.format("  🎯 %s", m.rule))
            end
        end
    else
        print("  No community rules matched.")
    end
end

local function cmd_generate(target)
    print("GULLWING-YARA GENERATE: " .. target)
    print()
    
    -- Run Gullwing reflect to get evidence
    os.execute("luajit " .. shq(REFLECT) .. " " .. shq(target) .. " --static-only --json 2>/dev/null")
    local name = target:match("([^/]+)$") or "unknown"
    local epath = "/mnt/d/moabi/reports/" .. name .. ".evidence.json"
    
    if not file_exists(epath) then
        print("  Could not analyze binary. Run gullwing reflect first.")
        return
    end
    
    local f = io.open(epath)
    local evidence_str = f:read("*a")
    f:close()
    
    local json = require("json"); local ok, evidence = pcall(json.decode, evidence_str)
    if not ok then
        print("  Could not parse evidence.")
        return
    end
    
    local c = evidence.convergence or {}
    local ml = evidence.ml or {}
    local sem = evidence.semantics or {}
    
    local libs = {}
    if sem.libraries then
        for lib, present in pairs(sem.libraries) do
            if present then libs[#libs+1] = lib end
        end
    end
    
    local data = {
        name = name,
        class = ml.class or "unknown",
        risk = c.risk_tier or "?",
        libraries = table.concat(libs, ", "),
        signals = c.signals or {},
    }
    
    print("  Generating YARA rule via phi3:mini...")
    local rule = generate_yara_rule(data)
    print()
    print("  Generated YARA rule:")
    print("  " .. string.rep("─", 60))
    print(rule)
    print("  " .. string.rep("─", 60))
    
    -- Save the rule
    local rule_path = RULES_DIR .. "/" .. name .. ".yar"
    local rf = io.open(rule_path, "w")
    rf:write(rule)
    rf:close()
    print()
    print("  Rule saved: " .. rule_path)
end

local function cmd_full(target)
    cmd_scan(target)
    print()
    cmd_generate(target)
end

local function cmd_rules()
    print("Updating community YARA rules...")
    os.execute("rm -rf " .. shq(COMMUNITY_RULES))
    ensure_community_rules()
    print("Done.")
end

local function main()
    local cmd = arg[1]
    if cmd == "scan" and arg[2] then cmd_scan(arg[2])
    elseif cmd == "generate" and arg[2] then cmd_generate(arg[2])
    elseif cmd == "full" and arg[2] then cmd_full(arg[2])
    elseif cmd == "rules" then cmd_rules()
    else usage() end
end

main()
