#!/usr/bin/env luajit
-- Gullwing-wsolver Bridge — Map wsolver results to Gullwing format

local function map_verdict(wsolver_verdict, confidence)
    local risk_map = {
        UNSAFE = "CRITICAL",
        UNKNOWN = "ELEVATED",
        SAFE = "CLEAR",
    }
    
    local risk = risk_map[wsolver_verdict] or "UNKNOWN"
    
    return {
        verdict = wsolver_verdict,
        risk_tier = risk,
        confidence = confidence,
        source = "wsolver",
        integrated = true,
    }
end

-- Example usage
local result = map_verdict("UNSAFE", "HIGH")
print("wsolver: UNSAFE (HIGH) → Gullwing: " .. result.risk_tier)
