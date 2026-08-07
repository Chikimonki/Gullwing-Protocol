#!/usr/bin/env luajit
--============================================================================
--  FLEET TRAINER v1.0 — Generate fleet traffic data for ML training
--============================================================================

local SRC = "/mnt/d/moabi/src"
local TRAINING = "/mnt/d/moabi/reports/training/fleet"

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

-- Simulated fleet activity patterns
local PATTERNS = {
    normal = {
        name = "normal_fleet",
        description = "Regular Tailscale traffic between trusted nodes",
        connections = {
            {from="node-01", to="node-02", port=9393, proto="http", bytes=1500, label="reflect_api"},
            {from="node-02", to="node-01", port=9393, proto="http", bytes=800, label="status_check"},
            {from="node-03", to="node-01", port=9393, proto="http", bytes=2200, label="deep_scan"},
        },
        interval = "5s",
        risk = "CLEAR"
    },
    suspicious = {
        name = "suspicious_scan",
        description = "Unknown node probing all fleet members",
        connections = {
            {from="unknown-99", to="node-01", port=9393, proto="http", bytes=100, label="probe"},
            {from="unknown-99", to="node-02", port=9393, proto="http", bytes=100, label="probe"},
            {from="unknown-99", to="node-03", port=9393, proto="http", bytes=100, label="probe"},
            {from="unknown-99", to="node-04", port=22, proto="ssh", bytes=500, label="ssh_attempt"},
        },
        interval = "500ms",
        risk = "SUSPICIOUS"
    },
    hostile = {
        name = "lateral_movement",
        description = "Compromised node scanning internal network",
        connections = {
            {from="node-01", to="192.168.1.0/24", port=445, proto="smb", bytes=4000, label="smb_scan"},
            {from="node-01", to="192.168.1.0/24", port=3389, proto="rdp", bytes=2000, label="rdp_scan"},
            {from="node-01", to="192.168.1.0/24", port=22, proto="ssh", bytes=3000, label="ssh_bruteforce"},
        },
        interval = "100ms",
        risk = "HOSTILE"
    },
    data_exfil = {
        name = "data_exfiltration",
        description = "Large outbound transfers to unknown IP",
        connections = {
            {from="node-02", to="198.51.100.23", port=443, proto="https", bytes=50000000, label="large_upload"},
            {from="node-02", to="198.51.100.23", port=443, proto="https", bytes=35000000, label="large_upload"},
        },
        interval = "10m",
        risk = "HOSTILE"
    }
}

local function generate_training_data()
    os.execute("mkdir -p " .. shq(TRAINING))
    
    print("FLEET TRAINER: Generating synthetic fleet data...")
    print()
    
    for pattern_key, pattern in pairs(PATTERNS) do
        local filepath = TRAINING .. "/" .. pattern.name .. ".json"
        local f = io.open(filepath, "w")
        
        local entry = {
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            pattern = pattern.name,
            description = pattern.description,
            risk = pattern.risk,
            connections = pattern.connections,
            metadata = {
                total_bytes = 0,
                unique_targets = 0,
                unique_ports = 0,
                interval = pattern.interval,
            }
        }
        
        -- Calculate metadata
        local targets = {}; local ports = {}
        for _, conn in ipairs(pattern.connections) do
            entry.metadata.total_bytes = entry.metadata.total_bytes + conn.bytes
            targets[conn.to] = true
            ports[conn.port] = true
        end
        entry.metadata.unique_targets = table.getn(targets)
        entry.metadata.unique_ports = table.getn(ports)
        
        f:write(require("json").encode(entry))
        f:close()
        
        print(string.format("  ✅ %-20s → %s/%s.json  [%s]", 
            pattern.description, TRAINING:match("([^/]+)$"), pattern.name, pattern.risk))
    end
    
    print()
    print("Training data generated. Use these patterns to:")
    print("  1. Train the ML model to recognize fleet attack patterns")
    print("  2. Simulate attacks on your Tailscale network")
    print("  3. Validate that gullwing watch detects lateral movement")
end

local function simulate_attack(pattern_name)
    local pattern = PATTERNS[pattern_name]
    if not pattern then
        print("Unknown pattern: " .. (pattern_name or "nil"))
        print("Available: " .. table.concat(table.getn(PATTERNS) and {"normal","suspicious","hostile","data_exfil"} or {}, ", "))
        return
    end
    
    print(string.format("SIMULATING: %s [%s]", pattern.description, pattern.risk))
    print()
    
    for _, conn in ipairs(pattern.connections) do
        print(string.format("  %-15s → %-20s :%-5d %s (%d bytes)",
            conn.from, conn.to, conn.port, conn.proto:upper(), conn.bytes))
    end
    
    print()
    print("  Run 'gullwing watch /tmp 3.0' to detect this pattern.")
    print("  The watcher will flag unknown connections as NOTABLE/SUSPICIOUS.")
end

local function usage()
    print("FLEET TRAINER v1.0 — Fleet ML Training Data Generator")
    print()
    print("Commands:")
    print("  dev-harness fleet generate     — Generate synthetic fleet training data")
    print("  dev-harness fleet simulate <pattern> — Simulate an attack pattern")
    print()
    print("Patterns: normal, suspicious, hostile, data_exfil")
end

local function main()
    local cmd = arg[1]
    
    if cmd == "generate" then
        generate_training_data()
    elseif cmd == "simulate" then
        simulate_attack(arg[2])
    else
        usage()
    end
end

main()
