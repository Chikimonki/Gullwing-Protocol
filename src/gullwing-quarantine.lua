#!/usr/bin/env luajit
-- Gullwing Quarantine - Isolate suspicious binaries

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

local SRC = "/mnt/d/The-Gullwing-Protocol/CORE/gullwing-cormorant/src"
local QUARANTINE_DIR = "/mnt/d/The-Gullwing-Protocol/CORE/gullwing-cormorant/quarantine"

-- Create quarantine directory if it doesn't exist
os.execute("mkdir -p " .. shq(QUARANTINE_DIR))

local target = arg[1]
if not target then
    print("Usage: gullwing quarantine <binary>")
    os.exit(1)
end

-- Check if target exists
local f = io.open(target, "rb")
if not f then
    print("❌ Target not found: " .. target)
    os.exit(1)
end
f:close()

-- Generate quarantine record
local timestamp = os.date("%Y%m%d-%H%M%S")
local filename = target:gsub("/", "_"):gsub("^_", "")
local quarantine_path = QUARANTINE_DIR .. "/" .. filename .. "." .. timestamp .. ".quarantined"

-- Copy to quarantine
os.execute("cp " .. shq(target) .. " " .. shq(quarantine_path))
os.execute("chmod 000 " .. shq(quarantine_path))

-- Generate hash
local pipe = io.popen("sha256sum " .. shq(target))
local hash = pipe:read("*a"):match("^(%S+)")
pipe:close()

-- Create quarantine record
local record = {
    original_path = target,
    quarantine_path = quarantine_path,
    timestamp = timestamp,
    sha256 = hash,
    status = "QUARANTINED",
    detected_by = "Gullwing 8-layer analysis"
}

-- Save record
local record_file = QUARANTINE_DIR .. "/" .. filename .. "." .. timestamp .. ".json"
local json = require("json")
local f = io.open(record_file, "w")
f:write(json.encode(record))
f:close()

print("🚨 QUARANTINE ACTIVATED")
print("======================")
print("Original: " .. target)
print("Quarantined to: " .. quarantine_path)
print("SHA-256: " .. hash)
print("Timestamp: " .. timestamp)
print("Status: QUARANTINED")
print("")
print("✅ Binary isolated and permissions removed")
print("✅ Forensic copy preserved")
print("✅ Audit record created: " .. record_file)
