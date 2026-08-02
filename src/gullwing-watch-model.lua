#!/usr/bin/env luajit
-- Watch a single file for changes. Fire alert if modified.
local SRC = "/mnt/d/moabi/src"
local MODEL = "/mnt/d/moabi/reports/system.model"
local THRESHOLD = 0.1  -- Any change is critical for the model

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

print("GULLWING MODEL GUARD watching: " .. MODEL)
print("Any modification triggers CRITICAL alert")
print()

local last_sha = ""
local h = io.popen("sha256sum " .. shq(MODEL) .. " 2>/dev/null")
last_sha = h:read("*a"):match("^(%x+)") or ""
h:close()
print("Baseline SHA-256: " .. last_sha:sub(1,16) .. "...")
print()

while true do
    local h = io.popen("sha256sum " .. shq(MODEL) .. " 2>/dev/null")
    local current_sha = h:read("*a"):match("^(%x+)") or ""
    h:close()
    
    if current_sha ~= last_sha and last_sha ~= "" then
        local RED = "\27[31m" local RESET = "\27[0m"
        local msg = string.format("[%s] MODEL TAMPER DETECTED\n  Old: %s\n  New: %s\n  Action: Immediate investigation required.\n",
            os.date("%Y-%m-%d %H:%M:%S"), last_sha:sub(1,16), current_sha:sub(1,16))
        io.stderr:write(RED .. msg .. RESET)
        print(msg)
        -- Trigger agent
        os.execute("luajit " .. shq(SRC .. "/gullwing-agent.lua") .. " respond " .. shq(MODEL) .. " \"MODEL TAMPER DETECTED\" 2>&1 &")
        last_sha = current_sha
    elseif current_sha ~= last_sha then
        last_sha = current_sha
    end
    
    io.stderr:write(".")
    os.execute("sleep 2")
end
