#!/usr/bin/env luajit
--============================================================================
--  GULLWING-AGENT v1.0 — Automated Response Engine
--  Quarantine, attest, restore on CRITICAL alerts.
--============================================================================

local SRC = "/mnt/d/moabi/src"
local REPORTS = "/mnt/d/moabi/reports"
local QUARANTINE = REPORTS .. "/quarantine"
local ALERT_LOG = REPORTS .. "/watch/alerts.log"
local THRESHOLD = "NOTABLE"

package.path = SRC .. "/?.lua;" .. package.path

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function ensure_dir(p) os.execute("mkdir -p " .. shq(p) .. " 2>/dev/null") end
local function basename(p) return p:match("([^/]+)$") or p end
local function now() return os.date("%Y-%m-%d %H:%M:%S") end
local function file_exists(p) local f=io.open(p,"rb"); if f then f:close() return true end; return false end

local function log_action(action, target, detail)
    ensure_dir(REPORTS .. "/agent")
    local f = io.open(REPORTS .. "/agent/actions.log", "a")
    f:write(string.format("[%s] %s | %s | %s\n", now(), action, target, detail))
    f:close()
end

local function quarantine(target)
    ensure_dir(QUARANTINE)
    local dest = QUARANTINE .. "/" .. basename(target) .. "." .. os.date("%Y%m%d-%H%M%S")
    local cmd = "cp " .. shq(target) .. " " .. shq(dest) .. " 2>/dev/null"
    local rc = os.execute(cmd)
    if rc ~= 0 then return nil end
    os.execute("chmod -x " .. shq(dest) .. " 2>/dev/null")
    os.remove(target)
    return dest
end

local function attest_evidence(target)
    local epath = REPORTS .. "/watch/" .. basename(target) .. ".evidence.json"
    if not file_exists(epath) then return false end
    local h = io.popen("luajit " .. shq(SRC .. "/gullwing-attest.lua") .. " sign " .. shq(epath) .. " 2>&1")
    local out = h:read("*a") h:close()
    return out:find("Status: SIGNED") ~= nil
end

local function restore_from_baseline(target)
    local bpath = REPORTS .. "/watch/baseline/" .. basename(target)
    if not file_exists(bpath) then return false end
    os.execute("cp " .. shq(bpath) .. " " .. shq(target) .. " 2>/dev/null")
    os.execute("chmod +x " .. shq(target) .. " 2>/dev/null")
    return true
end

local function notify(target, verdict, qpath)
    local RED = "\27[31m" local YELLOW = "\27[33m" local RESET = "\27[0m"
    io.stderr:write(string.format([[
%s══════════════════════════════════════════════════════════════%s
%s  GULLWING AGENT — AUTOMATED RESPONSE%s
%s══════════════════════════════════════════════════════════════%s

  Time:      %s
  Target:    %s
  Verdict:   %s%s%s
  Action:    QUARANTINED → %s

  Evidence signed and logged.
%s══════════════════════════════════════════════════════════════%s
]], RED, RESET, RED, RESET, RED, RESET, now(), target, YELLOW, verdict, RESET, qpath, RED, RESET))
end

local function process_alert(line)
    local target = line:match("%]%s+(%S+)%s+[%—-][%—-]")
    local verdict = line:match("[%—-][%—-]%s+(.-)%s*$")
    if not target or not verdict then return end
    if not (verdict:match("CRITICAL") or verdict:match("NOTABLE")) then
        log_action("MONITOR", target, verdict .. " — below threshold")
        return
    end
    if not file_exists(target) then return end
    log_action("ALERT", target, verdict .. " — RESPONDING")
    local qpath = quarantine(target)
    if not qpath then log_action("FAIL", target, "Quarantine failed") return end
    log_action("QUARANTINE", target, "Moved to " .. qpath)
    local attested = attest_evidence(target)
    if attested then log_action("ATTEST", target, "Evidence signed") end
    local restored = restore_from_baseline(target)
    if restored then log_action("RESTORE", target, "Restored from baseline")
    else log_action("RESTORE", target, "No baseline — manual restore required") end
    notify(target, verdict, qpath)
end

local function watch_alerts()
    ensure_dir(REPORTS .. "/watch")
    ensure_dir(QUARANTINE)
    local f = io.open(ALERT_LOG, "a") f:close()
    local last_mtime = 0
    while true do
        local h = io.popen("stat -c %Y " .. shq(ALERT_LOG) .. " 2>/dev/null")
        local mtime = tonumber(h:read("*a") or "0") h:close()
        if mtime and mtime > last_mtime then
            last_mtime = mtime
            local f = io.open(ALERT_LOG, "r")
            if f then
                for line in f:lines() do
                    if line:match("CRITICAL") or line:match("HOSTILE") then
                        process_alert(line)
                    end
                end
                f:close()
            end
        end
        io.stderr:write(".")
        os.execute("sleep 2")
    end
end

local function usage()
    print("GULLWING-AGENT v1.0 — Automated Response Engine")
    print("Modes:")
    print("  gullwing agent watch     — Monitor alert log")
    print("  gullwing agent respond TARGET VERDICT — Manual trigger")
    print("  gullwing agent status    — Show quarantine state")
end

local function main()
    local cmd = arg[1]
    if cmd == "watch" then
        print("GULLWING-AGENT monitoring: " .. ALERT_LOG)
        print("Threshold: " .. THRESHOLD)
        watch_alerts()
    elseif cmd == "respond" and arg[2] and arg[3] then
        local line = string.format("[%s] %s — %s", now(), arg[2], arg[3])
        process_alert(line)
    elseif cmd == "status" then
        print("Quarantine: " .. QUARANTINE)
        os.execute("ls -la " .. shq(QUARANTINE) .. " 2>/dev/null")
        print("Action log:")
        os.execute("cat " .. shq(REPORTS .. "/agent/actions.log") .. " 2>/dev/null")
    else
        usage()
    end
end

main()
