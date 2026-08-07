#!/usr/bin/env luajit
--[[
  Custom system-wide compliance check
  Uses moabi as a library
]]

local moabi = require("/mnt/d/moabi/src/moabi")
local ffi = require("ffi")

-- Binaries we care about for CRA compliance
local CRITICAL_BINARIES = {
    "/usr/bin/ssh",
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/usr/bin/bash",
    "/usr/sbin/sshd",
}

-- Results table
local results = {}

print("")
print("╔══════════════════════════════════════════════════════════╗")
print("║  SYSTEM-WIDE CRA COMPLIANCE CHECK                       ║")
print("╚══════════════════════════════════════════════════════════╝")
print("")

for _, binary in ipairs(CRITICAL_BINARIES) do
    -- Check if file exists
    local f = io.open(binary, "rb")
    if f then
        f:close()
        print("Scanning: " .. binary)
        
        -- Create baseline if not exists
        local bl_path = "/mnt/d/moabi/reports/" .. 
                        binary:gsub("/", "_") .. ".baseline.json"
        
        local bl_file = io.open(bl_path, "r")
        if not bl_file then
            print("  → No baseline, creating...")
            moabi.create_baseline(binary, bl_path)
        else
            bl_file:close()
            print("  → Verifying against baseline...")
            moabi.verify_baseline(binary, bl_path)
        end
        
        -- Generate report
        local report_path = "/mnt/d/moabi/reports/" ..
                           binary:gsub("/", "_") .. ".report.txt"
        moabi.report(binary, report_path)
        
        print("  → Report: " .. report_path)
        print("")
    else
        print("Skipping (not found): " .. binary)
    end
end

print("System check complete.")
print("Reports in: /mnt/d/moabi/reports/")
