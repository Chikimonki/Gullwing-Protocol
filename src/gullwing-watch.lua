#!/usr/bin/env luajit
--============================================================================
--  GULLWING-WATCH v1.0 — Continuous Supply Chain Monitor
--  Polls directory. On change: delta → alert. Triggers agent.
--============================================================================

local SRC = "/mnt/d/moabi/src"
local REFLECT = SRC .. "/moabi-reflect.lua"
local DELTA   = SRC .. "/moabi-delta.lua"
local EXTRACT = SRC .. "/moabi-extract.lua"
local AGENT   = SRC .. "/gullwing-agent.lua"
local REPORTS = "/mnt/d/moabi/reports/watch"
local THRESHOLD = 3.0

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function ensure_dir(p) os.execute("mkdir -p " .. shq(p) .. " 2>/dev/null") end
local function basename(p) return p:match("([^/]+)$") or p end

local function evidence_path(target)
    return REPORTS .. "/" .. basename(target) .. ".evidence.json"
end

local function reflect(target)
    local out = evidence_path(target)
    -- Read current content BEFORE overwriting (for delta)
    local old_content = ""
    local f = io.open(out, "r")
    if f then old_content = f:read("*a"); f:close() end
    -- Run reflect
    os.execute("luajit " .. shq(REFLECT) .. " " .. shq(target) .. " --static-only --json 2>/dev/null")
    -- Move if written elsewhere
    local default_out = "/mnt/d/moabi/reports/" .. basename(target) .. ".evidence.json"
    if default_out ~= out then
        os.execute("mv " .. shq(default_out) .. " " .. shq(out) .. " 2>/dev/null")
    end
    return out, old_content
end

local function delta(old_path, new_path)
    if not old_path or not new_path then return nil end
    local f = io.open(old_path, "r") if not f then return nil end f:close()
    f = io.open(new_path, "r") if not f then return nil end f:close()
    local h = io.popen("luajit " .. shq(DELTA) .. " " .. shq(old_path) .. " " .. shq(new_path) .. " 2>&1")
    local out = h:read("*a") h:close()
    local weight = tonumber(out:match("Weight: ([%d%.]+)"))
    local verdict = out:match("%[VERDICT%]%s+(.+)")
    local changes = tonumber(out:match("Changes: (%d+)"))
    return { weight = weight or 0, verdict = verdict or "UNKNOWN", changes = changes or 0, output = out }
end

local function alert(target, d)
    local log = io.open(REPORTS .. "/alerts.log", "a")
    local ts = os.date("%Y-%m-%d %H:%M:%S")
    local msg = string.format("[%s] %s — %s\n  Weight: %.1f  |  Changes: %d  |  Critical: %d\n\n",
        ts, target, d.verdict, d.weight, d.changes, d.critical_count or 0)
    log:write(msg) log:close()
    local RED = "\27[31m" local RESET = "\27[0m"
    io.stderr:write(RED .. msg .. RESET)
    -- Auto-trigger agent
    os.execute("luajit " .. shq(AGENT) .. " respond " .. shq(target) .. " " .. shq(d.verdict) .. " 2>&1 &")
end

local function usage()
    print("GULLWING-WATCH v1.0 — Continuous Supply Chain Monitor")
    print("Usage: gullwing watch DIRECTORY [THRESHOLD]")
end

local function main()
    local watch_dir = arg[1]
    if not watch_dir then usage() return 1 end
    if arg[2] then THRESHOLD = tonumber(arg[2]) or THRESHOLD end
    ensure_dir(REPORTS)

    print("GULLWING-WATCH monitoring: " .. watch_dir)
    print("Alert threshold: " .. THRESHOLD)
    print()

    -- Baseline all executables
    print("Building baseline...")
    local baseline = {}
    local h = io.popen("find " .. shq(watch_dir) .. " -type f -executable 2>/dev/null")
    for file in h:lines() do
        local evpath, _ = reflect(file)
        baseline[file] = evpath
        print("  Baselined: " .. basename(file))
    end
    h:close()
    print("Baseline complete. Watching for changes...\n")

    -- Polling loop
    local last_mtimes = {}
    while true do
        io.stderr:write(".")
        local h = io.popen("find " .. shq(watch_dir) .. " -type f 2>/dev/null")
        for file in h:lines() do
            -- Check if executable
            local chk = io.popen("test -x " .. shq(file) .. " && echo 1")
            local is_exec = chk:read("*l") == "1"
            chk:close()
            if is_exec then
                local stat_h = io.popen("stat -c %Y " .. shq(file) .. " 2>/dev/null")
                local mtime = tonumber(stat_h:read("*a") or "0")
                stat_h:close()
                local last = last_mtimes[file] or 0
                if mtime > last then
                    last_mtimes[file] = mtime
                    if last > 0 then
                        -- File changed — run delta
                        print("\n" .. os.date("%H:%M:%S") .. "  Changed: " .. basename(file))
                        local old_file = baseline[file]
                        local new_out, old_content = reflect(file)
                        if old_file and old_content ~= "" then
                            -- Write old content to temp file for delta
                            local snap = os.tmpname()
                            local sf = io.open(snap, "w")
                            sf:write(old_content)
                            sf:close()
                            local d = delta(snap, new_out)
                            if d and d.weight >= THRESHOLD then
                                alert(file, d)
                            else
                                print("  Delta below threshold (weight=" .. (d and d.weight or 0) .. ") — updated baseline")
                            end
                            os.remove(snap)
                        else
                            print("  New file — baselined")
                        end
                        baseline[file] = new_out
                    end
                end
            end
        end
        h:close()
        os.execute("sleep 2")
    end
end

main()
