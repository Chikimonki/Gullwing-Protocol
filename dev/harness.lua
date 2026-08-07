#!/usr/bin/env luajit
--============================================================================
--  GULLWING DEV HARNESS v1.0 — Automate the Pain Away
--============================================================================

local SRC = "/mnt/d/moabi/src"
local EXT = SRC .. "/extension"
local WIN_EXT = "/mnt/c/Users/ccuk/Desktop/gullwing-extension"

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

local function check_disk()
    local h = io.popen("df -h /mnt/c | tail -1 | awk '{print $4}'")
    local avail = h:read("*a"):gsub("%s+", "")
    h:close()
    local num = tonumber(avail:match("([%d%.]+)"))
    local unit = avail:match("([A-Za-z]+)")
    local gb = num
    if unit == "M" then gb = num / 1024 end
    print(string.format("  C: drive free: %s", avail))
    if gb < 5 then
        print("  WARNING: Less than 5GB free on C:!")
    elseif gb < 10 then
        print("  Less than 10GB free — monitor closely.")
    else
        print("  Plenty of space.")
    end
end

local function validate()
    local errors = 0
    local files = 0
    local h = io.popen("find " .. shq(SRC) .. " -name '*.lua' -not -path '*/archive/*' -not -path '*/deps/*' -not -path '*/luajit/*'")
    for file in h:lines() do
        files = files + 1
        local ok, err = loadfile(file)
        if not ok and not file:match("%.before%-") then
            print(string.format("  FAIL: %s", file:gsub(SRC.."/", "")))
            errors = errors + 1
        end
    end
    h:close()
    print(string.format("  Files: %d | Errors: %d", files, errors))
    if errors == 0 then print("  All files pass.") end
end

local function sync()
    print("  Syncing WSL -> Windows...")
    os.execute("cp " .. shq(EXT .. "/unified.html") .. " " .. shq(WIN_EXT .. "/unified.html") .. " 2>/dev/null")
    os.execute("cp " .. shq(EXT .. "/background.js") .. " " .. shq(WIN_EXT .. "/background.js") .. " 2>/dev/null")
    os.execute("cp " .. shq(EXT .. "/manifest.json") .. " " .. shq(WIN_EXT .. "/manifest.json") .. " 2>/dev/null")
    os.execute("cp " .. shq(EXT .. "/popup.html") .. " " .. shq(WIN_EXT .. "/popup.html") .. " 2>/dev/null")
    os.execute("cp " .. shq(EXT .. "/popup.js") .. " " .. shq(WIN_EXT .. "/popup.js") .. " 2>/dev/null")
    print("  Sync complete.")
end

local function quickstart()
    os.execute("pkill -f moabi-serve 2>/dev/null")
    os.execute("pkill -f 'python3 -m http.server' 2>/dev/null")
    os.execute("fuser -k 9393/tcp 2>/dev/null")
    os.execute("fuser -k 8080/tcp 2>/dev/null")
    os.execute("sleep 1")
    os.execute("luajit " .. shq(SRC .. "/moabi-serve.lua") .. " &")
    os.execute("sleep 1")
    os.execute("cd " .. shq(EXT) .. " && python3 -m http.server 8080 &")
    os.execute("sleep 1")
    print("  API:    http://127.0.0.1:9393")
    print("  Frontend: http://127.0.0.1:8080/unified.html")
end

local function cleanup()
    print("  Large files on C: (>50MB):")
    os.execute("find /mnt/c/Users/ccuk -type f -size +50M 2>/dev/null | head -10")
end

local function fleet_generate()
    os.execute("luajit /mnt/d/moabi/dev/fleet-trainer.lua generate")
end

local function fleet_simulate(pattern)
    os.execute("luajit /mnt/d/moabi/dev/fleet-trainer.lua simulate " .. shq(pattern or "hostile"))
end

local function usage()
    print("GULLWING DEV HARNESS v1.0")
    print()
    print("Commands:")
    print("  dev-harness check     — Validate syntax + disk space")
    print("  dev-harness sync      — Sync files to Windows extension folder")
    print("  dev-harness start     — Launch everything (API + frontend)")
    print("  dev-harness clean     — Find large/duplicate files")
    print("  dev-harness fleet generate      — Generate fleet ML training data")
    print("  dev-harness fleet simulate <p>  — Simulate attack pattern")
    print("  dev-harness all       — Check, sync, start (full workflow)")

end

local function main()
    local cmd = arg[1] or "all"
    
    if cmd == "check" or cmd == "all" then
        print("[1/3] Validating...")
        validate()
        print()
        print("[2/3] Disk space...")
        check_disk()
    end
    
    if cmd == "sync" or cmd == "all" then
        print()
        print("[3/3] Syncing...")
        sync()
    end
    
    if cmd == "start" or cmd == "all" then
        print()
        quickstart()
    end
    
    if cmd == "clean" then cleanup() end
    
    if cmd == "fleet" then
        local sub = arg[2] or "generate"
        if sub == "generate" then fleet_generate()
        elseif sub == "simulate" then fleet_simulate(arg[3])
        else usage() end
    end
    
    if cmd == "help" or cmd == "-h" then usage() end
end
