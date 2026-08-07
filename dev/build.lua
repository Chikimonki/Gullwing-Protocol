#!/usr/bin/env luajit
--============================================================================
--  GULLWING BUILD SYSTEM v1.0 — Template-based code generation
--  No more sed. No more manual editing. Templates → validated output.
--============================================================================

local SRC = "/mnt/d/moabi/src"
local DEV = "/mnt/d/moabi/dev"

-- Template: dev-harness usage section
local HARNESS_USAGE = [[
    print("  dev-harness check     — Validate syntax + disk space")
    print("  dev-harness sync      — Sync files to Windows extension folder")
    print("  dev-harness start     — Launch everything (API + frontend)")
    print("  dev-harness clean     — Find large/duplicate files")
    print("  dev-harness fleet generate      — Generate fleet ML training data")
    print("  dev-harness fleet simulate <p>  — Simulate attack pattern")
    print("  dev-harness all       — Check, sync, start (full workflow)")
]]

-- ============================================================================
--  BUILD: Regenerate dev-harness.lua from template
-- ============================================================================

local function build_harness()
    local template = io.open(DEV .. "/harness_template.lua", "r")
    if not template then
        print("No template found. Creating from current harness...")
        os.execute("cp " .. "/mnt/d/moabi/dev/harness.lua" .. " " .. "/mnt/d/moabi/dev/harness_template.lua")
        return
    end
    
    local content = template:read("*a")
    template:close()
    
    -- Replace usage section
    content = content:gsub("local function usage.-end", 
        "local function usage()\n    print(\"GULLWING DEV HARNESS v1.0\")\n    print()\n    print(\"Commands:\")\n" .. HARNESS_USAGE .. "\nend")
    
    local out = io.open(DEV .. "/harness.lua", "w")
    out:write(content)
    out:close()
    
    -- Validate
    local ok, err = loadfile(DEV .. "/harness.lua")
    if ok then
        print("✅ harness.lua built and validated")
    else
        print("❌ harness.lua has errors: " .. tostring(err))
    end
end

-- ============================================================================
--  BUILD: Validate all project files
-- ============================================================================

local function validate_all()
    local errors = 0
    local files = 0
    
    local h = io.popen("find " .. "/mnt/d/moabi/src" .. " -name '*.lua' -not -path '*/archive/*' -not -path '*/deps/*' -not -path '*/luajit/*'")
    for file in h:lines() do
        files = files + 1
        local ok, err = loadfile(file)
        if not ok and not file:match("%.before%-") then
            -- Skip known backup files
            local msg = tostring(err):match(":(%d+):") or "?"
            print(string.format("  ❌ %-50s line %s", file:gsub(SRC.."/", ""), msg))
            errors = errors + 1
        end
    end
    h:close()
    
    print()
    print(string.format("  Files checked: %d", files))
    print(string.format("  Errors: %d", errors))
    if errors == 0 then print("  ✅ All files pass.") end
end

-- ============================================================================
--  MAIN
-- ============================================================================

local function main()
    local cmd = arg[1] or "all"
    
    if cmd == "harness" or cmd == "all" then
        build_harness()
    end
    
    if cmd == "validate" or cmd == "all" then
        validate_all()
    end
end


main()
