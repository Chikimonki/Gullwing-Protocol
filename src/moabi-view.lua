#!/usr/bin/env luajit
-- MOABI-VIEW v1.1 — robust terminal dashboard for MOABI CycloneDX files

local function read_all(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local d = f:read("*a")
    f:close()
    return d
end

local function color(c) return "\27[" .. c .. "m" end
local RESET = color("0")
local BOLD  = color("1")
local GREEN = color("32")
local YELL  = color("33")
local RED   = color("31")
local CYAN  = color("36")
local DIM   = color("2")

local function count_pattern(text, pat)
    local n = 0
    for _ in text:gmatch(pat) do n = n + 1 end
    return n
end

local function main()
    local path = arg[1]
    if not path then
        print("Usage: luajit moabi-view.lua <cyclonedx.json>")
        return 1
    end

    local text = read_all(path)
    if not text then
        print("Error reading file")
        return 1
    end

    local bom_format = text:match('"bomFormat"%s*:%s*"([^"]+)"') or "unknown"
    local spec = text:match('"specVersion"%s*:%s*"([^"]+)"') or "unknown"

    local components = count_pattern(text, '"bom%-ref"%s*:%s*"moabi/')
    local elf = count_pattern(text, '"moabi:format"%s*,%s*"value"%s*:%s*"elf"')
    local pe  = count_pattern(text, '"moabi:format"%s*,%s*"value"%s*:%s*"pe"')
    local other = count_pattern(text, '"moabi:format"%s*,%s*"value"%s*:%s*"other"')

    local risks = {
        CLEAR = count_pattern(text, '"moabi:risk"%s*,%s*"value"%s*:%s*"CLEAR"'),
        NOTABLE = count_pattern(text, '"moabi:risk"%s*,%s*"value"%s*:%s*"NOTABLE"'),
        SUSPICIOUS = count_pattern(text, '"moabi:risk"%s*,%s*"value"%s*:%s*"SUSPICIOUS"'),
        HOSTILE = count_pattern(text, '"moabi:risk"%s*,%s*"value"%s*:%s*"HOSTILE"'),
    }

    print(CYAN .. "╔" .. string.rep("═", 60) .. "╗" .. RESET)
    print(CYAN .. "║" .. BOLD .. "  MOABI GULLWING DASHBOARD" .. string.rep(" ", 34) .. RESET .. CYAN .. "║" .. RESET)
    print(CYAN .. "╚" .. string.rep("═", 60) .. "╝" .. RESET)
    print()
    print("  Target BOM:    " .. path)
    print("  Format:        " .. bom_format .. " " .. spec)
    print("  Components:    " .. GREEN .. components .. RESET)
    print()
    print("  Composition:")
    print("    ELF:         " .. elf)
    print("    PE:          " .. pe)
    print("    Other:       " .. other)
    print()
    print("  Risk Profile:")

    local function bar(label, n, col)
        local maxw = 30
        local w = math.min(n, maxw)
        print(string.format("    %-12s [%s%-30s%s] %d",
            label, col, string.rep("█", w), RESET, n))
    end

    bar("CLEAR", risks.CLEAR, GREEN)
    bar("NOTABLE", risks.NOTABLE, YELL)
    bar("SUSPICIOUS", risks.SUSPICIOUS, YELL .. BOLD)
    bar("HOSTILE", risks.HOSTILE, RED .. BOLD)

    print()
    print(CYAN .. string.rep("═", 62) .. RESET)
end

os.exit(main() or 0)
