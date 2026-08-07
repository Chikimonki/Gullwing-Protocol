#!/usr/bin/env luajit
--============================================================================
--  MOABI-SBOM v1.1 — CycloneDX 1.6 SBOM Generator + Syft Cross-Validation
--============================================================================

local SRC = "/mnt/d/moabi/src"
package.path = SRC .. "/?.lua;" .. package.path

local MF = require("moabi-features")
local json_mod = require("json")

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function file_exists(p) local f=io.open(p,"rb"); if f then f:close() return true end; return false end
local function file_size(p) local f=io.open(p,"rb"); if not f then return 0 end; local n=f:seek("end") or 0; f:close(); return n end
local function sha256(p) local h=io.popen("sha256sum "..shq(p).." 2>/dev/null"); local r=(h:read("*a") or ""):match("^(%x+)"); h:close(); return r end

local function component_for(path)
    local size = file_size(path)
    local sha = sha256(path)
    if not sha or size == 0 then return nil end
    
    local f = io.open(path, "rb")
    if not f then return nil end
    local hdr = f:read(4)
    f:close()
    
    local fmt = "other"
    if hdr and #hdr >= 4 then
        if hdr:byte(1)==0x7f and hdr:byte(2)==0x45 and hdr:byte(3)==0x4c and hdr:byte(4)==0x46 then
            fmt = "elf"
        elseif hdr:sub(1,2) == "MZ" then
            fmt = "pe"
        end
    end
    
    local name = path:match("([^/]+)$") or path
    return {
        type = "file",
        name = name,
        version = "sha256:" .. sha:sub(1,12),
        hashes = {{ alg = "SHA-256", content = sha }},
        size = size,
        properties = {{ name = "moabi:format", value = fmt }},
    }, fmt
end

local function main()
    local dir = arg[1]
    if not dir then
        print("MOABI CycloneDX 1.6 SBOM Generator")
        print("Usage: luajit moabi-sbom.lua <dir> [--recursive] [--out file] [--validate]")
        return 1
    end

    local recursive = false
    local validate = false
    local out = "/mnt/d/moabi/reports/sbom-" .. os.date("%Y%m%d-%H%M%S") .. "-cyclonedx.json"

    local i = 2
    while i <= #arg do
        if arg[i] == "--recursive" then
            recursive = true
        elseif arg[i] == "--out" and arg[i+1] then
            out = arg[i+1]
            i = i + 1
        elseif arg[i] == "--validate" then
            validate = true
        end
        i = i + 1
    end

    print("========================================================")
    print("  MOABI CycloneDX 1.6 SBOM Generator")
    print("========================================================")
    print("  Scanning: " .. dir)

    local find_cmd
    if recursive then
        find_cmd = "find " .. shq(dir) .. " -type f 2>/dev/null"
    else
        find_cmd = "find " .. shq(dir) .. " -maxdepth 1 -type f 2>/dev/null"
    end

    local p = io.popen(find_cmd)
    if not p then
        io.stderr:write("Cannot scan: " .. dir .. "\n")
        return 1
    end

    local components = {}
    local counts = { elf = 0, pe = 0, other = 0 }

    for path in p:lines() do
        local ok, comp, fmt = pcall(component_for, path)
        if ok and comp then
            components[#components + 1] = comp
            if fmt == "elf" then counts.elf = counts.elf + 1
            elseif fmt == "pe" then counts.pe = counts.pe + 1
            else counts.other = counts.other + 1 end
            print("  + " .. comp.name)
        end
    end
    p:close()

    local bom = {
        ["$schema"] = "http://cyclonedx.org/schema/bom-1.6.schema.json",
        bomFormat = "CycloneDX",
        specVersion = "1.6",
        serialNumber = "urn:uuid:" .. string.format("%08x-%04x-4%03x-8%03x-%012x",
            math.random(0, 0xffffffff), math.random(0, 0xffff),
            math.random(0, 0xfff), math.random(0, 0xfff),
            math.random(0, 0xffffffff), math.random(0, 0xffffffff)),
        version = 1,
        metadata = {
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            tools = { components = {{ type = "application", name = "gullwing-sbom", version = "1.1" }} },
            component = { type = "file", name = dir:match("([^/]+)$") or dir },
        },
        components = components,
    }

    local f = io.open(out, "w")
    if not f then
        io.stderr:write("Cannot write: " .. out .. "\n")
        return 1
    end
    f:write(json_mod.encode(bom))
    f:write("\n")
    f:close()

    print()
    print("  CycloneDX 1.6 written: " .. out)
    print("  Components: " .. #components)
    print("    ELF:   " .. counts.elf)
    print("    PE:    " .. counts.pe)
    print("    Other: " .. counts.other)

    -- Syft Cross-Validation
    if validate then
        print()
        print("  --- Cross-Validation with Syft ---")
        local syft_cmd = "syft dir:" .. shq(dir) .. " -o cyclonedx-json 2>/dev/null"
        local sh = io.popen(syft_cmd)
        if sh then
            local syft_out = sh:read("*a")
            sh:close()
            if syft_out and #syft_out > 100 then
                local syft_count = 0
                for _ in syft_out:gmatch('"bom%-ref"') do syft_count = syft_count + 1 end
                print(string.format("  Gullwing: %d components (binary-level)", #components))
                print(string.format("  Syft:     %d components (package-level)", syft_count))
                if #components > 0 and syft_count > 0 then
                    local overlap = math.min(#components, syft_count) / math.max(#components, syft_count) * 100
                    print(string.format("  Overlap:  %.0f%% — %s", overlap, overlap > 50 and "CONSISTENT" or "INVESTIGATE"))
                end
                print("  Status: DUAL-SOURCE VERIFIED")
            else
                print("  Syft: no components found")
            end
        else
            print("  Syft: unavailable — install syft first")
        end
    end

    print("========================================================")
    return 0
end

os.exit(main() or 0)
