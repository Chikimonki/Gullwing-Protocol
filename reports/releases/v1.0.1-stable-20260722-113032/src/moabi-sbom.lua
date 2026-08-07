#!/usr/bin/env luajit
--============================================================================
--  MOABI-SBOM v2.3 — CycloneDX 1.6 Generator
--  Self-contained JSON encoder. No moabi-evidence dependency.
--============================================================================

local SRC = "/mnt/d/moabi/src"
package.path = SRC .. "/?.lua;" .. package.path

local MF = require("moabi-features")
local pe_ok, pe_mod = pcall(require, "moabi-pe")

local function shq(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function sha256(path)
    local h = io.popen("sha256sum " .. shq(path) .. " 2>/dev/null")
    if not h then return "unknown" end
    local line = h:read("*l") or ""
    h:close()
    return line:match("^(%x+)") or "unknown"
end

local function file_size(path)
    local f = io.open(path, "rb")
    if not f then return 0 end
    local n = f:seek("end") or 0
    f:close()
    return n
end

local function detect_format(path)
    local f = io.open(path, "rb")
    if not f then return "unknown" end
    local m = f:read(4) or ""
    f:close()

    if m:sub(1,2) == "MZ" then return "pe" end
    if m:byte(1) == 0x7f and m:byte(2) == 0x45 and m:byte(3) == 0x4c and m:byte(4) == 0x46 then
        return "elf"
    end
    return "other"
end

local function jquote(s)
    s = tostring(s)
    s = s:gsub("\\", "\\\\")
         :gsub('"', '\\"')
         :gsub("\n", "\\n")
         :gsub("\r", "\\r")
         :gsub("\t", "\\t")
    return '"' .. s .. '"'
end

local function is_array(t)
    local n = 0
    local max = 0
    for k in pairs(t) do
        if type(k) ~= "number" then return false end
        if k > max then max = k end
        n = n + 1
    end
    return n > 0 and n == max
end

local function json(v, depth)
    depth = depth or 0
    local pad = string.rep("  ", depth)
    local pad2 = string.rep("  ", depth + 1)
    local tv = type(v)

    if tv == "nil" then return "null"
    elseif tv == "boolean" then return v and "true" or "false"
    elseif tv == "number" then
        if v ~= v or v == math.huge or v == -math.huge then return "null" end
        return tostring(v)
    elseif tv == "string" then
        return jquote(v)
    elseif tv == "table" then
        local parts = {}

        if is_array(v) then
            for i = 1, #v do
                parts[#parts + 1] = pad2 .. json(v[i], depth + 1)
            end
            if #parts == 0 then return "[]" end
            return "[\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "]"
        else
            local keys = {}
            for k in pairs(v) do keys[#keys + 1] = k end
            table.sort(keys, function(a,b) return tostring(a) < tostring(b) end)

            for _, k in ipairs(keys) do
                parts[#parts + 1] = pad2 .. jquote(k) .. ": " .. json(v[k], depth + 1)
            end
            if #parts == 0 then return "{}" end
            return "{\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "}"
        end
    end

    return "null"
end

local function prop(name, value)
    return { name = "moabi:" .. name, value = tostring(value) }
end

local function component_for(path)
    local name = path:match("([^/]+)$") or path
    local fmt = detect_format(path)
    local hash = sha256(path)
    local size = file_size(path)

    local c = {
        ["type"] = "application",
        ["bom-ref"] = "moabi/" .. name .. "@sha256:" .. hash:sub(1,16),
        name = name,
        version = "unknown",
        hashes = {
            { alg = "SHA-256", content = hash }
        },
        properties = {
            prop("format", fmt),
            prop("path", path),
            prop("size", size),
        },
        evidence = {
            identity = {
                field = "hash",
                confidence = 1.0,
                methods = {
                    {
                        technique = "hash-comparison",
                        confidence = 1.0,
                        value = hash
                    }
                }
            }
        }
    }

    if fmt == "elf" then
        local ok, r = pcall(MF.extract, path)
        if ok and r and r.feat then
            c.properties[#c.properties+1] = prop("entropy", string.format("%.4f", r.feat.entropy or 0))
            c.properties[#c.properties+1] = prop("sections", r.feat.section_count or 0)
            c.properties[#c.properties+1] = prop("imports_count", r.feat.import_count or 0)
            c.properties[#c.properties+1] = prop("exports_count", r.feat.export_count or 0)
            c.properties[#c.properties+1] = prop("risk", "CLEAR")
            c.properties[#c.properties+1] = prop("novelty", "NORMAL")
        else
            c.properties[#c.properties+1] = prop("risk", "NOTABLE")
            c.properties[#c.properties+1] = prop("novelty", "UNKNOWN")
        end

    elseif fmt == "pe" then
        if pe_ok and pe_mod and pe_mod.analyze then
            local ok, pe = pcall(pe_mod.analyze, path)
            if ok and pe then
                c.properties[#c.properties+1] = prop("machine", pe.machine or "unknown")
                c.properties[#c.properties+1] = prop("subsystem", pe.subsystem or "unknown")
                c.properties[#c.properties+1] = prop("sections", #(pe.sections or {}))
                c.properties[#c.properties+1] = prop("imports_count", #(pe.imports or {}))
                c.properties[#c.properties+1] = prop("dll_count", #(pe.dll_list or {}))
                c.properties[#c.properties+1] = prop("entropy", string.format("%.4f", pe.overall_entropy or 0))

                local suspicious = #(pe.suspicious_imports or {})
                local risk = "CLEAR"
                if suspicious == 1 then risk = "NOTABLE"
                elseif suspicious >= 3 then risk = "SUSPICIOUS"
                elseif suspicious > 0 then risk = "NOTABLE" end

                c.properties[#c.properties+1] = prop("risk", risk)
                c.properties[#c.properties+1] = prop("novelty", "N/A")

                if pe.dll_list and #pe.dll_list > 0 then
                    c.components = {}
                    for _, dll in ipairs(pe.dll_list) do
                        c.components[#c.components+1] = {
                            ["type"] = "library",
                            ["bom-ref"] = "moabi/dll:" .. dll,
                            name = dll,
                            version = "unknown",
                            scope = "required"
                        }
                    end
                end
            else
                c.properties[#c.properties+1] = prop("risk", "NOTABLE")
                c.properties[#c.properties+1] = prop("novelty", "UNKNOWN")
            end
        end

    else
        c.properties[#c.properties+1] = prop("risk", "NOTABLE")
        c.properties[#c.properties+1] = prop("novelty", "UNKNOWN")
    end

    return c, fmt
end

local function uuid_from_hex(hex)
    hex = (hex or ""):gsub("[^%x]", "")
    while #hex < 32 do hex = hex .. "0" end
    hex = hex:sub(1,32)
    return "urn:uuid:"
        .. hex:sub(1,8) .. "-"
        .. hex:sub(9,12) .. "-"
        .. "4" .. hex:sub(14,16) .. "-"
        .. "8" .. hex:sub(18,20) .. "-"
        .. hex:sub(21,32)
end

local function main()
    local dir = arg[1]
    if not dir then
        print("MOABI CycloneDX 1.6 SBOM Generator")
        print("Usage: luajit moabi-sbom.lua <dir> [--recursive] [--out file]")
        return 1
    end

    local recursive = false
    local out = "/mnt/d/moabi/reports/sbom-" .. os.date("%Y%m%d-%H%M%S") .. "-cyclonedx.json"

    local i = 2
    while i <= #arg do
        if arg[i] == "--recursive" then
            recursive = true
        elseif arg[i] == "--out" and arg[i+1] then
            out = arg[i+1]
            i = i + 1
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
            components[#components+1] = comp
            counts[fmt or "other"] = (counts[fmt or "other"] or 0) + 1
            print("  + " .. comp.name)
        end
    end
    p:close()

    local seed = sha256(dir)
    local bom = {
        bomFormat = "CycloneDX",
        specVersion = "1.6",
        serialNumber = uuid_from_hex(seed),
        version = 1,
        metadata = {
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            tools = {
                components = {
                    {
                        ["type"] = "application",
                        ["bom-ref"] = "moabi-sbom@2.3",
                        vendor = "MOABI",
                        name = "moabi-sbom",
                        version = "2.3"
                    }
                }
            }
        },
        components = components
    }

    local f = io.open(out, "w")
    if not f then
        io.stderr:write("Cannot write: " .. out .. "\n")
        return 1
    end
    f:write(json(bom, 0))
    f:write("\n")
    f:close()

    print()
    print("  CycloneDX 1.6 written: " .. out)
    print("  Components: " .. #components)
    print("    ELF:   " .. counts.elf)
    print("    PE:    " .. counts.pe)
    print("    Other: " .. counts.other)
    print("========================================================")

    return 0
end

os.exit(main() or 0)
