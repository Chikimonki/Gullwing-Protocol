#!/usr/bin/env luajit
--============================================================================
--  MOABI-EXTRACT v1.0 — Embedded Binary Extractor
--  Finds executables inside PDFs, archives, Office docs, and other files.
--============================================================================

local SRC = "/mnt/d/moabi/src"
package.path = SRC .. "/?.lua;" .. package.path

-- ============================================================================
--  MAGIC BYTE SIGNATURES
-- ============================================================================

local MAGIC = {
    ELF = "\127ELF",
    PE  = "MZ",
    ZIP = "PK\003\004",
    PDF = "%PDF-",
    GZ  = "\031\139",
    BZ2 = "BZh",
    XZ  = "\2537zXZ",
    ZST = "\040\181\047\253",
}

-- ============================================================================
--  EXTRACTION FUNCTIONS
-- ============================================================================

local function extract_raw(path)
    -- If the file itself is an executable, return it directly
    local f = io.open(path, "rb")
    if not f then return {} end
    local header = f:read(4)
    f:close()

    if not header then return {} end

    if header:sub(1, 4) == MAGIC.ELF or header:sub(1, 2) == MAGIC.PE then
        return { { path = path, offset = 0, format = "raw", note = "direct binary" } }
    end

    return nil  -- Not a binary, needs further extraction
end

local function extract_zip(path)
    -- Extract all files from a ZIP archive, check each for ELF/PE headers
    local results = {}
    local tmpdir = os.tmpname() .. "_extract"
    os.execute("mkdir -p " .. "'" .. tmpdir .. "' 2>/dev/null")
    os.execute("unzip -o '" .. path .. "' -d '" .. tmpdir .. "' 2>/dev/null")

    local p = io.popen("find '" .. tmpdir .. "' -type f 2>/dev/null")
    if p then
        for file in p:lines() do
            local f = io.open(file, "rb")
            if f then
                local header = f:read(4)
                f:close()
                if header and (header:sub(1, 4) == MAGIC.ELF or header:sub(1, 2) == MAGIC.PE) then
                    results[#results + 1] = {
                        path = file,
                        offset = 0,
                        format = "zip-embedded",
                        note = "extracted from " .. path,
                    }
                end
            end
        end
        p:close()
    end

    return results
end

local function extract_pdf(path)
    -- Find ELF/PE streams embedded in PDF files
    local results = {}
    local f = io.open(path, "rb")
    if not f then return results end
    local data = f:read("*a")
    f:close()

    -- Search for ELF magic
    local pos = 1
    while pos <= #data do
        local elf_pos = data:find(MAGIC.ELF, pos, true)
        if not elf_pos then break end

        -- Extract the suspected ELF to a temp file
        local tmp = os.tmpname() .. ".elf"
        local chunk_size = math.min(#data - elf_pos + 1, 10 * 1024 * 1024)  -- 10MB max
        local out = io.open(tmp, "wb")
        out:write(data:sub(elf_pos, elf_pos + chunk_size - 1))
        out:close()

        -- Verify it's a real ELF by checking the class byte
        local check = io.open(tmp, "rb")
        if check then
            local hdr = check:read(6)
            check:close()
            if hdr and #hdr >= 6 and hdr:byte(5) >= 1 and hdr:byte(5) <= 2 then
                results[#results + 1] = {
                    path = tmp,
                    offset = elf_pos,
                    format = "pdf-embedded",
                    note = string.format("ELF at offset %d in %s", elf_pos, path),
                }
            else
                os.remove(tmp)
            end
        end

        pos = elf_pos + 4
    end

    -- Search for PE magic
    pos = 1
    while pos <= #data do
        local pe_pos = data:find(MAGIC.PE, pos, true)
        if not pe_pos then break end

        local tmp = os.tmpname() .. ".exe"
        local chunk_size = math.min(#data - pe_pos + 1, 10 * 1024 * 1024)
        local out = io.open(tmp, "wb")
        out:write(data:sub(pe_pos, pe_pos + chunk_size - 1))
        out:close()

        -- Verify PE header
        local check = io.open(tmp, "rb")
        if check then
            check:seek("set", 60)  -- PE signature offset in DOS header
            local pe_sig = check:read(4)
            check:close()
            if pe_sig == "PE\000\000" then
                results[#results + 1] = {
                    path = tmp,
                    offset = pe_pos,
                    format = "pdf-embedded",
                    note = string.format("PE at offset %d in %s", pe_pos, path),
                }
            else
                os.remove(tmp)
            end
        end

        pos = pe_pos + 2
    end

    return results
end

-- ============================================================================
--  UEFI FIRMWARE VOLUME EXTRACTION
--  Scans for PE executables (EFI applications/drivers) inside firmware images.
-- ============================================================================

local function extract_uefi(path)
    local results = {}
    local f = io.open(path, "rb")
    if not f then return results end
    local data = f:read("*a")
    f:close()
    if not data or #data < 128 then return results end

    local pos = 1
    local count = 0
    local seen = {}
    while pos <= #data - 4 do
        -- Search for PE\0\0 signature
        if data:byte(pos) == 80 and data:byte(pos+1) == 69 
           and data:byte(pos+2) == 0 and data:byte(pos+3) == 0 then
            -- Found PE header — look backwards up to 128 bytes for MZ
            local mz = nil
            for back = 0, 128 do
                if pos - back > 0 and data:sub(pos - back, pos - back + 1) == "MZ" then
                    mz = pos - back
                    break
                end
            end
            if mz and not seen[mz] then
                seen[mz] = true
                count = count + 1
                local tmp = os.tmpname() .. ".efi"
                local chunk = math.min(#data - mz + 1, 10 * 1024 * 1024)
                local out = io.open(tmp, "wb")
                out:write(data:sub(mz, mz + chunk - 1))
                out:close()
                results[#results + 1] = {
                    path = tmp,
                    offset = mz,
                    format = "uefi-firmware",
                    note = string.format("EFI executable at offset %d", mz),
                }
                pos = mz + 64  -- Skip past this PE
            end
        end
        pos = pos + 1
    end
    if count > 0 then
        io.stderr:write(string.format("  [UEFI] Found %d EFI executable(s)\n", count))
    end
    return results
end

local function extract_gz(path)
    -- Decompress gzip and check contents
    local results = {}
    local tmp = os.tmpname()
    os.execute("gunzip -c '" .. path .. "' > '" .. tmp .. "' 2>/dev/null")

    local f = io.open(tmp, "rb")
    if f then
        local header = f:read(4)
        f:close()
        if header and (header:sub(1, 4) == MAGIC.ELF or header:sub(1, 2) == MAGIC.PE) then
            results[#results + 1] = {
                path = tmp,
                offset = 0,
                format = "gz-embedded",
                note = "decompressed from " .. path,
            }
        else
            os.remove(tmp)
        end
    end

    return results
end

-- ============================================================================
--  MAIN EXTRACTION DISPATCHER
-- ============================================================================

local function extract(path)
    -- First: is it directly a binary?
    local direct = extract_raw(path)
    if direct then return direct end

    -- Determine file type from magic bytes
    local f = io.open(path, "rb")
    if not f then return {} end
    local header = f:read(4)
    f:close()

    if not header then return {} end

    -- PDF
    if header:sub(1, 4) == MAGIC.PDF then
        return extract_pdf(path)
    end

    -- ZIP-based (including Office docs: .docx, .xlsx, .jar, .apk)
    if header:sub(1, 4) == MAGIC.ZIP then
        return extract_zip(path)
    end

    -- Gzip
    if header:sub(1, 2) == MAGIC.GZ then
        return extract_gz(path)
    -- UEFI Firmware Volume (scans for PE executables inside firmware)
    end
    local uefi_results = extract_uefi(path)
    if #uefi_results > 0 then
        return uefi_results
    end

    -- Fallback: scan raw bytes for ELF/PE headers anywhere
    local results = {}
    f = io.open(path, "rb")
    if f then
        local data = f:read("*a")
        f:close()
        if data then
            -- Quick scan for ELF
            local elf_count = 0
            local pos = 1
            while pos <= #data do
                local found = data:find(MAGIC.ELF, pos, true)
                if not found then break end
                elf_count = elf_count + 1
                pos = found + 4
            end
            if elf_count > 0 then
                results[#results + 1] = {
                    path = path,
                    offset = 0,
                    format = "raw-scan",
                    note = string.format("%d ELF header(s) found in %s", elf_count, path),
                }
            end
        end
    end

    return results
end

-- ============================================================================
--  REPORT
-- ============================================================================

local function print_report(results, source_path)
    local line = string.rep("=", 64)
    print(line)
    print("  MOABI-EXTRACT — Embedded Binary Scanner")
    print(line)
    print()
    print("  Source: " .. source_path)

    if #results == 0 then
        print("  Result: No embedded executables found")
    else
        print(string.format("  Result: %d embedded executable(s) found", #results))
        print()
        for i, r in ipairs(results) do
            print(string.format("  [%d] %s", i, r.note or r.format))
            print(string.format("      Path:   %s", r.path))
            print(string.format("      Format: %s", r.format))
            print()
        end
    end
    print(line)
end

-- ============================================================================
--  MAIN
-- ============================================================================

local function usage()
    print("MOABI-EXTRACT v1.0 — Embedded Binary Extractor")
    print("Usage: luajit moabi-extract.lua FILE [--reflect]")
    print()
    print("  --reflect   Pipe extracted binaries to gullwing reflect")
end

local function main()
    if not arg[1] or arg[1] == "-h" or arg[1] == "--help" then
        usage()
        return 0
    end

    local results = extract(arg[1])
    print_report(results, arg[1])

    -- Optionally run reflect on each extracted binary
    local do_reflect = false
    for i = 2, #arg do
        if arg[i] == "--reflect" then do_reflect = true; break end
    end

    if do_reflect and #results > 0 then
        print("Running gullwing reflect on extracted binaries...")
        print()
        for _, r in ipairs(results) do
            os.execute("luajit /mnt/d/moabi/src/moabi-reflect.lua '" .. r.path .. "' --static-only 2>&1")
        end
    end

    return #results > 0 and 1 or 0
end

main()
