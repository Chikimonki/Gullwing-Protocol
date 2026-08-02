#!/usr/bin/env luajit
--============================================================================
--  GULLWING-UNPACK-DEEP v1.1 — GDB Memory Dumping via QEMU
--============================================================================

local SRC = "/mnt/d/moabi/src"
local REFLECT = SRC .. "/moabi-reflect.lua"
local TIMEOUT = 5
local GDB_PORT = 12345

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

local function usage()
    print("GULLWING-UNPACK-DEEP v1.1 — GDB Memory Dumping")
    print("Usage: gullwing unpack_deep <binary>")
end

local function deep_unpack(target)
    local name = target:match("([^/]+)$") or "unknown"
    local dump_path = "/tmp/" .. name .. ".memory.dump"
    local unpacked_path = "/tmp/" .. name .. ".unpacked.elf"
    local gdb_script = "/tmp/" .. name .. ".gdb"
    
    print(string.format("GULLWING-UNPACK-DEEP: %s", target))
    print()
    
    -- Step 1: Write GDB script to dump memory
    local gdb = io.open(gdb_script, "w")
    gdb:write([[
set pagination off
set confirm off
# Dump the entire process memory map
info proc mappings
# Dump the text segment (usually 0x400000 for x86_64)
dump binary memory ]] .. shq(dump_path) .. [[ 0x00000000 0x7fffffffffff
quit
]])
    gdb:close()
    
    -- Step 2: Start QEMU with GDB stub in background
    print("  [1/3] Starting QEMU with GDB stub on port " .. GDB_PORT .. "...")
    local qemu_cmd = string.format(
        "timeout %d qemu-x86_64 -g %d %s 2>/dev/null 1>/dev/null &",
        TIMEOUT, GDB_PORT, shq(target))
    os.execute(qemu_cmd)
    
    -- Give QEMU time to start and the binary to reach unpacking
    os.execute("sleep 3")
    
    -- Step 3: Connect GDB and dump memory
    print("  [2/3] Connecting GDB to dump memory...")
    local gdb_cmd = string.format(
        "gdb -batch -x %s 2>/dev/null",
        shq(gdb_script))
    os.execute(gdb_cmd)
    
    -- Step 4: Extract ELF from dump
    print("  [3/3] Extracting executable segments...")
    local f = io.open(dump_path, "rb")
    if f then
        local data = f:read("*a")
        f:close()
        
        if #data > 0 then
            -- Search for ELF header in the dump
            local elf_pos = data:find("\127ELF", 1, true)
            if elf_pos then
                local elf_data = data:sub(elf_pos)
                local out = io.open(unpacked_path, "wb")
                out:write(elf_data)
                out:close()
                print(string.format("  Extracted ELF: %d bytes from offset %d", #elf_data, elf_pos))
                
                -- Run Gullwing on unpacked binary
                os.execute("luajit " .. shq(REFLECT) .. " " .. shq(unpacked_path) .. " --static-only --json 2>/dev/null")
                print()
                print("  Original: " .. target)
                print("  Unpacked: " .. unpacked_path)
            else
                print("  No ELF header found in memory dump")
                print("  Falling back to original binary analysis...")
                os.execute("luajit " .. shq(REFLECT) .. " " .. shq(target) .. " --static-only --json 2>/dev/null")
            end
        else
            print("  Memory dump empty — binary may have exited before unpacking")
            print("  Try increasing TIMEOUT in the script")
        end
    else
        print("  Memory dump failed — QEMU may not have started properly")
    end
    
    -- Cleanup
    os.remove(dump_path)
    os.remove(gdb_script)
    os.execute("pkill -f 'qemu-x86_64 -g' 2>/dev/null")
    
    local line = string.rep("=", 64)
    print(line)
    print("  DEEP UNPACK COMPLETE")
    print(line)
end

local function main()
    if not arg[1] or arg[1] == "-h" then usage(); return 0 end
    deep_unpack(arg[1])
    return 0
end

main()
