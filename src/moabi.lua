#!/usr/bin/env luajit
--[[
  MOABI Binary Analysis Suite — LuaJIT Orchestration Layer
  
  Usage:
    luajit moabi.lua <command> [options] <target>
  
  Commands:
    scan        Run all tools against a binary
    baseline    Create a forensic baseline
    verify      Verify against baseline
    inject      Simulate cave injection (for testing)
    clean       Remove simulated injection
    report      Generate full CRA report
    
  This script orchestrates the Zig tools and provides
  scriptable automation for batch analysis.
]]

local ffi = require("ffi")

-- ============================================================
-- CONFIGURATION
-- ============================================================

local MOABI_BIN = "/mnt/d/moabi/bin"
local MOABI_REPORTS = "/mnt/d/moabi/reports"

local TOOLS = {
    entropy  = MOABI_BIN .. "/moabi-entropy",
    elfparse = MOABI_BIN .. "/moabi-elfparse",
    caves    = MOABI_BIN .. "/moabi-caves",
    strings  = MOABI_BIN .. "/moabi-strings",
    symbols  = MOABI_BIN .. "/moabi-symbols",
    hashdeep = MOABI_BIN .. "/moabi-hashdeep",
    report   = MOABI_BIN .. "/moabi-report",
    baseline = MOABI_BIN .. "/moabi-baseline",
}

-- ============================================================
-- FFI DEFINITIONS FOR LOW-LEVEL ACCESS
-- ============================================================

ffi.cdef[[
    // File operations
    typedef struct FILE FILE;
    FILE *fopen(const char *path, const char *mode);
    int fclose(FILE *stream);
    size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
    size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
    int fseek(FILE *stream, long offset, int whence);
    long ftell(FILE *stream);
    
    // Memory
    void *malloc(size_t size);
    void free(void *ptr);
    void *memset(void *s, int c, size_t n);
    void *memcpy(void *dest, const void *src, size_t n);
    
    // Process
    int system(const char *command);
    
    // Time
    typedef long time_t;
    time_t time(time_t *tloc);
    struct tm *localtime(const time_t *timep);
    size_t strftime(char *s, size_t max, const char *format, const struct tm *tm);
]]

local C = ffi.C

-- ============================================================
-- UTILITY FUNCTIONS
-- ============================================================

local function file_exists(path)
    local f = io.open(path, "r")
    if f then f:close() return true end
    return false
end

local function read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local content = f:read("*all")
    f:close()
    return content
end

local function write_file(path, content)
    local f = io.open(path, "wb")
    if not f then return false end
    f:write(content)
    f:close()
    return true
end

local function run_tool(tool, args)
    local cmd = TOOLS[tool]
    if not cmd then
        print("Unknown tool: " .. tool)
        return nil
    end
    if not file_exists(cmd) then
        print("Tool not found: " .. cmd)
        return nil
    end
    
    local full_cmd = cmd .. " " .. (args or "")
    local handle = io.popen(full_cmd .. " 2>&1")
    local output = handle:read("*all")
    handle:close()
    return output
end

local function timestamp()
    local t = ffi.new("time_t[1]")
    C.time(t)
    local tm = C.localtime(t)
    local buf = ffi.new("char[64]")
    C.strftime(buf, 64, "%Y-%m-%d %H:%M:%S", tm)
    return ffi.string(buf)
end

local function basename(path)
    return path:match("([^/]+)$") or path
end

-- ============================================================
-- CORE FUNCTIONS
-- ============================================================

local moabi = {}

-- Run all analysis tools
function moabi.scan(target)
    print("")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║  MOABI FULL SCAN                                          ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print("")
    print("Target: " .. target)
    print("Time:   " .. timestamp())
    print("")
    
    local tools_order = {"entropy", "elfparse", "caves", "strings", "symbols", "hashdeep"}
    
    for _, tool in ipairs(tools_order) do
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  Running: moabi-" .. tool)
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("")
        local output = run_tool(tool, target)
        if output then print(output) end
    end
end

-- Generate CRA report
function moabi.report(target, output_path)
    output_path = output_path or (MOABI_REPORTS .. "/" .. basename(target) .. "-report.txt")
    
    print("Generating CRA compliance report...")
    print("Target: " .. target)
    print("Output: " .. output_path)
    
    local output = run_tool("report", "-o " .. output_path .. " " .. target)
    if output then print(output) end
    
    return output_path
end

-- Create baseline
function moabi.create_baseline(target, output_path)
    output_path = output_path or (MOABI_REPORTS .. "/" .. basename(target) .. ".baseline.json")
    
    print("Creating forensic baseline...")
    local output = run_tool("baseline", "create -o " .. output_path .. " " .. target)
    if output then print(output) end
    
    return output_path
end

-- Verify against baseline
function moabi.verify_baseline(target, baseline_path)
    print("Verifying against baseline...")
    local output = run_tool("baseline", "compare -b " .. baseline_path .. " " .. target)
    if output then print(output) end
end

-- Simulate injection into a cave (for testing transient hooks)
function moabi.inject_test(target, offset, size, pattern)
    pattern = pattern or 0x90  -- NOP by default
    
    print("")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║  MOABI INJECTION SIMULATOR                                ║")
    print("║  ⚠  FOR TESTING ONLY — MODIFIES BINARY                    ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print("")
    
    -- Read file
    local content = read_file(target)
    if not content then
        print("Error: Cannot read " .. target)
        return false
    end
    
    if offset + size > #content then
        print("Error: Injection range exceeds file size")
        return false
    end
    
    -- Create backup
    local backup_path = target .. ".moabi_backup"
    write_file(backup_path, content)
    print("Backup created: " .. backup_path)
    
    -- Inject pattern
    local before = content:sub(1, offset)
    local injection = string.rep(string.char(pattern), size)
    local after = content:sub(offset + size + 1)
    
    local modified = before .. injection .. after
    write_file(target, modified)
    
    print(string.format("Injected %d bytes of 0x%02X at offset 0x%X", size, pattern, offset))
    print("Original bytes saved in backup")
    
    return true
end

-- Remove injection (restore from backup)
function moabi.clean_test(target)
    local backup_path = target .. ".moabi_backup"
    
    if not file_exists(backup_path) then
        print("No backup found: " .. backup_path)
        return false
    end
    
    local content = read_file(backup_path)
    write_file(target, content)
    os.remove(backup_path)
    
    print("Restored from backup, backup removed")
    return true
end

-- Full transient hook test cycle
function moabi.test_transient(target, cave_offset, cave_size)
    print("")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║  MOABI TRANSIENT HOOK TEST                                ║")
    print("║  Simulating: inject → verify → clean → verify             ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print("")
    
    -- Step 1: Create baseline
    print("Step 1: Creating baseline...")
    local bl_path = moabi.create_baseline(target)
    print("")
    
    -- Step 2: Inject
    print("Step 2: Injecting test payload...")
    moabi.inject_test(target, cave_offset, cave_size, 0xCC)  -- INT3
    print("")
    
    -- Step 3: Verify (should fail)
    print("Step 3: Verifying (expecting FAILURE)...")
    moabi.verify_baseline(target, bl_path)
    print("")
    
    -- Step 4: Clean
    print("Step 4: Cleaning injection...")
    moabi.clean_test(target)
    print("")
    
    -- Step 5: Verify again (should pass)
    print("Step 5: Verifying after cleanup (expecting PASS)...")
    moabi.verify_baseline(target, bl_path)
    print("")
    
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  TEST COMPLETE")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
end

-- Batch scan a directory
function moabi.batch_scan(directory)
    print("Batch scanning directory: " .. directory)
    
    local handle = io.popen("find " .. directory .. " -type f -executable 2>/dev/null")
    local files = handle:read("*all")
    handle:close()
    
    for file in files:gmatch("[^\n]+") do
        print("")
        print("════════════════════════════════════════════════════════════")
        print("  Scanning: " .. file)
        print("════════════════════════════════════════════════════════════")
        moabi.report(file)
    end
end

-- Interactive cave finder
function moabi.find_caves(target)
    print("Finding code caves...")
    local output = run_tool("caves", target)
    if output then print(output) end
    
    -- Parse output to extract cave info
    local caves = {}
    for line in output:gmatch("[^\n]+") do
        local offset, size = line:match("0x(%x+):%s+(%d+)")
        if offset and size then
            table.insert(caves, {
                offset = tonumber(offset, 16),
                size = tonumber(size)
            })
        end
    end
    
    return caves
end

-- ============================================================
-- CLI INTERFACE
-- ============================================================

local function print_usage()
    print([[
MOABI Binary Analysis Suite — LuaJIT Orchestration

Usage: luajit moabi.lua <command> [options] <target>

Commands:
    scan <binary>                      Run all analysis tools
    report <binary> [output]           Generate CRA compliance report
    baseline <binary> [output]         Create forensic baseline
    verify <binary> <baseline>         Verify against baseline
    inject <binary> <offset> <size>    Simulate cave injection
    clean <binary>                     Remove simulated injection
    test-transient <binary> <off> <sz> Full inject/clean/verify cycle
    batch <directory>                  Batch scan all executables
    caves <binary>                     Find and list code caves

Examples:
    luajit moabi.lua scan /usr/bin/ls
    luajit moabi.lua report /usr/bin/ssh
    luajit moabi.lua baseline /usr/bin/bash
    luajit moabi.lua verify /usr/bin/bash bash.baseline.json
    luajit moabi.lua test-transient ./test_binary 0x1000 64
    luajit moabi.lua batch /usr/bin
]])
end

local function main()
    if #arg < 1 then
        print_usage()
        return
    end
    
    local cmd = arg[1]
    
    if cmd == "scan" and arg[2] then
        moabi.scan(arg[2])
    
    elseif cmd == "report" and arg[2] then
        moabi.report(arg[2], arg[3])
    
    elseif cmd == "baseline" and arg[2] then
        moabi.create_baseline(arg[2], arg[3])
    
    elseif cmd == "verify" and arg[2] and arg[3] then
        moabi.verify_baseline(arg[2], arg[3])
    
    elseif cmd == "inject" and arg[2] and arg[3] and arg[4] then
        local offset = tonumber(arg[3])
        local size = tonumber(arg[4])
        moabi.inject_test(arg[2], offset, size)
    
    elseif cmd == "clean" and arg[2] then
        moabi.clean_test(arg[2])
    
    elseif cmd == "test-transient" and arg[2] and arg[3] and arg[4] then
        local offset = tonumber(arg[3])
        local size = tonumber(arg[4])
        moabi.test_transient(arg[2], offset, size)
    
    elseif cmd == "batch" and arg[2] then
        moabi.batch_scan(arg[2])
    
    elseif cmd == "caves" and arg[2] then
        moabi.find_caves(arg[2])
    
    else
        print_usage()
    end
end

-- Run if executed directly
if arg then
    main()
end

-- Export for use as module
return moabi
