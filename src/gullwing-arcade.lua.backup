#!/usr/bin/env luajit
--============================================================================
--  GULLWING ARCADE v1.0 — Assembly Golf Engine
--============================================================================

local SRC = "/mnt/d/moabi/src"
local REFLECT = SRC .. "/moabi-reflect.lua"

local LEVELS = {
    {
        id = 1,
        name = "Return 42",
        goal = "Make the program return the number 42",
        par = 2,
        hint = "Use mov eax, 42 followed by ret",
        template = "mov eax, 42\nret",
        check = function(exit_code) return exit_code == 42 end,
        teach = "Basic x86_64 assembly. Gullwing classifies small binaries as system_utility."
    },
    {
        id = 2,
        name = "Print 'hi'",
        goal = "Print the string 'hi' to stdout",
        par = 6,
        hint = "Use syscall 1 (write) with rdi=1 (stdout)",
        template = "mov rax, 1\nmov rdi, 1\nlea rsi, [rel msg]\nmov rdx, 2\nsyscall\nmov eax, 60\nxor edi, edi\nsyscall\nsection .data\nmsg: db 'hi'",
        check = function(output) return output:find("hi") ~= nil end,
        teach = "Syscalls. Gullwing detects Libraries and imports via DT_NEEDED."
    },
    {
        id = 3,
        name = "Read a File",
        goal = "Open and read /etc/hostname",
        par = 12,
        hint = "Use syscall 2 (open), then syscall 0 (read), then syscall 1 (write)",
        template = "mov rax, 2\nlea rdi, [rel filename]\nxor esi, esi\nsyscall\nmov rdi, rax\nxor eax, eax\nlea rsi, [rel buf]\nmov rdx, 256\nsyscall\nmov rdx, rax\nmov rax, 1\nmov rdi, 1\nsyscall\nmov eax, 60\nxor edi, edi\nsyscall\nsection .data\nfilename: db '/etc/hostname', 0\nsection .bss\nbuf: resb 256",
        check = function(output) return #output > 0 end,
        teach = "File I/O. Gullwing's Runtime layer detects open/read/write syscalls."
    }
}

local function count_instructions(code)
    local count = 0
    for line in code:gmatch("[^\n]+") do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" and not trimmed:match("^;") and not trimmed:match("^section") then
            count = count + 1
        end
    end
    return count
end

local function compile_and_run(code, level)
    local dir = "/tmp/golf_" .. os.time()
    os.execute("mkdir -p " .. dir)
    
    -- Write assembly
    local asm = io.open(dir .. "/golf.asm", "w")
    asm:write("section .text\nglobal _start\n_start:\n" .. code .. "\n")
    asm:close()
    
    -- Compile
    local ok = os.execute("nasm -f elf64 " .. dir .. "/golf.asm -o " .. dir .. "/golf.o 2>/dev/null")
    if ok ~= 0 then
        return { error = "Assembly failed. Check your syntax." }
    end
    
    ok = os.execute("ld " .. dir .. "/golf.o -o " .. dir .. "/golf 2>/dev/null")
    if ok ~= 0 then
        return { error = "Linking failed." }
    end
    
    -- Run and capture output
    local h = io.popen(dir .. "/golf 2>&1; echo EXIT:$?")
    local full_output = h:read("*a")
    h:close()
    
    local output = full_output:gsub("EXIT:%d+\n$", "")
    local exit_code = tonumber(full_output:match("EXIT:(%d+)")) or -1
    
    -- Run Gullwing
    os.execute("luajit " .. REFLECT .. " " .. dir .. "/golf --static-only --json 2>/dev/null")
    
    local evidence = ""
    local f = io.open("/mnt/d/moabi/reports/golf.evidence.json")
    if f then evidence = f:read("*a"); f:close() end
    
    -- Parse Gullwing results
    local class = evidence:match('"class":"([^"]+)"') or "?"
    local risk = evidence:match('"risk_tier":"([^"]+)"') or "?"
    local size = evidence:match('"size":(%d+)') or "0"
    local entropy = evidence:match('"global":([%d%.]+)') or "0"
    
    -- Cleanup
    os.execute("rm -rf " .. dir)
    
    local instructions = count_instructions(code)
    local passed = level.check(level.id == 1 and exit_code or output)
    local stars = 0
    if passed and instructions <= level.par then
        stars = level.par - instructions + 1
    end
    
    return {
        passed = passed,
        exit_code = exit_code,
        output = output:sub(1, 200),
        instructions = instructions,
        par = level.par,
        stars = stars,
        class = class,
        risk = risk,
        size = size,
        entropy = entropy,
        teach = level.teach,
    }
end

-- API mode: print JSON for frontend
if arg[1] == "api" then
    local json = require("json")
    local level_id = tonumber(arg[2]) or 1
    local code = arg[3] or ""
    local level = LEVELS[level_id]
    if not level then
        print(json.encode({error = "Invalid level"}))
        os.exit(1)
    end
    local result = compile_and_run(code, level)
    result.level = level.name
    result.goal = level.goal
    print(json.encode(result))
    os.exit(0)
end

-- CLI mode
local function usage()
    print("GULLWING ARCADE — Assembly Golf")
    print()
    print("Levels:")
    for _, l in ipairs(LEVELS) do
        print(string.format("  %d. %s (par: %d)", l.id, l.name, l.par))
    end
    print()
    print("Play: gullwing arcade <level>")
    print("  Write your assembly, type 'done' on a new line, then Ctrl+D")
end

if not arg[1] or arg[1] == "help" then
    usage()
    os.exit(0)
end

local level = LEVELS[tonumber(arg[1])]
if not level then
    print("Invalid level. Choose 1-" .. #LEVELS)
    os.exit(1)
end

print(string.rep("=", 50))
print("  ASSEMBLY GOLF — Level " .. level.id .. ": " .. level.name)
print(string.rep("=", 50))
print("Goal: " .. level.goal)
print("Par:  " .. level.par .. " instructions")
print("Hint: " .. level.hint)
print()
print("Template:")
print("  " .. level.template:gsub("\n", "\n  "))
print()
print("Enter your assembly (type 'done' on a new line, then Enter):")

local lines = {}
while true do
    local line = io.read("*l")
    if line == "done" then break end
    lines[#lines + 1] = line
end

local code = table.concat(lines, "\n")
print()
print("Compiling and analyzing...")
local result = compile_and_run(code, level)

if result.error then
    print("❌ " .. result.error)
    os.exit(1)
end

print(string.rep("=", 50))
print("  RESULTS")
print(string.rep("=", 50))
print(string.format("  Status:       %s", result.passed and "✅ PASSED" or "❌ FAILED"))
print(string.format("  Instructions: %d (par: %d)", result.instructions, level.par))
if result.stars > 0 then
    print(string.format("  Stars:        %s", string.rep("⭐", result.stars)))
end
print()
print("  [Gullwing Analysis]")
print(string.format("  Class:        %s", result.class))
print(string.format("  Risk:         %s", result.risk))
print(string.format("  Size:         %s bytes", result.size))
print(string.format("  Entropy:      %s", result.entropy))
print()
print("  📖 " .. result.teach)
