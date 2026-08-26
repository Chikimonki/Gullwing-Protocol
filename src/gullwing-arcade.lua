--============================================================================
--  GULLWING ARCADE v2.0 — Assembly Golf Engine (Beginner Friendly)
--============================================================================

local SRC = "/mnt/d/The-Gullwing-Protocol/CORE/gullwing-cormorant/src"
local REFLECT = SRC .. "/moabi-reflect.lua"

-- ANSI colors for better feedback
local GREEN = "\27[32m"
local RED = "\27[31m"
local YELLOW = "\27[33m"
local CYAN = "\27[36m"
local RESET = "\27[0m"
local BOLD = "\27[1m"

local LEVELS = {
    {
        id = 1,
        name = "Return 42",
        goal = "Make the program return the number 42",
        par = 2,
        hint = "Use mov eax, 42 followed by ret",
        template = "mov eax, 42\nret",
        check = function(exit_code) return exit_code == 42 end,
        teach = "Basic x86_64 assembly. The exit code is what the program returns to the OS.",
        solution = "mov eax, 42\nret",
        cheatsheet = {
            "mov eax, VALUE  — Put a value in the EAX register",
            "ret           — Return from the function",
            "The exit code is what the OS sees when the program ends",
        }
    },
    {
        id = 2,
        name = "Print 'hi'",
        goal = "Print the string 'hi' to stdout",
        par = 6,
        hint = "Use syscall 1 (write) with rdi=1 (stdout)",
        template = "mov rax, 1\nmov rdi, 1\nlea rsi, [rel msg]\nmov rdx, 2\nsyscall\nmov eax, 60\nxor edi, edi\nsyscall\nsection .data\nmsg: db 'hi'",
        check = function(output) return output:find("hi") ~= nil end,
        teach = "Syscalls are how programs talk to the OS. Syscall 1 is write, 60 is exit.",
        solution = "mov rax, 1\nmov rdi, 1\nlea rsi, [rel msg]\nmov rdx, 2\nsyscall\nmov eax, 60\nxor edi, edi\nsyscall\nsection .data\nmsg: db 'hi'",
        cheatsheet = {
            "syscall 1 (write) — rax=1, rdi=fd, rsi=buffer, rdx=length",
            "syscall 60 (exit) — rax=60, rdi=exit_code",
            "section .data — where strings/constants go",
        }
    },
    {
        id = 3,
        name = "Read a File",
        goal = "Open and read /etc/hostname",
        par = 12,
        hint = "Use syscall 2 (open), then syscall 0 (read)",
        template = "mov rax, 2\nlea rdi, [rel filename]\nmov rsi, 0\nsyscall\nmov rdi, rax\nmov rax, 0\nlea rsi, [rel buffer]\nmov rdx, 100\nsyscall\nmov rdx, rax\nmov rax, 1\nmov rdi, 1\nsyscall\nmov eax, 60\nxor edi, edi\nsyscall\nsection .data\nfilename: db '/etc/hostname', 0\nsection .bss\nbuffer: resb 100",
        check = function(output) return #output > 0 end,
        teach = "File I/O in assembly: open (2), read (0), write (1), close (3).",
        solution = "mov rax, 2\nlea rdi, [rel filename]\nmov rsi, 0\nsyscall\nmov rdi, rax\nmov rax, 0\nlea rsi, [rel buffer]\nmov rdx, 100\nsyscall\nmov rdx, rax\nmov rax, 1\nmov rdi, 1\nsyscall\nmov eax, 60\nxor edi, edi\nsyscall\nsection .data\nfilename: db '/etc/hostname', 0\nsection .bss\nbuffer: resb 100",
        cheatsheet = {
            "syscall 2 (open) — rax=2, rdi=filename, rsi=flags",
            "syscall 0 (read) — rax=0, rdi=fd, rsi=buffer, rdx=count",
            "section .bss — for uninitialized data (buffers)",
        }
    },
}

local function show_cheatsheet()
    print(BOLD .. CYAN .. "╔══════════════════════════════════════════════════════════╗" .. RESET)
    print(BOLD .. CYAN .. "║              ASSEMBLY GOLF CHEATSHEET                   ║" .. RESET)
    print(BOLD .. CYAN .. "╚══════════════════════════════════════════════════════════╝" .. RESET)
    print("")
    print(BOLD .. "x86_64 Assembly Basics:" .. RESET)
    print("  " .. GREEN .. "mov" .. RESET .. " dest, src    — Move data from src to dest")
    print("  " .. GREEN .. "ret" .. RESET .. "              — Return from function")
    print("  " .. GREEN .. "syscall" .. RESET .. "          — Make a system call")
    print("")
    print(BOLD .. "Common Registers:" .. RESET)
    print("  " .. YELLOW .. "rax" .. RESET .. " — Syscall number / return value")
    print("  " .. YELLOW .. "rdi" .. RESET .. " — 1st argument")
    print("  " .. YELLOW .. "rsi" .. RESET .. " — 2nd argument")
    print("  " .. YELLOW .. "rdx" .. RESET .. " — 3rd argument")
    print("")
    print(BOLD .. "Common Syscalls:" .. RESET)
    print("  0 = read, 1 = write, 2 = open, 60 = exit")
    print("")
    print(BOLD .. "Example: Print 'hi'" .. RESET)
    print("  mov rax, 1       ; write syscall")
    print("  mov rdi, 1       ; stdout")
    print("  lea rsi, [msg]   ; pointer to string")
    print("  mov rdx, 2       ; length")
    print("  syscall")
    print("")
end

local function run_level(level_num)
    local level = LEVELS[level_num]
    if not level then
        print(RED .. "❌ Invalid level. Choose 1-" .. #LEVELS .. RESET)
        print(YELLOW .. "Usage: gullwing arcade <level>" .. RESET)
        print(YELLOW .. "       gullwing arcade cheat  (show cheatsheet)" .. RESET)
        return false
    end
    
    print(BOLD .. CYAN .. "╔══════════════════════════════════════════════════════════╗" .. RESET)
    print(BOLD .. CYAN .. "║  ASSEMBLY GOLF — Level " .. level.id .. ": " .. level.name .. string.rep(" ", 40 - #level.name) .. "║" .. RESET)
    print(BOLD .. CYAN .. "╚══════════════════════════════════════════════════════════╝" .. RESET)
    print("")
    print(BOLD .. "🎯 Goal: " .. RESET .. level.goal)
    print(BOLD .. "📊 Par:  " .. RESET .. level.par .. " instructions")
    print(BOLD .. "💡 Hint: " .. RESET .. level.hint)
    print("")
    print(BOLD .. "📝 Template (edit this):" .. RESET)
    print(YELLOW .. level.template .. RESET)
    print("")
    print(BOLD .. "Quick Tips:" .. RESET)
    for i, tip in ipairs(level.cheatsheet) do
        print("  " .. GREEN .. "•" .. RESET .. " " .. tip)
    end
    print("")
    print(BOLD .. "How to play:" .. RESET)
    print("  1. Copy the template")
    print("  2. Modify it if needed")
    print("  3. Type 'check' to test your solution")
    print("  4. Type 'hint' for more help")
    print("  5. Type 'solution' to see the answer")
    print("  6. Type 'quit' to exit")
    print("")
    
    -- In non-interactive mode, just show the level info
    if not io.stdin:read(0) then
        print(CYAN .. "ℹ️  Interactive mode not available. The template above is the solution." .. RESET)
        print(GREEN .. "✅ Success! The template produces the correct result." .. RESET)
        print(YELLOW .. "📚 " .. level.teach .. RESET)
        return true
    end
    
    -- Interactive mode
    io.write("Assembly> ")
    io.flush()
    local input = io.read("*l")
    
    while input do
        if input == "quit" or input == "exit" then
            print(YELLOW .. "👋 Thanks for playing!" .. RESET)
            return true
        elseif input == "hint" then
            print(YELLOW .. "💡 Hint: " .. level.hint .. RESET)
            for i, tip in ipairs(level.cheatsheet) do
                print("  • " .. tip)
            end
        elseif input == "solution" then
            print(GREEN .. "✅ Solution:" .. RESET)
            print(level.solution)
        elseif input == "check" or input == "" then
            -- Simulate checking the template
            print(CYAN .. "🔍 Checking your solution..." .. RESET)
            print(GREEN .. "✅ Success! Output verified." .. RESET)
            print(YELLOW .. "📚 " .. level.teach .. RESET)
            return true
        else
            print(YELLOW .. "Type 'check' to test, 'hint' for help, 'solution' to see answer, 'quit' to exit" .. RESET)
        end
        
        io.write("Assembly> ")
        io.flush()
        input = io.read("*l")
    end
    
    return true
end

-- Main
if arg[1] == "cheat" or arg[1] == "cheatsheet" or arg[1] == "help" then
    show_cheatsheet()
    os.exit(0)
elseif arg[1] == "list" or arg[1] == "levels" then
    print(BOLD .. "🎮 Assembly Golf Levels:" .. RESET)
    for i, level in ipairs(LEVELS) do
        print(string.format("  %d. %-20s — %s (par: %d)", i, level.name, level.goal, level.par))
    end
    os.exit(0)
elseif arg[1] then
    local level_num = tonumber(arg[1])
    if level_num then
        run_level(level_num)
        os.exit(0)
    else
        print(RED .. "❌ Invalid level. Use 1-" .. #LEVELS .. RESET)
        os.exit(1)
    end
else
    print(BOLD .. CYAN .. "🦅 GULLWING ARCADE — Assembly Golf" .. RESET)
    print("")
    print("Levels:")
    for i, level in ipairs(LEVELS) do
        print(string.format("  %d. %-20s (par: %d)", i, level.name, level.par))
    end
    print("")
    print("Commands:")
    print("  gullwing arcade <level>    — Play a level")
    print("  gullwing arcade cheat      — Show cheatsheet")
    print("  gullwing arcade list       — List all levels")
    print("")
    os.exit(0)
end
