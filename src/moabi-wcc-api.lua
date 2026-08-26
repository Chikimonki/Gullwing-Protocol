#!/usr/bin/env luajit
--============================================================================
--  MOABI-WCC-API v1.0 — WCC + WSH Standalone API Server
--  Port 9394 — PE→ELF, Punk-C Interrogation, Libify
--============================================================================

local SRC = "/mnt/d/moabi/src"
local REFLECT = SRC .. "/moabi-reflect.lua"
local MODEL_PATH = "/mnt/d/moabi/reports/system.model"
local PORT = 9394

package.path = SRC .. "/?.lua;" .. package.path
package.cpath = "/usr/lib/x86_64-linux-gnu/lua/5.1/?.so;" .. package.cpath
package.path = "/usr/share/lua/5.1/?.lua;" .. package.path
local socket = require("socket")
local json = require("json")

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function file_exists(p) local f=io.open(p,"rb"); if f then f:close() return true end; return false end
local function url_decode(s) return s:gsub("+", " "):gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end) end

-- ============================================================================
--  HANDLER: WCC Cross-Format Compile (PE → ELF)
-- ============================================================================

local function handle_wcc_compile(params)
    local target = params.path or params.target
    if not target or target == "" then return 400, json.encode({error="missing path"}) end
    
    local name = target:match("([^/]+)$") or "unknown"
    local output = "/tmp/" .. name .. ".elf"
    
    local cmd = string.format("wcc -c %s -o %s 2>&1", shq(target), shq(output))
    local h = io.popen(cmd)
    local wcc_out = h:read("*a")
    h:close()
    
    if not file_exists(output) then
        return 500, json.encode({error="wcc compilation failed", output=wcc_out:sub(1, 500)})
    end
    
    -- Run Gullwing on the ELF
    os.execute("luajit " .. shq(REFLECT) .. " " .. shq(output) .. " --static-only --json --model " .. shq(MODEL_PATH) .. " 2>/dev/null")
    
    local evidence = nil
    local f = io.open("/mnt/d/moabi/reports/" .. name .. ".elf.evidence.json")
    if f then
        local ok, ev = pcall(json.decode, f:read("*a"))
        if ok then evidence = ev end
        f:close()
    end
    
    return 200, json.encode({
        original = target,
        compiled = output,
        format = "PE→ELF",
        size = file_exists(output) and io.open(output):seek("end") or 0,
        evidence = evidence,
    })
end

-- ============================================================================
--  HANDLER: WCC Libify (binary → shared library)
-- ============================================================================

local function handle_wcc_libify(params)
    local target = params.path or params.target
    if not target or target == "" then return 400, json.encode({error="missing path"}) end
    
    local name = target:match("([^/]+)$") or "unknown"
    local libified = "/tmp/" .. name .. ".so"
    local header = "/tmp/" .. name .. ".h"
    
    os.execute("cp " .. shq(target) .. " " .. shq(libified) .. " 2>/dev/null")
    os.execute("wld -libify " .. shq(libified) .. " 2>/dev/null")
    os.execute("wcch " .. shq(libified) .. " > " .. shq(header) .. " 2>/dev/null")
    
    local funcs = {}
    local nm = io.popen("nm -D " .. shq(libified) .. " 2>/dev/null | grep ' T ' | head -30")
    if nm then
        for line in nm:lines() do
            local func = line:match(" T (.+)$")
            if func then funcs[#funcs+1] = func end
        end
        nm:close()
    end
    
    local flags = ""
    local fh = io.popen("wldd " .. shq(target) .. " 2>&1")
    if fh then flags = fh:read("*a"):gsub("%s+$", ""); fh:close() end
    
    return 200, json.encode({
        original = target,
        libified = libified,
        header_file = header,
        functions = funcs,
        function_count = #funcs,
        build_flags = flags,
        punk_c = "wsh " .. libified,
    })
end

-- ============================================================================
--  HANDLER: WSH Interactive Interrogation
-- ============================================================================

local function handle_wsh(params)
    local target = params.path or params.target
    local command = params.cmd or "help"
    
    if not target then return 400, json.encode({error="missing path"}) end
    
    local name = target:match("([^/]+)$") or "unknown"
    local libified = "/tmp/" .. name .. ".so"
    
    if not file_exists(libified) then
        os.execute("cp " .. shq(target) .. " " .. shq(libified) .. " 2>/dev/null")
        os.execute("wld -libify " .. shq(libified) .. " 2>/dev/null")
    end
    
    local wsh_cmd = string.format("echo '%s' | wsh %s 2>/dev/null", command:gsub("'", "'\\''"), shq(libified))
    local h = io.popen(wsh_cmd)
    local output = h:read("*a")
    h:close()
    
    -- Strip ANSI escape codes
    output = output:gsub("\27%[[0-9;]*[a-zA-Z]", "")
    
    return 200, json.encode({
        target = target,
        libified = libified,
        command = command,
        output = output,
    })
end

-- ============================================================================
--  HANDLER: WCC Deep Functions (via WSH)
-- ============================================================================

local function handle_wcc_deep(params)
    local target = params.path or params.target
    if not target or target == "" then return 400, json.encode({error="missing path"}) end
    
    local name = target:match("([^/]+)$") or "unknown"
    local libified = "/tmp/" .. name .. ".so"
    
    os.execute("cp " .. shq(target) .. " " .. shq(libified) .. " 2>/dev/null")
    os.execute("wld -libify " .. shq(libified) .. " 2>/dev/null")
    
    local h = io.popen("echo 'functions()' | wsh " .. shq(libified) .. " 2>/dev/null")
    local output = h:read("*a")
    h:close()
    
    local total = tonumber(output:match("(%d+) functions matched") or "0")
    local funcs = {}
    for line in output:gmatch("[^\n]+") do
        local lib, func = line:match("^(%S+%.[%w%.]+)%s+(%S+)%s+Function")
        if lib and func and #funcs < 200 then
            funcs[#funcs+1] = {library = lib:match("([^/]+)$") or lib, name = func}
        end
    end
    
    return 200, json.encode({
        libified = libified,
        total_functions = total,
        functions = funcs,
        note = "wsh " .. libified,
    })
end

-- ============================================================================
--  SERVER
-- ============================================================================

local function respond(client, code, body)
    client:send(string.format("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", code, code==200 and "OK" or "Error", #body, body))
    client:close()
end

local function start()
    local server = socket.tcp()
    server:setoption("reuseaddr", true)
    assert(server:bind("127.0.0.1", PORT))
    server:listen(10)
    print(string.format("WCC-API v1.0 — http://127.0.0.1:%d", PORT))
    print("  POST /compile    — PE→ELF via wcc")
    print("  POST /libify     — Binary → shared library")
    print("  POST /wsh        — Punk-C interactive interrogation")
    print("  POST /deep       — All callable functions via WSH")
    
    while true do
        local client = server:accept()
        if client then
            client:settimeout(5)
            local line = client:receive("*l")
            if line then
                local method, path = line:match("^(%S+)%s+(%S+)")
                local clen = 0
                while true do
                    local hdr = client:receive("*l")
                    if not hdr or hdr == "" then break end
                    local cl = hdr:match("^Content%-Length:%s+(%d+)")
                    if cl then clen = tonumber(cl) end
                end
                local body = clen > 0 and (client:receive(clen) or "") or ""
                local params = {}
                for k,v in body:gmatch("([^&=]+)=([^&]*)") do params[url_decode(k)] = url_decode(v) end
                
                local code, resp = 404, json.encode({error="not found"})
                if path == "/compile" and method == "POST" then code, resp = handle_wcc_compile(params)
                elseif path == "/libify" and method == "POST" then code, resp = handle_wcc_libify(params)
                elseif path == "/wsh" and method == "POST" then code, resp = handle_wsh(params)
                elseif path == "/deep" and method == "POST" then code, resp = handle_wcc_deep(params)
                end
                respond(client, code, resp)
            else
                client:close()
            end
        end
    end
end

start()
