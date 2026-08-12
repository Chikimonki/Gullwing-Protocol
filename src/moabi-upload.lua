#!/usr/bin/env luajit
--============================================================================
--  MOABI-UPLOAD v1.0 — Drag & Drop Upload API (Port 9395)
--  Safeguards: size limit, magic byte check, auto-quarantine
--============================================================================

local SRC = "/mnt/d/moabi/src"
local REFLECT = SRC .. "/moabi-reflect.lua"
local MODEL_PATH = "/mnt/d/moabi/reports/system.model"
local PORT = 9395

package.path = SRC .. "/?.lua;" .. package.path
package.cpath = "/usr/lib/x86_64-linux-gnu/lua/5.1/?.so;" .. package.cpath
package.path = "/usr/share/lua/5.1/?.lua;" .. package.path
local socket = require("socket")
local json = require("json")

local MAX_SIZE = 100 * 1024 * 1024  -- 100MB

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function file_exists(p) local f=io.open(p,"rb"); if f then f:close() return true end; return false end

local function handle_upload(body)
    -- Safeguard 1: Size limit
    if #body > MAX_SIZE then
        return 413, json.encode({error="file too large", max_mb=100, size_mb=math.floor(#body/1024/1024)})
    end
    
    -- Safeguard 2: Magic byte check
    local magic = body:sub(1,4)
    local is_elf = (magic:byte(1)==0x7f and magic:byte(2)==0x45 and magic:byte(3)==0x4c and magic:byte(4)==0x46)
    local is_pe = (magic:sub(1,2) == "MZ")
    local is_zip = (magic:sub(1,4) == "PK\003\004")
    local is_pdf = (magic:sub(1,4) == "%PDF")
    
    if not is_elf and not is_pe and not is_zip and not is_pdf then
        return 415, json.encode({error="unsupported format", supported={"ELF","PE","ZIP","PDF"}})
    end
    
    -- Save to temp
    local filename = "upload_" .. os.time()
    local target_dir = "/tmp/gullwing_uploads"
    os.execute("mkdir -p " .. shq(target_dir))
    local target_path = target_dir .. "/" .. filename
    
    local f = io.open(target_path, "wb")
    if not f then return 500, json.encode({error="write failed"}) end
    f:write(body)
    f:close()
    
    -- Run Gullwing analysis
    os.execute("luajit " .. shq(REFLECT) .. " " .. shq(target_path) .. " --static-only --json --model " .. shq(MODEL_PATH) .. " 2>/dev/null")
    
    local n = filename
    local ep = "/mnt/d/moabi/reports/" .. n .. ".evidence.json"
    if not file_exists(ep) then
        return 500, json.encode({error="analysis failed"})
    end
    
    local evf = io.open(ep)
    local ev = json.decode(evf:read("*a"))
    evf:close()
    
    local c = ev.convergence or {}
    local ml = ev.ml or {}
    local id = ev.identity or {}
    
    -- Safeguard 3: Auto-quarantine if HOSTILE
    if c.risk_tier == "HOSTILE" then
        local qpath = "/mnt/d/moabi/reports/quarantine/" .. filename .. "." .. os.time()
        os.execute("mv " .. shq(target_path) .. " " .. shq(qpath))
        os.execute("chmod -x " .. shq(qpath) .. " 2>/dev/null")
    end
    
    return 200, json.encode({
        filename = filename,
        path = target_path,
        class = ml.class or "?",
        confidence = ml.confidence or 0,
        risk = c.risk_tier or "?",
        novelty = c.novelty_tier or "?",
        size = id.size or #body,
        sha256 = id.sha256 or "?",
        quarantined = c.risk_tier == "HOSTILE",
        signals = c.signals or {},
    })
end

-- Server
local function respond(client, code, body)
    client:send(string.format("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", code, code==200 and "OK" or "Error", #body, body))
    client:close()
end

local function start()
    local server = socket.tcp()
    server:setoption("reuseaddr", true)
    assert(server:bind("127.0.0.1", PORT))
    server:listen(10)
    print(string.format("UPLOAD-API v1.0 — http://127.0.0.1:%d", PORT))
    print("  POST /upload — Drag & drop binary analysis with safeguards")
    
    while true do
        local client = server:accept()
        if client then
            client:settimeout(10)
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
                
                if path == "/upload" and method == "POST" then
                    local code, resp = handle_upload(body)
                    respond(client, code, resp)
                elseif path == "/health" then
                    respond(client, 200, json.encode({status="ok"}))
                else
                    respond(client, 404, json.encode({error="not found"}))
                end
            else
                client:close()
            end
        end
    end
end

start()
