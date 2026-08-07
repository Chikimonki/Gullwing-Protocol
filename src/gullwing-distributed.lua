#!/usr/bin/env luajit
--============================================================================
--  GULLWING-DISTRIBUTED v1.0 — Multi-Node Analysis via Tailscale
--============================================================================

local SRC = "/mnt/d/moabi/src"
local API_PORT = 9393

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

local function get_fleet_nodes()
    local nodes = {}
    local h = io.popen("tailscale status 2>/dev/null")
    if h then
        for line in h:lines() do
            local ip, name, user, os = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
            if ip and name then
                nodes[#nodes + 1] = {
                    ip = ip,
                    name = name,
                    user = user or "?",
                    os = os or "?",
                }
            end
        end
        h:close()
    end
    return nodes
end

local function check_node(ip)
    local cmd = string.format("curl -s --connect-timeout 2 http://%s:%d/status 2>/dev/null", ip, API_PORT)
    local h = io.popen(cmd)
    local response = h:read("*a")
    h:close()
    
    if response and #response > 10 then
        local ok = pcall(function() return load("return " .. response)() end)
        if ok then return true, response end
    end
    return false, nil
end

local function remote_reflect(node_ip, target_path)
    local cmd = string.format(
        "curl -s -X POST --connect-timeout 10 http://%s:%d/reflect -d 'path=%s' 2>/dev/null",
        node_ip, API_PORT, target_path:gsub("'", "'\\''"))
    local h = io.popen(cmd)
    local response = h:read("*a")
    h:close()
    
    if response and #response > 10 then
        local ok, data = pcall(function() return load("return " .. response)() end)
        if ok and data then
            return data
        end
    end
    return nil
end

local function usage()
    print("GULLWING-DISTRIBUTED v1.0 — Multi-Node Analysis")
    print()
    print("Commands:")
    print("  gullwing distributed fleet              — List all nodes on tailnet")
    print("  gullwing distributed scan <path>        — Scan a binary on ALL nodes")
    print("  gullwing distributed send <node> <path> — Send analysis to specific node")
    print()
    print("Requires Tailscale and gullwing serve running on all nodes.")
end

local function cmd_fleet()
    local nodes = get_fleet_nodes()
    
    if #nodes == 0 then
        print("No nodes found on tailnet. Run 'tailscale up' on other devices.")
        return
    end
    
    print("GULLWING DISTRIBUTED FLEET")
    print()
    print(string.format("  Nodes: %d", #nodes))
    print()
    
    for _, node in ipairs(nodes) do
        local online, _ = check_node(node.ip)
        local status = online and "🟢 ONLINE" or "🔴 OFFLINE"
        print(string.format("  %-20s %-18s %s %s", node.name, node.ip, node.os, status))
    end
end

local function cmd_scan(target_path)
    local nodes = get_fleet_nodes()
    local online_nodes = {}
    
    print("GULLWING DISTRIBUTED SCAN: " .. target_path)
    print()
    
    -- Find online nodes
    for _, node in ipairs(nodes) do
        local online, _ = check_node(node.ip)
        if online then
            online_nodes[#online_nodes + 1] = node
        end
    end
    
    print(string.format("  Online nodes: %d / %d", #online_nodes, #nodes))
    print()
    
    if #online_nodes == 0 then
        print("  No online nodes available.")
        return
    end
    
    -- Run analysis on each online node
    for _, node in ipairs(online_nodes) do
        print(string.format("  [%s] Analyzing...", node.name))
        local result = remote_reflect(node.ip, target_path)
        if result then
            local evidence = result.evidence or result
            local ml = evidence.ml or {}
            local c = evidence.convergence or {}
            print(string.format("    Class: %s | Risk: %s | Confidence: %.1f%%",
                ml.class or "?", c.risk_tier or "?", ml.confidence or 0))
        else
            print("    Analysis failed")
        end
    end
    
    print()
    print("  Distributed scan complete.")
end

local function cmd_send(node_name, target_path)
    local nodes = get_fleet_nodes()
    local target_node = nil
    
    for _, node in ipairs(nodes) do
        if node.name == node_name or node.ip == node_name then
            target_node = node
            break
        end
    end
    
    if not target_node then
        io.stderr:write("Node not found: " .. node_name .. "\n")
        return
    end
    
    local online, _ = check_node(target_node.ip)
    if not online then
        io.stderr:write("Node offline: " .. target_node.name .. "\n")
        return
    end
    
    print(string.format("Sending analysis to %s (%s)...", target_node.name, target_node.ip))
    local result = remote_reflect(target_node.ip, target_path)
    
    if result then
        local evidence = result.evidence or result
        local ml = evidence.ml or {}
        local c = evidence.convergence or {}
        print(string.format("  Class: %s", ml.class or "?"))
        print(string.format("  Risk: %s | Confidence: %.1f%%", c.risk_tier or "?", ml.confidence or 0))
        print(string.format("  Node: %s", target_node.name))
    else
        print("  Analysis failed — check gullwing serve on remote node")
    end
end

local function main()
    local cmd = arg[1]
    
    if cmd == "fleet" then
        cmd_fleet()
    elseif cmd == "scan" and arg[2] then
        cmd_scan(arg[2])
    elseif cmd == "send" and arg[2] and arg[3] then
        cmd_send(arg[2], arg[3])
    else
        usage()
    end
end

main()
