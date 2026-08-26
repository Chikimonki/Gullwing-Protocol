-- Fleet Commander: Distributed system monitoring
-- Teaches fleet management with Headscale

local FleetCommander = {
    nodes = {
        {
            name = "node-alpha",
            status = "HEALTHY",
            risk = "CLEAR",
            note = "All systems nominal",
        },
        {
            name = "node-beta",
            status = "SUSPICIOUS",
            risk = "WARNING",
            note = "Unexpected binary change detected",
        },
        {
            name = "node-gamma",
            status = "COMPROMISED",
            risk = "CRITICAL",
            note = "RWX memory detected, quarantine initiated",
        },
    },
}

-- Display function
print("🌐 FLEET COMMANDER — Distributed System Monitoring")
print("")
print("Fleet Status:")
for i, node in ipairs(FleetCommander.nodes) do
    local risk_color = node.risk == "CLEAR" and "✅" or (node.risk == "WARNING" and "⚠️" or "🚨")
    print(string.format("  %s %s", risk_color, node.name))
    print(string.format("     Status: %s", node.status))
    print(string.format("     Risk: %s", node.risk))
    print(string.format("     Note: %s", node.note))
    print("")
end

print("How to play: Monitor the fleet and respond to security events.")
print("This teaches real-time fleet management using Headscale and Cormorant Bus.")
print("Alerts flow from Gullwing → Bus → Dashboard in microseconds.")
