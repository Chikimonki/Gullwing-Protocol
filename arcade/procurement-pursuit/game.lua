-- Procurement Pursuit: Supply chain security decisions
-- Teaches CRA compliance and vendor risk assessment

local ProcurementPursuit = {
    scenarios = {
        {
            vendor = "Unknown vendor from internet",
            binary = "accounting_tool.exe",
            risk = "HIGH",
            reason = "No source, no attestation, no SBOM",
            action = "REJECT - Cannot verify supply chain",
        },
        {
            vendor = "Established vendor with SBOM",
            binary = "database_client.so",
            risk = "LOW",
            reason = "Full SBOM, Ed25519 attestation, known good hash",
            action = "ACCEPT - Verify attestation matches",
        },
        {
            vendor = "Vendor with incomplete documentation",
            binary = "reporting_tool",
            risk = "MEDIUM",
            reason = "Missing some dependencies in SBOM",
            action = "REVIEW - Request complete SBOM before deployment",
        },
    },
}

-- Display function
print("💰 PROCUREMENT PURSUIT — Supply Chain Security Decisions")
print("")
print("Scenarios:")
for i, scenario in ipairs(ProcurementPursuit.scenarios) do
    print(string.format("  Scenario %d:", i))
    print(string.format("    Vendor: %s", scenario.vendor))
    print(string.format("    Binary: %s", scenario.binary))
    print(string.format("    Risk: %s", scenario.risk))
    print(string.format("    Reason: %s", scenario.reason))
    print(string.format("    Action: %s", scenario.action))
    print("")
end

print("How to play: Evaluate vendor risk and make procurement decisions.")
print("This teaches CRA compliance - every binary needs verifiable provenance.")
print("Critical for September 11, 2026 CRA deadline compliance.")
