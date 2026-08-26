-- Entropy Hunter: Identify packed/obfuscated binaries
-- Teaches the entropy layer from Gullwing's 8-layer analysis

local EntropyHunter = {
    binaries = {
        {
            name = "normal_ls",
            entropy = 5.2,
            packed = false,
            hint = "Normal system binaries have entropy around 5-6 bits/byte",
        },
        {
            name = "packed_malware",
            entropy = 7.8,
            packed = true,
            hint = "Packed binaries often have entropy above 7 bits/byte",
        },
        {
            name = "obfuscated_tool",
            entropy = 7.5,
            packed = true,
            hint = "Encrypted or compressed code pushes entropy higher",
        },
        {
            name = "text_document",
            entropy = 3.1,
            packed = false,
            hint = "Plain text has low entropy — lots of repetition",
        },
    },
}

-- Display function
print("📊 ENTROPY HUNTER — Identify Packed Binaries")
print("")
print("Challenge: Determine if each binary is packed or normal based on entropy.")
print("")
print("Binaries:")
for i, binary in ipairs(EntropyHunter.binaries) do
    local status = binary.packed and "PACKED" or "NORMAL"
    print(string.format("  %d. %s", i, binary.name))
    print(string.format("     Entropy: %.1f bits/byte", binary.entropy))
    print(string.format("     Status: %s", status))
    print(string.format("     Hint: %s", binary.hint))
    print("")
end

print("How to play: Use entropy values to identify suspicious binaries.")
print("High entropy (>7) often indicates packing or encryption.")
print("This is a key layer in Gullwing's 8-layer convergent analysis.")
