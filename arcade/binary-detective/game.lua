-- Binary Detective: Identify the binary from 8-layer clues
-- Teaches the full convergent analysis

local BinaryDetective = {
    cases = {
        {
            clues = {
                "ELF: true",
                "Class: ELF64",
                "Libraries: libc.so.6",
                "Entropy: 5.2",
                "ML: system_utility",
            },
            answer = "Standard Linux system utility",
            options = {"Linux system utility", "Windows malware", "Android app", "Firmware image"},
        },
        {
            clues = {
                "ELF: false",
                "PE: true",
                "Entropy: 7.8",
                "ML: suspicious",
                "Imports: kernel32.dll, ws2_32.dll",
            },
            answer = "Packed Windows executable",
            options = {"Packed Windows executable", "Linux daemon", "Database file", "Image file"},
        },
        {
            clues = {
                "ELF: true",
                "Class: ELF64",
                "Libraries: libssl.so.3, libcrypto.so.3",
                "Entropy: 6.1",
                "ML: network_tool",
            },
            answer = "Encrypted network utility",
            options = {"Encrypted network utility", "Text editor", "Image viewer", "Database server"},
        },
    },
}

-- Display function
print("🔍 BINARY DETECTIVE — Identify the Binary from Clues")
print("")
print("Cases:")
for i, case in ipairs(BinaryDetective.cases) do
    print(string.format("  Case %d:", i))
    for _, clue in ipairs(case.clues) do
        print(string.format("    • %s", clue))
    end
    print("")
    print("  Options:")
    for j, option in ipairs(case.options) do
        print(string.format("    %d. %s", j, option))
    end
    print(string.format("  Answer: %s", case.answer))
    print("")
end

print("How to play: Examine the 8-layer analysis clues and identify the binary.")
print("This teaches the convergent analysis methodology used by Gullwing.")
