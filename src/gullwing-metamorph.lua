#!/usr/bin/env luajit
--============================================================================
--  GULLWING-METAMORPH v1.0 — Opcode Graph Similarity Engine
--  Detects metamorphic malware by normalizing opcode sequences.
--============================================================================

local SRC = "/mnt/d/moabi/src"
local REFLECT = SRC .. "/moabi-reflect.lua"

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

-- Opcode categories for normalization (x86_64)
local OPCODE_CATEGORIES = {
    MOV = "data_transfer",
    PUSH = "stack",
    POP = "stack",
    CALL = "control_flow",
    RET = "control_flow",
    JMP = "control_flow",
    JE = "control_flow",
    JNE = "control_flow",
    JG = "control_flow",
    JL = "control_flow",
    JGE = "control_flow",
    JLE = "control_flow",
    CMP = "comparison",
    TEST = "comparison",
    ADD = "arithmetic",
    SUB = "arithmetic",
    MUL = "arithmetic",
    DIV = "arithmetic",
    XOR = "logic",
    AND = "logic",
    OR = "logic",
    NOT = "logic",
    SHL = "shift",
    SHR = "shift",
    LEA = "address",
    NOP = "noise",
    INT = "interrupt",
    SYSCALL = "syscall",
}

local function categorize(opcode)
    return OPCODE_CATEGORIES[opcode:upper()] or "other"
end

local function extract_opcode_sequence(target)
    -- Use objdump to disassemble
    local cmd = string.format("objdump -d %s 2>/dev/null | grep -E '^\\s+[0-9a-f]+:' | awk '{print $2}' | head -500",
        shq(target))
    local h = io.popen(cmd)
    local opcodes = {}
    for line in h:lines() do
        local op = line:match("^([a-z]+)")
        if op and #op >= 2 then
            opcodes[#opcodes + 1] = categorize(op)
        end
    end
    h:close()
    return opcodes
end

local function build_bigram_profile(opcodes)
    local profile = {}
    for i = 1, #opcodes - 1 do
        local bigram = opcodes[i] .. "->" .. opcodes[i+1]
        profile[bigram] = (profile[bigram] or 0) + 1
    end
    return profile
end

local function profile_similarity(p1, p2)
    -- Jaccard-like similarity on bigrams
    local intersection, union = 0, 0
    local all_keys = {}
    for k in pairs(p1) do all_keys[k] = true end
    for k in pairs(p2) do all_keys[k] = true end
    
    for k in pairs(all_keys) do
        local v1 = p1[k] or 0
        local v2 = p2[k] or 0
        intersection = intersection + math.min(v1, v2)
        union = union + math.max(v1, v2)
    end
    
    return union > 0 and (intersection / union) * 100 or 0
end

local function usage()
    print("GULLWING-METAMORPH v1.0 — Opcode Graph Similarity")
    print("Usage: gullwing metamorph <binary1> <binary2>")
    print("       gullwing metamorph <binary>               (profile only)")
    print()
    print("Compares opcode bigram profiles to detect metamorphic variants.")
end

local function main()
    if not arg[1] or arg[1] == "-h" then usage(); return 0 end
    
    local target1 = arg[1]
    local target2 = arg[2]
    
    print("GULLWING-METAMORPH: Opcode Graph Similarity")
    print()
    
    print("  [1/2] Extracting opcode sequence from: " .. target1)
    local opcodes1 = extract_opcode_sequence(target1)
    local profile1 = build_bigram_profile(opcodes1)
    print(string.format("  Extracted %d opcodes, %d unique bigrams", #opcodes1, table.getn(profile1)))
    
    -- Show category distribution
    local cats1 = {}
    for _, op in ipairs(opcodes1) do cats1[op] = (cats1[op] or 0) + 1 end
    print("  Category distribution:")
    for cat, count in pairs(cats1) do
        print(string.format("    %-15s %d (%.1f%%)", cat, count, count/#opcodes1*100))
    end
    
    if target2 then
        print()
        print("  [2/2] Extracting opcode sequence from: " .. target2)
        local opcodes2 = extract_opcode_sequence(target2)
        local profile2 = build_bigram_profile(opcodes2)
        print(string.format("  Extracted %d opcodes, %d unique bigrams", #opcodes2, table.getn(profile2)))
        
        local similarity = profile_similarity(profile1, profile2)
        print()
        local line = string.rep("=", 64)
        print(line)
        print(string.format("  BIGRAM SIMILARITY: %.1f%%", similarity))
        if similarity > 80 then
            print("  VERDICT: LIKELY METAMORPHIC VARIANT — High opcode similarity")
        elseif similarity > 50 then
            print("  VERDICT: POSSIBLE VARIANT — Moderate similarity")
        else
            print("  VERDICT: DIFFERENT FAMILIES — Low similarity")
        end
        print(line)
    end
    
    return 0
end

main()
