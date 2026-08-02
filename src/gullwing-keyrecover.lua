#!/usr/bin/env luajit
--============================================================================
--  GULLWING-KEYRECOVER v1.0 — Encrypted Capsule Key Recovery
--  Finds hardcoded keys, crypto constants, and key derivation in firmware.
--============================================================================

local SRC = "/mnt/d/moabi/src"

local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

-- Known crypto constants for identification
local CRYPTO_CONSTANTS = {
    -- AES S-box (first 16 bytes of the forward S-box)
    { name = "AES_SBOX", pattern = "\099\124\119\123\242\107\111\197\050\001\006\005\009\013\014\002", min_len = 16 },
    -- AES Inverse S-box
    { name = "AES_INV_SBOX", pattern = "\082\009\106\213\048\054\165\056\191\064\163\158\129\243\215\251", min_len = 16 },
    -- RSA public exponent (65537 = 0x010001)
    { name = "RSA_EXPONENT_65537", pattern = "\001\000\001", min_len = 3 },
    -- MD5 initialization constants
    { name = "MD5_INIT", pattern = "\001\035\069\071\137\171\205\239\254\220\186\152\118\084\050\016", min_len = 16 },
    -- SHA256 initial hash values (first 8 bytes)
    { name = "SHA256_INIT", pattern = "\106\009\230\102\190\225\042\209", min_len = 8 },
}

-- Common key patterns
local KEY_PATTERNS = {
    { name = "hex_key_16", pattern = "^[0-9a-fA-F]{32}$" },
    { name = "hex_key_32", pattern = "^[0-9a-fA-F]{64}$" },
    { name = "base64_key", pattern = "^[A-Za-z0-9+/]{24,}={0,2}$" },
}

local function scan_crypto_constants(data, size)
    local findings = {}
    
    for _, constant in ipairs(CRYPTO_CONSTANTS) do
        local pos = 1
        while pos <= size - constant.min_len do
            if data:sub(pos, pos + constant.min_len - 1) == constant.pattern then
                findings[#findings + 1] = {
                    type = "crypto_constant",
                    name = constant.name,
                    offset = pos - 1,
                    size = constant.min_len,
                }
                pos = pos + 1
            else
                pos = pos + 1
            end
        end
    end
    
    return findings
end

local function scan_key_patterns(data, size)
    local findings = {}
    
    -- Extract printable strings and test against key patterns
    local current = ""
    for i = 1, size do
        local b = data:byte(i)
        if b >= 0x20 and b <= 0x7e then
            current = current .. string.char(b)
        else
            if #current >= 16 then
                for _, kp in ipairs(KEY_PATTERNS) do
                    if current:match(kp.pattern) then
                        findings[#findings + 1] = {
                            type = "potential_key",
                            name = kp.name,
                            offset = i - #current - 1,
                            value = current:sub(1, 64) .. (#current > 64 and "..." or ""),
                            length = #current,
                        }
                        break
                    end
                end
            end
            current = ""
        end
    end
    
    return findings
end

local function scan_entropy_regions(data, size)
    -- Find high-entropy regions that might be encrypted data
    local findings = {}
    local window = 256
    
    for start_pos = 1, size - window, 64 do
        local hist = {}
        for i = 0, 255 do hist[i] = 0 end
        for i = start_pos, start_pos + window - 1 do
            if i <= size then
                hist[data:byte(i)] = (hist[data:byte(i)] or 0) + 1
            end
        end
        
        -- Calculate Shannon entropy
        local entropy = 0
        for i = 0, 255 do
            if hist[i] > 0 then
                local p = hist[i] / window
                entropy = entropy - p * math.log(p, 2)
            end
        end
        
        if entropy > 7.5 then
            findings[#findings + 1] = {
                type = "high_entropy_region",
                name = "possible_encrypted_data",
                offset = start_pos - 1,
                size = window,
                entropy = entropy,
            }
        end
    end
    
    return findings
end

local function scan_der(data, size)
    -- Scan for DER/PEM encoded RSA/EC keys
    local findings = {}
    
    -- DER sequence header for private keys
    local der_seq = "\048\130"
    local pos = 1
    while pos <= size - 4 do
        if data:sub(pos, pos + 1) == der_seq then
            local len = data:byte(pos + 2) * 256 + data:byte(pos + 3)
            if len > 100 and len < 10000 then
                findings[#findings + 1] = {
                    type = "der_encoded_key",
                    name = "possible_private_key",
                    offset = pos - 1,
                    size = len + 4,
                }
            end
        end
        pos = pos + 1
    end
    
    return findings
end

local function usage()
    print("GULLWING-KEYRECOVER v1.0 — Encrypted Capsule Key Recovery")
    print("Usage: gullwing keyrecover <firmware_file>")
    print()
    print("Scans firmware for:")
    print("  - Crypto constants (AES S-box, RSA exponent, SHA/MD5 init)")
    print("  - Potential key strings (hex, base64)")
    print("  - High-entropy regions (possible encrypted data)")
    print("  - DER/PEM encoded keys")
end

local function main()
    if not arg[1] or arg[1] == "-h" then usage(); return 0 end
    
    local target = arg[1]
    local name = target:match("([^/]+)$") or target
    
    print("GULLWING-KEYRECOVER: " .. target)
    print()
    
    local f = io.open(target, "rb")
    if not f then
        io.stderr:write("Cannot open: " .. target .. "\n")
        return 1
    end
    local data = f:read("*a")
    f:close()
    local size = #data
    
    print(string.format("  File size: %d bytes (%.1f KB)", size, size / 1024))
    print()
    
    -- Run all scans
    print("  [1/4] Scanning for crypto constants...")
    local crypto_findings = scan_crypto_constants(data, size)
    print(string.format("  Found: %d", #crypto_findings))
    
    print("  [2/4] Scanning for key patterns...")
    local key_findings = scan_key_patterns(data, size)
    print(string.format("  Found: %d", #key_findings))
    
    print("  [3/4] Scanning for high-entropy regions...")
    local entropy_findings = scan_entropy_regions(data, size)
    print(string.format("  Found: %d", #entropy_findings))
    
    print("  [4/4] Scanning for DER/PEM keys...")
    local der_findings = scan_der(data, size)
    print(string.format("  Found: %d", #der_findings))
    
    -- Report
    local all_findings = {}
    for _, f in ipairs(crypto_findings) do all_findings[#all_findings+1] = f end
    for _, f in ipairs(key_findings) do all_findings[#all_findings+1] = f end
    for _, f in ipairs(entropy_findings) do all_findings[#all_findings+1] = f end
    for _, f in ipairs(der_findings) do all_findings[#all_findings+1] = f end
    
    print()
    local line = string.rep("=", 64)
    print(line)
    print(string.format("  KEY RECOVERY REPORT: %s", name))
    print(line)
    print(string.format("  Total findings: %d", #all_findings))
    print()
    
    if #all_findings > 0 then
        for i, finding in ipairs(all_findings) do
            if i <= 20 then
                print(string.format("  [%d] %s — %s", i, finding.type, finding.name))
                print(string.format("      Offset: 0x%x (%d)", finding.offset, finding.offset))
                if finding.entropy then
                    print(string.format("      Entropy: %.2f", finding.entropy))
                end
                if finding.value then
                    print(string.format("      Value: %s", finding.value:sub(1, 80)))
                end
                print()
            end
        end
        if #all_findings > 20 then
            print(string.format("  ... and %d more findings", #all_findings - 20))
        end
    else
        print("  No crypto artifacts found.")
        print("  The firmware may use proprietary encryption or keys are obfuscated.")
    end
    print(line)
    
    return 0
end

main()
