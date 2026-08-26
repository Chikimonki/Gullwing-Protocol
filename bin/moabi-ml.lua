#!/usr/bin/env luajit
--[[
  MOABI-ML: Simple Binary Classifier
  
  Learns what "normal" binaries look like,
  then flags anomalies in unknown binaries.
  
  This is a Naive Bayes / statistical distance classifier.
  Not deep learning — but the same concept Brossard started with.
]]

local ffi = require("ffi")
local math = require("math")

ffi.cdef[[
    typedef struct FILE FILE;
    FILE *fopen(const char *path, const char *mode);
    int fclose(FILE *stream);
    size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
    long ftell(FILE *stream);
    int fseek(FILE *stream, long offset, int whence);
    void *malloc(size_t size);
    void free(void *ptr);
]]

local C = ffi.C

-- ============================================================
-- FEATURE EXTRACTION
-- ============================================================

-- Read a binary file and extract features
local function read_binary(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local data = f:read("*all")
    f:close()
    return data
end

-- Extract a feature vector from a binary
local function extract_features(data)
    if not data or #data < 64 then return nil end
    
    local features = {}
    
    -- 1. File size (log scale)
    features.size_log = math.log(#data)
    
    -- 2. Global entropy
    local counts = {}
    for i = 0, 255 do counts[i] = 0 end
    for i = 1, #data do
        local b = data:byte(i)
        counts[b] = counts[b] + 1
    end
    
    local entropy = 0
    local len = #data
    for i = 0, 255 do
        if counts[i] > 0 then
            local p = counts[i] / len
            entropy = entropy - p * math.log(p) / math.log(2)
        end
    end
    features.entropy = entropy
    
    -- 3. Byte distribution statistics
    local mean = 0
    for i = 0, 255 do
        mean = mean + i * counts[i]
    end
    mean = mean / len
    features.byte_mean = mean
    
    local variance = 0
    for i = 0, 255 do
        variance = variance + counts[i] * (i - mean)^2
    end
    variance = variance / len
    features.byte_stddev = math.sqrt(variance)
    
    -- 4. Null byte ratio
    features.null_ratio = counts[0] / len
    
    -- 5. Printable character ratio
    local printable = 0
    for i = 32, 126 do
        printable = printable + counts[i]
    end
    features.printable_ratio = printable / len
    
    -- 6. High byte ratio (0x80-0xFF)
    local high = 0
    for i = 128, 255 do
        high = high + counts[i]
    end
    features.high_byte_ratio = high / len
    
    -- 7. ELF detection
    features.is_elf = (data:sub(1, 4) == "\x7FELF") and 1 or 0
    
    -- 8. Section count (from ELF header if applicable)
    features.section_count = 0
    if features.is_elf == 1 and #data >= 64 then
        -- e_shnum at offset 60 in ELF64
        local lo = data:byte(61)
        local hi = data:byte(62)
        features.section_count = lo + hi * 256
    end
    
    -- 9. Entry point region (where does execution start?)
    features.entry_ratio = 0
    if features.is_elf == 1 and #data >= 32 then
        local entry = 0
        for i = 0, 7 do
            entry = entry + data:byte(25 + i) * (256 ^ i)
        end
        features.entry_ratio = entry / #data
    end
    
    -- 10. Entropy variance across windows
    local window_size = 256
    local window_entropies = {}
    for off = 1, #data - window_size, window_size do
        local w_counts = {}
        for i = 0, 255 do w_counts[i] = 0 end
        for i = off, off + window_size - 1 do
            local b = data:byte(i)
            w_counts[b] = w_counts[b] + 1
        end
        local w_ent = 0
        for i = 0, 255 do
            if w_counts[i] > 0 then
                local p = w_counts[i] / window_size
                w_ent = w_ent - p * math.log(p) / math.log(2)
            end
        end
        table.insert(window_entropies, w_ent)
    end
    
    -- Entropy variance
    local ent_mean = 0
    for _, e in ipairs(window_entropies) do
        ent_mean = ent_mean + e
    end
    ent_mean = ent_mean / math.max(#window_entropies, 1)
    
    local ent_var = 0
    for _, e in ipairs(window_entropies) do
        ent_var = ent_var + (e - ent_mean)^2
    end
    ent_var = ent_var / math.max(#window_entropies, 1)
    features.entropy_variance = ent_var
    
    -- 11. High entropy window ratio
    local high_ent_count = 0
    for _, e in ipairs(window_entropies) do
        if e > 7.0 then high_ent_count = high_ent_count + 1 end
    end
    features.high_entropy_ratio = high_ent_count / 
                                  math.max(#window_entropies, 1)
    
    -- 12. Repeated pattern detection
    -- How many 4-byte sequences repeat?
    local patterns_seen = {}
    local repeated = 0
    local total_patterns = 0
    for i = 1, math.min(#data - 3, 10000) do
        local pat = data:sub(i, i + 3)
        total_patterns = total_patterns + 1
        if patterns_seen[pat] then
            repeated = repeated + 1
        else
            patterns_seen[pat] = true
        end
    end
    features.pattern_repetition = repeated / math.max(total_patterns, 1)
    
    return features
end

-- Convert features to a vector (ordered list)
local FEATURE_NAMES = {
    "size_log", "entropy", "byte_mean", "byte_stddev",
    "null_ratio", "printable_ratio", "high_byte_ratio",
    "is_elf", "section_count", "entry_ratio",
    "entropy_variance", "high_entropy_ratio", "pattern_repetition",
}

local function features_to_vector(features)
    local vec = {}
    for _, name in ipairs(FEATURE_NAMES) do
        table.insert(vec, features[name] or 0)
    end
    return vec
end

-- ============================================================
-- MODEL: STATISTICAL DISTANCE CLASSIFIER
-- ============================================================

local Model = {}
Model.__index = Model

function Model.new()
    return setmetatable({
        -- Per-class statistics
        classes = {},
        -- Global stats for normalization
        global_mean = {},
        global_std = {},
    }, Model)
end

-- Add training sample
function Model:add_sample(class_name, features)
    if not self.classes[class_name] then
        self.classes[class_name] = {
            samples = {},
            mean = {},
            std = {},
            count = 0,
        }
    end
    
    local vec = features_to_vector(features)
    table.insert(self.classes[class_name].samples, vec)
    self.classes[class_name].count = self.classes[class_name].count + 1
end

-- Train (compute statistics)
function Model:train()
    local n_features = #FEATURE_NAMES
    
    -- Compute per-class mean and std
    for class_name, class_data in pairs(self.classes) do
        class_data.mean = {}
        class_data.std = {}
        
        for fi = 1, n_features do
            local sum = 0
            for _, sample in ipairs(class_data.samples) do
                sum = sum + sample[fi]
            end
            class_data.mean[fi] = sum / class_data.count
            
            local var_sum = 0
            for _, sample in ipairs(class_data.samples) do
                var_sum = var_sum + (sample[fi] - class_data.mean[fi])^2
            end
            class_data.std[fi] = math.sqrt(var_sum / class_data.count + 1e-10)
        end
    end
    
    -- Compute global mean/std for normalization
    local all_samples = {}
    for _, class_data in pairs(self.classes) do
        for _, sample in ipairs(class_data.samples) do
            table.insert(all_samples, sample)
        end
    end
    
    for fi = 1, n_features do
        local sum = 0
        for _, sample in ipairs(all_samples) do
            sum = sum + sample[fi]
        end
        self.global_mean[fi] = sum / #all_samples
        
        local var_sum = 0
        for _, sample in ipairs(all_samples) do
            var_sum = var_sum + (sample[fi] - self.global_mean[fi])^2
        end
        self.global_std[fi] = math.sqrt(var_sum / #all_samples + 1e-10)
    end
end

-- Classify a new sample using Mahalanobis-like distance
function Model:classify(features)
    local vec = features_to_vector(features)
    local n_features = #FEATURE_NAMES
    
    local best_class = nil
    local best_distance = math.huge
    local distances = {}
    
    for class_name, class_data in pairs(self.classes) do
        local dist = 0
        for fi = 1, n_features do
            local normalized = (vec[fi] - class_data.mean[fi]) / 
                              (class_data.std[fi] + 1e-10)
            dist = dist + normalized^2
        end
        dist = math.sqrt(dist / n_features)
        distances[class_name] = dist
        
        if dist < best_distance then
            best_distance = dist
            best_class = class_name
        end
    end
    
    -- Compute confidence (inverse distance ratio)
    local total_inv = 0
    for _, d in pairs(distances) do
        total_inv = total_inv + 1 / (d + 1e-10)
    end
    local confidence = (1 / (best_distance + 1e-10)) / total_inv * 100
    
    return best_class, confidence, distances
end

-- ============================================================
-- MODEL SAVE/LOAD
-- ============================================================

function Model:save(path)
    local f = io.open(path, "w")
    if not f then return false end
    
    f:write("MOABI-ML-MODEL-V1\n")
    f:write(#FEATURE_NAMES .. "\n")
    
    -- Write feature names
    for _, name in ipairs(FEATURE_NAMES) do
        f:write(name .. "\n")
    end
    
    -- Write global stats
    for fi = 1, #FEATURE_NAMES do
        f:write(string.format("%.10f %.10f\n", 
                self.global_mean[fi] or 0, 
                self.global_std[fi] or 1))
    end
    
    -- Write classes
    local class_count = 0
    for _ in pairs(self.classes) do class_count = class_count + 1 end
    f:write(class_count .. "\n")
    
    for class_name, class_data in pairs(self.classes) do
        f:write(class_name .. "\n")
        f:write(class_data.count .. "\n")
        for fi = 1, #FEATURE_NAMES do
            f:write(string.format("%.10f %.10f\n", 
                    class_data.mean[fi], class_data.std[fi]))
        end
    end
    
    f:close()
    return true
end

function Model:load(path)
    local f = io.open(path, "r")
    if not f then return false end
    
    local header = f:read("*l")
    if header ~= "MOABI-ML-MODEL-V1" then
        f:close()
        return false
    end
    
    local n_features = tonumber(f:read("*l"))
    
    -- Skip feature names
    for _ = 1, n_features do f:read("*l") end
    
    -- Read global stats
    self.global_mean = {}
    self.global_std = {}
    for fi = 1, n_features do
        local line = f:read("*l")
        local mean, std = line:match("([%d%.e%+%-]+)%s+([%d%.e%+%-]+)")
        self.global_mean[fi] = tonumber(mean)
        self.global_std[fi] = tonumber(std)
    end
    
    -- Read classes
    local class_count = tonumber(f:read("*l"))
    self.classes = {}
    
    for _ = 1, class_count do
        local class_name = f:read("*l")
        local count = tonumber(f:read("*l"))
        
        local class_data = {
            samples = {},
            mean = {},
            std = {},
            count = count,
        }
        
        for fi = 1, n_features do
            local line = f:read("*l")
            local m, s = line:match("([%d%.e%+%-]+)%s+([%d%.e%+%-]+)")
            class_data.mean[fi] = tonumber(m)
            class_data.std[fi] = tonumber(s)
        end
        
        self.classes[class_name] = class_data
    end
    
    f:close()
    return true
end

-- ============================================================
-- CLI INTERFACE
-- ============================================================

local function train_from_directory(model, class_name, directory)
    local handle = io.popen("find " .. directory .. 
                           " -type f -executable 2>/dev/null")
    local files = handle:read("*all")
    handle:close()
    
    local count = 0
    for file in files:gmatch("[^\n]+") do
        local data = read_binary(file)
        if data and #data > 64 then
            local features = extract_features(data)
            if features then
                model:add_sample(class_name, features)
                count = count + 1
                io.write(string.format("\r  Added %d samples from %s", 
                         count, class_name))
            end
        end
    end
    print("")
    return count
end

local function print_features(features)
    print("  Feature Vector:")
    for _, name in ipairs(FEATURE_NAMES) do
        print(string.format("    %-22s  %.6f", name, features[name] or 0))
    end
end

local function main()
    if #arg < 1 then
        print([[
MOABI-ML: Binary Classification Engine

Usage:
  luajit moabi-ml.lua train <model-file>     Train on system binaries
  luajit moabi-ml.lua classify <model> <bin>  Classify a binary
  luajit moabi-ml.lua features <binary>       Extract feature vector
  luajit moabi-ml.lua batch <model> <dir>     Classify all in directory

Train builds a model from known-good system binaries.
Classify tells you how similar an unknown binary is to known classes.
]])
        return
    end
    
    local cmd = arg[1]
    
    if cmd == "features" and arg[2] then
        local data = read_binary(arg[2])
        if not data then
            print("Cannot read: " .. arg[2])
            return
        end
        
        print("")
        print("╔═══════════════════════════════════════════════════╗")
        print("║  MOABI-ML Feature Extraction                      ║")
        print("╚═══════════════════════════════════════════════════╝")
        print("")
        print("File: " .. arg[2])
        print("Size: " .. #data .. " bytes")
        print("")
        
        local features = extract_features(data)
        if features then
            print_features(features)
        end
    
    elseif cmd == "train" and arg[2] then
        local model_path = arg[2]
        local model = Model.new()
        
        print("")
        print("╔═══════════════════════════════════════════════════╗")
        print("║  MOABI-ML Training                                ║")
        print("╚═══════════════════════════════════════════════════╝")
        print("")
        
        -- Train on system utilities (known good)
        print("Training class: system_utility")
        train_from_directory(model, "system_utility", "/usr/bin")
        
        -- Train on our own tools (known minimal)
        print("Training class: moabi_tool")
        train_from_directory(model, "moabi_tool", "/mnt/d/moabi/bin")
        
        -- Train on system libraries
        print("Training class: shared_library")
        local lib_handle = io.popen(
            "find /usr/lib -name '*.so' -type f 2>/dev/null | head -50")
        local libs = lib_handle:read("*all")
        lib_handle:close()
        
        local lib_count = 0
        for file in libs:gmatch("[^\n]+") do
            local data = read_binary(file)
            if data and #data > 64 then
                local features = extract_features(data)
                if features then
                    model:add_sample("shared_library", features)
                    lib_count = lib_count + 1
                end
            end
        end
        print(string.format("  Added %d shared library samples", lib_count))
        
        -- Train the model
        print("\nComputing statistics...")
        model:train()
        
        -- Save
        model:save(model_path)
        print("Model saved to: " .. model_path)
        
        -- Print summary
        print("\nModel Summary:")
        for class_name, class_data in pairs(model.classes) do
            print(string.format("  %-20s  %d samples", 
                  class_name, class_data.count))
        end
    
    elseif cmd == "classify" and arg[2] and arg[3] then
        local model_path = arg[2]
        local target = arg[3]
        
        local model = Model.new()
        if not model:load(model_path) then
            print("Cannot load model: " .. model_path)
            return
        end
        
        local data = read_binary(target)
        if not data then
            print("Cannot read: " .. target)
            return
        end
        
        local features = extract_features(data)
        if not features then
            print("Cannot extract features")
            return
        end
        
        local class, confidence, distances = model:classify(features)
        
        print("")
        print("╔═══════════════════════════════════════════════════╗")
        print("║  MOABI-ML Classification Result                   ║")
        print("╚═══════════════════════════════════════════════════╝")
        print("")
        print("File:       " .. target)
        print("Size:       " .. #data .. " bytes")
        print("")
        print("Classification: " .. class)
        print(string.format("Confidence:     %.1f%%", confidence))
        print("")
        print("Distance to each class:")
        
        -- Sort by distance
        local sorted = {}
        for name, dist in pairs(distances) do
            table.insert(sorted, {name = name, dist = dist})
        end
        table.sort(sorted, function(a, b) return a.dist < b.dist end)
        
        for _, entry in ipairs(sorted) do
            local marker = (entry.name == class) and " ◄" or ""
            print(string.format("  %-20s  %.4f%s", 
                  entry.name, entry.dist, marker))
        end
        
        print("")
        if confidence > 80 then
            print("Verdict: HIGH confidence classification")
        elseif confidence > 60 then
            print("Verdict: MODERATE confidence — review recommended")
        else
            print("Verdict: LOW confidence — binary is unusual, investigate")
        end
        
        print("")
        print_features(features)
    
    elseif cmd == "batch" and arg[2] and arg[3] then
        local model_path = arg[2]
        local directory = arg[3]
        
        local model = Model.new()
        if not model:load(model_path) then
            print("Cannot load model: " .. model_path)
            return
        end
        
        print("")
        print("╔═══════════════════════════════════════════════════╗")
        print("║  MOABI-ML Batch Classification                    ║")
        print("╚═══════════════════════════════════════════════════╝")
        print("")
        print(string.format("%-40s %-20s %s", "File", "Class", "Confidence"))
        print(string.rep("-", 75))
        
        local handle = io.popen("find " .. directory .. 
                               " -type f -executable 2>/dev/null")
        local files = handle:read("*all")
        handle:close()
        
        local anomalies = {}
        
        for file in files:gmatch("[^\n]+") do
            local data = read_binary(file)
            if data and #data > 64 then
                local features = extract_features(data)
                if features then
                    local class, confidence = model:classify(features)
                    local flag = confidence < 50 and " ⚠" or ""
                    
                    local short_name = file:match("([^/]+)$") or file
                    print(string.format("%-40s %-20s %.1f%%%s", 
                          short_name, class, confidence, flag))
                    
                    if confidence < 50 then
                        table.insert(anomalies, {
                            file = file, 
                            class = class, 
                            confidence = confidence
                        })
                    end
                end
            end
        end
        
        if #anomalies > 0 then
            print("")
            print("⚠  ANOMALIES DETECTED:")
            for _, a in ipairs(anomalies) do
                print(string.format("  %s (%.1f%% confidence as %s)", 
                      a.file, a.confidence, a.class))
            end
        end
    
    else
        print("Unknown command. Run without arguments for help.")
    end
end

main()
