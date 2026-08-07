#!/usr/bin/env luajit
--============================================================================
--  MOABI-MODELBOM v1.0
--  Model Bill of Materials for MOABI-ML
--
--  Captures:
--    - model hash
--    - model version / k / feature count / anomaly threshold
--    - class counts
--    - feature schema
--    - normalization stats
--    - training sample manifest
--    - source-file hashes
--
--  Usage:
--    luajit moabi-modelbom.lua [model] [training_dir] [output.json]
--============================================================================

package.path = "/mnt/d/moabi/src/?.lua;" .. package.path

local DEFAULT_MODEL = "/mnt/d/moabi/reports/system.model"
local DEFAULT_TRAIN = "/mnt/d/moabi/reports/training"

local function shq(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function file_exists(path)
    local f = io.open(path, "rb")
    if f then f:close(); return true end
    return false
end

local function sha256(path)
    if not file_exists(path) then return nil end
    local h = io.popen("sha256sum " .. shq(path) .. " 2>/dev/null")
    if not h then return nil end
    local line = h:read("*l")
    h:close()
    if not line then return nil end
    return line:match("^(%x+)")
end

local function filesize(path)
    if not file_exists(path) then return nil end
    local h = io.popen("stat -c %s " .. shq(path) .. " 2>/dev/null")
    if not h then return nil end
    local line = h:read("*l")
    h:close()
    return tonumber(line)
end

local function basename(path)
    return tostring(path):match("([^/]+)$") or tostring(path)
end

local function parent_dir(path)
    return tostring(path):match("^(.*)/[^/]+$") or ""
end

local function utc_now()
    return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

-- JSON encoder, deterministic enough for audit artifacts
local function json_val(v)
    local t = type(v)

    if t == "nil" then
        return "null"

    elseif t == "boolean" then
        return v and "true" or "false"

    elseif t == "number" then
        if v ~= v then return "null" end
        if v == math.huge or v == -math.huge then return "null" end
        return string.format("%.15g", v)

    elseif t == "string" then
        local s = v:gsub("\\", "\\\\")
                   :gsub('"', '\\"')
                   :gsub("\n", "\\n")
                   :gsub("\r", "\\r")
                   :gsub("\t", "\\t")
        return '"' .. s .. '"'

    elseif t == "table" then
        local is_array = (#v > 0)
        if is_array then
            for k, _ in pairs(v) do
                if type(k) ~= "number" then
                    is_array = false
                    break
                end
            end
        end

        local parts = {}

        if is_array then
            for i = 1, #v do
                parts[#parts + 1] = json_val(v[i])
            end
            return "[" .. table.concat(parts, ",") .. "]"
        else
            local keys = {}
            for k, _ in pairs(v) do
                if type(k) == "string" or type(k) == "number" then
                    keys[#keys + 1] = k
                end
            end
            table.sort(keys, function(a, b)
                return tostring(a) < tostring(b)
            end)

            for _, k in ipairs(keys) do
                parts[#parts + 1] =
                    json_val(tostring(k)) .. ":" .. json_val(v[k])
            end

            return "{" .. table.concat(parts, ",") .. "}"
        end
    end

    return "null"
end

local function load_model(path)
    local chunk, err = loadfile(path)
    if not chunk then
        error("Cannot load model: " .. path .. "\n" .. tostring(err))
    end

    local ok, model = pcall(chunk)
    if not ok then
        error("Cannot execute model file: " .. tostring(model))
    end

    if type(model) ~= "table" then
        error("Invalid model: model did not return a table")
    end

    return model
end

local function get_feature_names(model)
    local ok, mf = pcall(require, "moabi-features")
    if ok and mf and type(mf.FEATURE_NAMES) == "table" then
        return mf.FEATURE_NAMES
    end

    if model.info and type(model.info.feature_names) == "table" then
        return model.info.feature_names
    end

    local n = model.info and model.info.n_features
        or (model.samples and model.samples[1] and #model.samples[1].vec)
        or 0

    local names = {}
    for i = 1, n do
        names[i] = "feature_" .. i
    end
    return names
end

local function class_counts_from_model(model)
    if model.class_counts then return model.class_counts end
    if model.info and model.info.class_counts then return model.info.class_counts end

    local counts = {}
    if model.samples then
        for _, s in ipairs(model.samples) do
            counts[s.label] = (counts[s.label] or 0) + 1
        end
    end
    return counts
end

local function feature_stats(model, feature_names)
    local stats = {}
    local mean = model.normalization and model.normalization.mean or {}
    local std  = model.normalization and model.normalization.std or {}

    for i, name in ipairs(feature_names) do
        stats[#stats + 1] = {
            index = i,
            name = name,
            mean = mean[i],
            std = std[i],
        }
    end

    return stats
end

local function source_manifest()
    local files = {
        "/mnt/d/moabi/src/moabi-reflect.lua",
        "/mnt/d/moabi/src/moabi-evidence.lua",
        "/mnt/d/moabi/src/moabi-features.lua",
        "/mnt/d/moabi/src/moabi-ml.lua",
        "/mnt/d/moabi/src/moabi-memory.lua",
        "/mnt/d/moabi/src/moabi-qemu.lua",
        "/mnt/d/moabi/src/moabi-sbom.lua",
        "/mnt/d/moabi/src/moabi-ffi2.lua",
        "/mnt/d/moabi/src/libmoabi.zig",
        "/mnt/d/moabi/bin/libmoabi.so",
    }

    local out = {}
    for _, path in ipairs(files) do
        out[#out + 1] = {
            path = path,
            exists = file_exists(path),
            size = filesize(path),
            sha256 = sha256(path),
        }
    end
    return out
end

local function training_manifest(training_dir)
    local manifest = {
        path = training_dir,
        exists = false,
        total_samples = 0,
        classes = {},
        samples = {},
    }

    local check = io.popen("test -d " .. shq(training_dir) .. " && echo 1")
    if check then
        local r = check:read("*l")
        check:close()
        if r ~= "1" then return manifest end
    else
        return manifest
    end

    manifest.exists = true

    local cmd = "find " .. shq(training_dir) ..
        " -mindepth 2 -maxdepth 2 -type f -print 2>/dev/null"

    local p = io.popen(cmd)
    if not p then return manifest end

    for path in p:lines() do
        local parent = parent_dir(path)
        local class = basename(parent)

        manifest.classes[class] = manifest.classes[class] or {
            count = 0,
            total_bytes = 0,
        }

        local sz = filesize(path) or 0

        manifest.classes[class].count =
            manifest.classes[class].count + 1

        manifest.classes[class].total_bytes =
            manifest.classes[class].total_bytes + sz

        manifest.total_samples = manifest.total_samples + 1

        manifest.samples[#manifest.samples + 1] = {
            class = class,
            path = path,
            file = basename(path),
            size = sz,
            sha256 = sha256(path),
        }
    end

    p:close()

    return manifest
end

local function model_samples_summary(model)
    local out = {
        total = 0,
        by_class = {},
        vector_length = nil,
    }

    if type(model.samples) ~= "table" then
        return out
    end

    out.total = #model.samples

    if model.samples[1] and model.samples[1].vec then
        out.vector_length = #model.samples[1].vec
    end

    for _, s in ipairs(model.samples) do
        local cls = s.label or "unknown"
        out.by_class[cls] = (out.by_class[cls] or 0) + 1
    end

    return out
end

local function build_modelbom(model_path, training_dir)
    local model = load_model(model_path)
    local feature_names = get_feature_names(model)
    local class_counts = class_counts_from_model(model)

    local bom = {
        schema = "moabi.modelbom.v1",
        generated_at = utc_now(),

        model_file = {
            path = model_path,
            size = filesize(model_path),
            sha256 = sha256(model_path),
        },

        model = {
            version = model.info and model.info.version or "unknown",
            algorithm = model.info and model.info.algorithm or "weighted-kNN",
            k = model.k or (model.info and model.info.k),
            n_features = model.info and model.info.n_features or #feature_names,
            n_samples = model.info and model.info.n_samples
                or (model.samples and #model.samples or 0),
            anomaly_threshold =
                model.anomaly_threshold
                or (model.info and model.info.anomaly_threshold),
            class_counts = class_counts,
        },

        feature_schema = {
            count = #feature_names,
            names = feature_names,
            stats = feature_stats(model, feature_names),
        },

        samples_in_model = model_samples_summary(model),

        training_dataset = training_manifest(training_dir),

        sources = source_manifest(),

        hyperparameters = {
            classifier = "weighted k-nearest-neighbors",
            distance = "euclidean over globally z-normalized features",
            normalization = "global z-score",
            class_weighting = "inverse class frequency",
            anomaly_method = "mean k-neighbor distance threshold",
        },

        limitations = {
            "Model-BOM records training inputs and code provenance, not model quality by itself.",
            "Validation accuracy should be recorded separately from training artifacts.",
            "Runtime tracing via strace observes behavior but is not containment.",
            "QEMU user-mode is emulation, not a full sandbox.",
            "Memory inspection uses /proc maps/mem and may inspect interpreter images for non-ELF scripts.",
        },
    }

    return bom
end

local function write_file(path, content)
    local f, err = io.open(path, "w")
    if not f then return nil, err end
    f:write(content)
    f:write("\n")
    f:close()
    return true
end

local function print_summary(bom, out_path)
    print("========================================")
    print("  MOABI Model-BOM")
    print("========================================")
    print()
    print("  Model:        " .. tostring(bom.model_file.path))
    print("  SHA-256:      " .. tostring(bom.model_file.sha256))
    print("  Version:      " .. tostring(bom.model.version))
    print("  Algorithm:    " .. tostring(bom.model.algorithm))
    print("  k:            " .. tostring(bom.model.k))
    print("  Features:     " .. tostring(bom.feature_schema.count))
    print("  Samples:      " .. tostring(bom.model.n_samples))
    print("  Threshold:    " .. tostring(bom.model.anomaly_threshold))
    print()
    print("  Classes:")
    local classes = {}
    for cls, _ in pairs(bom.model.class_counts or {}) do
        classes[#classes + 1] = cls
    end
    table.sort(classes)
    for _, cls in ipairs(classes) do
        print(string.format("    %-18s %s",
            cls,
            tostring(bom.model.class_counts[cls])
        ))
    end
    print()
    print("  Training manifest samples: " ..
        tostring(bom.training_dataset.total_samples))
    print("  Source files recorded:     " ..
        tostring(#bom.sources))
    print()
    print("  Written: " .. out_path)
    print()
end

local function main()
    local model_path = arg[1] or DEFAULT_MODEL
    local training_dir = arg[2] or DEFAULT_TRAIN
    local out_path = arg[3] or (
        "/mnt/d/moabi/reports/modelbom-" ..
        os.date("!%Y%m%d-%H%M%S") ..
        ".json"
    )

    local bom = build_modelbom(model_path, training_dir)
    local ok, err = write_file(out_path, json_val(bom))
    if not ok then
        error("Cannot write Model-BOM: " .. tostring(err))
    end

    print_summary(bom, out_path)
end

local ok, err = pcall(main)
if not ok then
    io.stderr:write("ERROR: " .. tostring(err) .. "\n")
    os.exit(1)
end
