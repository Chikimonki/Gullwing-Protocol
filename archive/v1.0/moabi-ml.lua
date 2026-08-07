#!/usr/bin/env luajit
--============================================================================
--  MOABI-ML v3.1: The Gullwing Edition
--  Features: Aligned 30-dim vector, Model Versioning, 
--            Online Welford Normalization, Permutation Importance.
--============================================================================

local MF = require("moabi-features")
local FEATURE_NAMES = MF.FEATURE_NAMES
local N_FEATURES = 27
local DEFAULT_K = 5
local EPSILON = 1e-10
local MODEL_VERSION = 3  -- Aligned with your suggestion #1
local ALPHA = 0.5        -- Soft weighting exponent (0.0=none, 1.0=full)

-- ============================================================================
--  MODEL CLASS
-- ============================================================================
local Model = {}
Model.__index = Model

function Model.new(k)
    local self = setmetatable({}, Model)
    self.k = k or DEFAULT_K
    self.samples = {}
    self.normalization = { mean = {}, std = {} }
    self.class_counts = {}
    self.anomaly_threshold = math.huge
    self.info = { version = MODEL_VERSION }
    
    -- Online Welford State (Suggestion #2)
    self._online_n = 0
    self._online_mean = {}
    self._online_M2 = {}
    for i = 1, N_FEATURES do
        self._online_mean[i] = 0.0
        self._online_M2[i] = 0.0
    end
    return self
end

function Model:add_sample(vec, label, filename)
    self.samples[#self.samples + 1] = { vec = vec, label = label, filename = filename }
    self.class_counts[label] = (self.class_counts[label] or 0) + 1
    
    -- Incremental Normalization (Welford's Algorithm)
    self._online_n = self._online_n + 1
    for i = 1, N_FEATURES do
        local x = vec[i] or 0.0
        local delta = x - self._online_mean[i]
        self._online_mean[i] = self._online_mean[i] + delta / self._online_n
        local delta2 = x - self._online_mean[i]
        self._online_M2[i] = self._online_M2[i] + delta * delta2
    end
end

function Model:finalize_normalization()
    local n = self._online_n
    if n == 0 then return end
    for i = 1, N_FEATURES do
        local mean = self._online_mean[i]
        local variance = self._online_M2[i] / n
        local std = math.sqrt(math.max(0, variance))
        if std < EPSILON then std = 1.0 end
        self.normalization.mean[i] = mean
        self.normalization.std[i] = std
    end
end

function Model:normalize(vec)
    local out = {}
    for i = 1, N_FEATURES do
        local m = self.normalization.mean[i] or 0.0
        local s = self.normalization.std[i] or 1.0
        out[i] = (vec[i] - m) / s
    end
    return out
end

local function euclid(a, b)
    local s = 0.0
    for i = 1, N_FEATURES do
        local d = a[i] - b[i]
        s = s + d * d
    end
    return math.sqrt(s)
end

function Model:classify(vec)
    local nv = self:normalize(vec)
    local nbs = {}
    for i = 1, #self.samples do
        local sv = self:normalize(self.samples[i].vec)
        nbs[#nbs + 1] = { dist = euclid(nv, sv), label = self.samples[i].label, filename = self.samples[i].filename or "?" }
    end
    if #nbs == 0 then error("Model has no samples") end
    table.sort(nbs, function(a, b) return a.dist < b.dist end)

    local k = math.min(self.k, #nbs)
    local scores, tw, sd = {}, 0.0, 0.0
    
    for i = 1, k do
        local nb = nbs[i]
        local class_size = self.class_counts[nb.label] or 1
        -- Balanced weighting (Inverse-distance + ALPHA-scaled class frequency)
        local w = (1 / (nb.dist + EPSILON)) / (class_size ^ ALPHA)
        
        scores[nb.label] = (scores[nb.label] or 0.0) + w
        tw = tw + w; sd = sd + nb.dist
    end

    local best_label, best_score = "unknown", -1
    for lbl, sc in pairs(scores) do
        if sc > best_score then best_label, best_score = lbl, sc end
    end
    
    local avg = sd / k
    local thresh = self.anomaly_threshold
    if self.info and self.info.anomaly_threshold then thresh = self.info.anomaly_threshold end

    return {
        label = best_label, confidence = tw > 0 and (best_score / tw) * 100 or 0,
        neighbours = nbs, k = k, avg_dist = avg, threshold = thresh,
        anomaly = avg > thresh, exact_match = nbs[1].dist <= EPSILON,
    }
end

-- ============================================================================
--  SERIALIZATION (JSON-style Table)
-- ============================================================================
local function serialize(val)
    local t = type(val)
    if t == "number" then
        if val ~= val then return "0/0" end
        if val == math.huge then return "math.huge" end
        if val == -math.huge then return "-math.huge" end
        return string.format("%.15g", val)
    elseif t == "string" then return string.format("%q", val)
    elseif t == "boolean" or t == "nil" then return tostring(val)
    elseif t == "table" then
        local parts = {}
        local is_arr = #val > 0
        if is_arr then
            for i = 1, #val do parts[i] = serialize(val[i]) end
            return "{" .. table.concat(parts, ",") .. "}"
        else
            for k, v in pairs(val) do
                local key = type(k) == "string" and k:match("^[%a_][%w_]*$") and k or "["..serialize(k).."]"
                parts[#parts+1] = key .. "=" .. serialize(v)
            end
            return "{" .. table.concat(parts, ",") .. "}"
        end
    end
end

local function load_model(path)
    local chunk, err = loadfile(path)
    if not chunk then error("Cannot load model: " .. path .. " " .. tostring(err)) end
    local model = chunk()
    if type(model) ~= "table" or type(model.samples) ~= "table" then error("Invalid model: " .. path) end
    
    -- Version check (Suggestion #1)
    local ver = model.info and model.info.version or 0
    if ver ~= MODEL_VERSION then
        error(string.format("Model version mismatch: found v%s, need v%d", tostring(ver), MODEL_VERSION))
    end
    return setmetatable(model, Model)
end

-- ============================================================================
--  CLI COMMANDS
-- ============================================================================

local function cmd_train(train_dir, model_path)
    print("========================================")
    print("  MOABI-ML v3.1 Training (Welford)")
    print("========================================")
    
    local model = Model.new()
    local p = io.popen('ls -1 "' .. train_dir .. '"')
    for cls in p:lines() do
        local cls_path = train_dir .. "/" .. cls
        local fp = io.popen('ls -1 "' .. cls_path .. '" 2>/dev/null')
        if fp then
            for fname in fp:lines() do
                local res = MF.extract(cls_path .. "/" .. fname)
                if res then model:add_sample(res.vec, cls, fname) end
            end
            fp:close()
        end
    end
    p:close()

    model:finalize_normalization() -- Suggestion #2

    -- Compute Anomaly Threshold
    local densities = {}
    for i = 1, #model.samples do
        local dists = {}
        for j = 1, #model.samples do
            if i ~= j then dists[#dists+1] = euclid(model:normalize(model.samples[i].vec), model:normalize(model.samples[j].vec)) end
        end
        table.sort(dists)
        local s = 0; for d=1,DEFAULT_K do s = s + (dists[d] or 0) end
        densities[i] = s / DEFAULT_K
    end
    local dsum = 0; for _,v in ipairs(densities) do dsum = dsum + v end
    local dmean = dsum / #densities
    local dss = 0; for _,v in ipairs(densities) do dss = dss + (v-dmean)^2 end
    model.anomaly_threshold = dmean + 2.0 * math.sqrt(dss/#densities)
    model.info.anomaly_threshold = model.anomaly_threshold
    model.info.class_counts = model.class_counts

    local f = io.open(model_path, "w")
    f:write("return " .. serialize(model))
    f:close()
    print("  Model saved: " .. model_path)
end

local function compute_accuracy(model, k)
    local correct = 0
    for i = 1, #model.samples do
        local train_model = Model.new(k)
        for j = 1, #model.samples do
            if i ~= j then train_model:add_sample(model.samples[j].vec, model.samples[j].label) end
        end
        train_model:finalize_normalization()
        local out = train_model:classify(model.samples[i].vec)
        if out.label == model.samples[i].label then correct = correct + 1 end
    end
    return correct / #model.samples
end

local function cmd_validate(model_path)
    local model = load_model(model_path)
    print("========================================")
    print("  MOABI-ML v3.1 Importance Validation")
    print("========================================")
    
    local baseline = compute_accuracy(model, model.k)
    print(string.format("  Baseline Accuracy: %.1f%%", baseline * 100))
    print("\n  Permutation Importance (Impact):")
    
    for f_idx = 1, N_FEATURES do
        local perm_values = {}
        for i=1,#model.samples do perm_values[i] = model.samples[i].vec[f_idx] end
        for i=#perm_values,2,-1 do local j=math.random(i); perm_values[i],perm_values[j] = perm_values[j],perm_values[i] end
        
        local perm_model = Model.new(model.k)
        for i=1,#model.samples do
            local pvec = {}; for v=1,N_FEATURES do pvec[v] = model.samples[i].vec[v] end
            pvec[f_idx] = perm_values[i]
            perm_model:add_sample(pvec, model.samples[i].label)
        end
        perm_model:finalize_normalization()
        local acc = compute_accuracy(perm_model, model.k)
        local drop = baseline - acc
        local marker = drop > 0.05 and "***" or (drop > 0.01 and "*" or "")
        print(string.format("    %-20s %+.4f %s", FEATURE_NAMES[f_idx], drop, marker))
    end
end

-- ============================================================================
--  MAIN
-- ============================================================================
local cmd = arg[1]
if cmd == "train" then cmd_train(arg[2], arg[3])
elseif cmd == "validate" then cmd_validate(arg[2])
elseif cmd == "classify" then 
    local m = load_model(arg[2])
    local r = MF.extract(arg[3])
    local out = m:classify(r.vec)
    print("Class: "..out.label.." ("..string.format("%.1f", out.confidence).."%)")
else
    print("Usage: moabi-ml.lua train|validate|classify")
end
