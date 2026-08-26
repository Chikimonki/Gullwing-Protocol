#!/usr/bin/env luajit
-- MOABI-REFLECT v2.0
-- Canonical ELF/PE reflector.
-- Normal path: standard memory telemetry.
-- --deep-memory: optional standalone disk/memory differential analysis.

local SRC = "/mnt/d/moabi"
package.path = SRC .. "/src/?.lua;" .. package.path

local ev = require("moabi-evidence")
local MF = require("moabi-features")
local mem = require("moabi-memory")
local pe_mod = require("moabi-pe")
local diff_mod = require("moabi-diff")
local clock = require("moabi-clock")

local DEFAULT_MODEL = "/mnt/d/moabi/reports/system.model"
local LOG2 = math.log(2)
local EPSILON = 1e-10

local function now_ms()
    return clock.now_ms()
end

local function quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function exists(path)
    local f = io.open(path, "rb")
    if f then
        f:close()
        return true
    end
    return false
end

local function size_of(path)
    local f = io.open(path, "rb")
    if not f then return 0 end
    local size = f:seek("end") or 0
    f:close()
    return size
end

local function sha256(path)
    local p = io.popen("sha256sum " .. quote(path) .. " 2>/dev/null")
    if not p then return "unknown" end
    local line = p:read("*l") or ""
    p:close()
    return line:match("^(%x+)") or "unknown"
end

local function is_executable(path)
    local p = io.popen("test -x " .. quote(path) .. " && echo 1")
    if not p then return false end
    local value = p:read("*l")
    p:close()
    return value == "1"
end

local function read_magic(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local value = f:read(4)
    f:close()
    return value
end

local function library_map(result)
    local libraries = {}

    for _, name in ipairs(result.libs or {}) do
        libraries[name] = true
    end

    local flags = {
        {"has_libssl", "libssl"},
        {"has_libcrypto", "libcrypto"},
        {"has_libcurl", "libcurl"},
        {"has_libz", "libz"},
        {"has_lzma", "liblzma"},
        {"has_ncurses", "libncurses"},
        {"has_readline", "libreadline"},
        {"has_libpython", "libpython"},
        {"has_libperl", "libperl"},
        {"has_libruby", "libruby"},
        {"has_libselinux", "libselinux"},
    }

    for _, item in ipairs(flags) do
        if result.feat[item[1]] == 1 then
            libraries[item[2]] = true
        end
    end

    return libraries
end

local function sense_static(target)
    local start = now_ms()
    local result, err = MF.extract(target)

    if not result then
        return nil, err
    end

    local feat = result.feat
    local is_elf = tonumber(feat.is_elf or 0) == 1

    local structure = {
        is_elf = is_elf,
        format = is_elf and "ELF" or "other",
    }

    if is_elf then
        local types = {
            [0] = "NONE",
            [1] = "REL",
            [2] = "EXEC",
            [3] = "DYN",
            [4] = "CORE",
        }

        structure.elf_class =
            tonumber(feat.elf_class_num or 0) == 2
            and "ELF64"
            or "ELF32"

        structure.elf_type =
            types[tonumber(feat.elf_type_num or 0)]
            or tostring(feat.elf_type_num or 0)

        structure.section_count = feat.section_count or 0
        structure.import_count = feat.import_count or 0
        structure.export_count = feat.export_count or 0
        structure.has_debug = feat.has_debug == 1
    end

    return {
        identity = {
            path = target,
            size = result.size or size_of(target),
            sha256 = sha256(target),
            executable = is_executable(target),
        },

        entropy_profile = {
            global = feat.entropy or 0,
            byte_mean = feat.byte_mean or 0,
            byte_stddev = feat.byte_stddev or 0,
            null_ratio = feat.null_ratio or 0,
            printable_ratio = feat.printable_ratio or 0,
            available = true,
        },

        structure = structure,

        semantics = {
            libraries = library_map(result),
            symbols = result.symbols or {},
            strings = result.toolchain or {},
        },

        vec = result.vec,
        source = result.source or "moabi-features",
        elapsed = now_ms() - start,
    }
end

local function classify(model_path, vector)
    local start = now_ms()
    local chunk, err = loadfile(model_path)

    if not chunk then
        return {
            available = false,
            class = "unknown",
            confidence = 0,
            anomaly = true,
            error = tostring(err),
        }, now_ms() - start
    end

    local ok, model = pcall(chunk)

    if not ok
       or type(model) ~= "table"
       or type(model.samples) ~= "table"
       or type(model.normalization) ~= "table"
    then
        return {
            available = false,
            class = "unknown",
            confidence = 0,
            anomaly = true,
            error = "invalid model",
        }, now_ms() - start
    end

    local n = MF.N
    local means = model.normalization.mean or {}
    local stds = model.normalization.std or {}

    local function normalize(values)
        local output = {}

        for i = 1, n do
            local mean = means[i] or 0
            local std = stds[i] or 1

            if math.abs(std) < EPSILON then
                std = 1
            end

            output[i] = (values[i] - mean) / std
        end

        return output
    end

    local target_vector = normalize(vector)
    local neighbours = {}

    for _, sample in ipairs(model.samples) do
        local sample_vector = normalize(sample.vec)
        local sum = 0

        for i = 1, n do
            local delta = target_vector[i] - sample_vector[i]
            sum = sum + delta * delta
        end

        neighbours[#neighbours + 1] = {
            distance = math.sqrt(sum),
            label = sample.label,
            filename = sample.filename or "?",
        }
    end

    table.sort(neighbours, function(a, b)
        return a.distance < b.distance
    end)

    local k = math.min(model.k or 5, #neighbours)
    local scores = {}
    local total_weight = 0
    local distance_sum = 0

    local class_counts =
        model.class_counts
        or (model.info and model.info.class_counts)
        or {}

    local alpha =
        model.info and tonumber(model.info.alpha)
        or 0

    for i = 1, k do
        local item = neighbours[i]
        local class_size = class_counts[item.label] or 1

        local weight =
            1
            / (item.distance + EPSILON)
            / (class_size ^ alpha)

        scores[item.label] =
            (scores[item.label] or 0) + weight

        total_weight = total_weight + weight
        distance_sum = distance_sum + item.distance
    end

    local best_label = "unknown"
    local best_score = -math.huge

    for label, score in pairs(scores) do
        if score > best_score then
            best_label = label
            best_score = score
        end
    end

    local average =
        k > 0 and distance_sum / k or math.huge

    local threshold =
        tonumber(model.anomaly_threshold)
        or (model.info and tonumber(model.info.anomaly_threshold))
        or 7.5

    return {
        available = true,
        class = best_label,
        confidence = total_weight > 0
            and best_score / total_weight * 100
            or 0,
        anomaly = average > threshold,
        exact_match = neighbours[1]
            and neighbours[1].distance <= EPSILON,
        avg_dist = average,
        threshold = threshold,
        model_version = model.info and model.info.version or "unknown",
    }, now_ms() - start
end

local NETWORK = {
    socket = true, connect = true, accept = true, accept4 = true,
    bind = true, listen = true, sendto = true, recvfrom = true,
    sendmsg = true, recvmsg = true,
}

local FILE_IO = {
    open = true, openat = true, openat2 = true, read = true,
    write = true, close = true, stat = true, fstat = true,
    lstat = true, newfstatat = true, access = true,
}

local function sense_runtime(target, static_only)
    local start = now_ms()

    if static_only then
        return {
            attempted = false,
            reason = "skipped (--static-only)",
        }, now_ms() - start
    end

    if not is_executable(target) then
        return {
            attempted = false,
            reason = "not executable",
        }, now_ms() - start
    end

    local trace = os.tmpname() .. ".moabi-trace"

    os.execute(
        "timeout 3s strace -f -qq -o "
        .. quote(trace)
        .. " -- "
        .. quote(target)
        .. " >/dev/null 2>&1"
    )

    local f = io.open(trace, "r")

    if not f then
        os.remove(trace)
        return {
            attempted = false,
            reason = "trace unavailable",
        }, now_ms() - start
    end

    local counts = {}
    local total = 0

    for line in f:lines() do
        local syscall =
            line:match("^%s*%d+%s+([%a_][%w_]*)%(")
            or line:match("^%s*([%a_][%w_]*)%(")

        if syscall then
            counts[syscall] = (counts[syscall] or 0) + 1
            total = total + 1
        end
    end

    f:close()
    os.remove(trace)

    local network_count = 0
    local file_count = 0
    local unique = 0
    local syscall_entropy = 0

    for syscall, count in pairs(counts) do
        unique = unique + 1

        if NETWORK[syscall] then
            network_count = network_count + count
        end

        if FILE_IO[syscall] then
            file_count = file_count + count
        end
    end

    if total > 0 then
        for _, count in pairs(counts) do
            local p = count / total
            syscall_entropy =
                syscall_entropy
                - p * (math.log(p) / LOG2)
        end
    end

    return {
        attempted = true,
        total = total,
        unique = unique,
        entropy = syscall_entropy,
        net_count = network_count,
        file_count = file_count,
        exec_count = counts.execve or 0,
        net_ratio = total > 0 and network_count / total or 0,
        file_ratio = total > 0 and file_count / total or 0,
    }, now_ms() - start
end

local function reflect_pe(target)
    local pe, err = pe_mod.analyze(target)

    if not pe then
        error("PE analysis failed: " .. tostring(err))
    end

    local e = ev.new(target)

    ev.set_identity(e, {
        path = target,
        size = pe.size or size_of(target),
        sha256 = sha256(target),
        executable = is_executable(target),
    }, "moabi-pe", 0)

    ev.set_structure(e, {
        is_pe = true,
        format = "PE",
        machine = pe.machine,
        subsystem = pe.subsystem,
        section_count = #(pe.sections or {}),
        import_count = #(pe.imports or {}),
    }, "moabi-pe", 0)

    local libraries = {}
    for _, dll in ipairs(pe.dll_list or {}) do
        libraries[dll] = true
    end

    ev.set_semantics(e, {
        libraries = libraries,
        dlls = pe.dll_list or {},
        suspicious_imports = pe.suspicious_imports or {},
    }, "moabi-pe", 0)

    ev.set_entropy_profile(e, {
        global = pe.overall_entropy or 0,
        available = true,
    }, "moabi-pe", 0)

    ev.set_runtime(e, {
        attempted = false,
        status = "skipped",
        reason = "PE static analysis from WSL",
    }, "moabi-pe", 0)

    ev.set_memory(e, {
        profiled = false,
        status = "skipped",
        reason = "PE memory requires Windows, Wine, or VM",
    }, "moabi-pe", 0)

    if type(ev.set_memory_differential) == "function" then
        ev.set_memory_differential(e, {
            profiled = false,
            status = "skipped",
            reason = "PE differential deferred to Wine/VM",
        }, "moabi-pe", 0)
    end

    -- ML Classification for PE files
    local pe_features = require("moabi-pe-features")
    local vec = pe_features.extract_pe_features(target)
    if vec then
        local model_path = DEFAULT_MODEL
        local ml_result, ml_time = classify(model_path, vec)
        ev.set_ml(e, ml_result, "moabi-ml/inline", ml_time)
    end
    ev.converge(e)
    ev.print_report(e)
    return e
end

local function usage()
    print("MOABI-REFLECT v2.0")
    print("Usage: luajit moabi-reflect.lua TARGET [options]")
    print("  --model PATH")
    print("  --static-only")
    print("  --deep-memory")
    print("  --json")
end

local function main()
    local target = arg[1]

    if not target or target == "-h" or target == "--help" then
        usage()
        return 0
    end

    if not exists(target) then
        io.stderr:write("Target not found: " .. target .. "\n")
        return 1
    end

    local model_path = DEFAULT_MODEL
    local static_only = false
    local deep_memory = false
    local json_out = false

    local i=2; while i<=#arg do
        if arg[i]=="--static-only" then static_only=true
        elseif arg[i]=="--json" then json_out=true
        elseif arg[i]=="--deep-memory" then deep_memory=true
        elseif arg[i]=="--containment" then containment=true
        elseif arg[i]=="--containment" then containment=true
        elseif arg[i]=="--model" and arg[i+1] then model_path=arg[i+1]; i=i+1
        end
        i=i+1
    end

    local magic = read_magic(target)

    if magic and magic:sub(1, 2) == "MZ" then
        local e = reflect_pe(target)

        if json_out then
            local name = target:match("([^/]+)$") or "unknown"
            local output = "/mnt/d/moabi/reports/" .. name .. ".evidence.json"
            ev.write_json(e, output)
            print("JSON written: " .. output)
        end

        return 0
    end

    local static, err = sense_static(target)

    if not static then
        io.stderr:write("Static extraction failed: " .. tostring(err) .. "\n")
        return 1
    end

    local e = ev.new(target)

    ev.set_identity(e, static.identity, "moabi-features", static.elapsed)
    ev.set_entropy_profile(e, static.entropy_profile, "moabi-features", 0)
    ev.set_structure(e, static.structure, static.source, 0)
    ev.set_semantics(e, static.semantics, static.source, 0)

    local ml_result, ml_time =
        classify(model_path, static.vec)

    ev.set_ml(e, ml_result, "moabi-ml/inline", ml_time)

    local runtime_result, runtime_time =
        sense_runtime(target, static_only)

    ev.set_runtime(e, runtime_result, "strace", runtime_time)

    if static_only then
        ev.set_memory(e, {
            profiled = false,
            status = "skipped",
            reason = "skipped (--static-only)",
        }, "moabi-memory", 0)
    else
        local memory_start = now_ms()
        local memory_result = mem.inspect(target)

        ev.set_memory(
            e,
            mem.evidence_fragment(memory_result),
            "moabi-memory",
            now_ms() - memory_start
        )
    end

    if deep_memory then
        local differential_start = now_ms()
        local ok, differential = pcall(diff_mod.compare, target)

        if ok and differential then
            ev.set_memory_differential(
                e,
                diff_mod.evidence_fragment(differential),
                "moabi-diff",
                now_ms() - differential_start
            )
        else
            ev.set_memory_differential(
                e,
                {
                    profiled = false,
                    status = "error",
                    error = tostring(differential),
                },
                "moabi-diff",
                now_ms() - differential_start
            )
        end
    else
        ev.set_memory_differential(
            e,
            {
                profiled = false,
                status = "skipped",
                reason = "disabled; use --deep-memory",
            },
            "moabi-diff",
            0
        )
    end

    ev.converge(e)
    ev.print_report(e)

    if json_out then
        local name = target:match("([^/]+)$") or "unknown"
        local output = "/mnt/d/moabi/reports/" .. name .. ".evidence.json"
        ev.write_json(e, output)
        print("JSON written: " .. output)
    end

    return 0
end

local ok, result = pcall(main)

if not ok then
    io.stderr:write("\nERROR: " .. tostring(result) .. "\n")
    os.exit(1)
end

os.exit(result or 0)
