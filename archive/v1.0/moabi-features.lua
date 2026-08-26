--============================================================================
--  MOABI-FEATURES v1.3 — 25-feature extractor (libraries restored)
--============================================================================

local ffi2_ok, ffi2 = pcall(require, "moabi-ffi2")

local LOG2 = math.log(2)
local WINDOW = 1024

local FEATURE_NAMES = {
    "size_log", "entropy", "byte_mean", "byte_stddev", "null_ratio",
    "printable_ratio", "is_elf", "elf_class_num", "elf_type_num",
    "entropy_variance", "high_entropy_ratio", "low_entropy_ratio",
    "top_byte_ratio", "ff_ratio", "section_count", "import_count",
    "export_count", "has_libssl", "has_libcrypto", "has_libcurl",
    "has_libz", "has_lzma", "has_ncurses", "has_readline",
    "has_libpython", "has_libperl", "has_libruby",
}

local N_FEATURES = #FEATURE_NAMES -- should be 27 now

local M = { FEATURE_NAMES = FEATURE_NAMES, N = N_FEATURES }

local function entropy_from_hist(hist, n)
    if n <= 0 then return 0 end
    local e = 0.0
    for i = 0, 255 do
        local c = hist[i] or 0
        if c > 0 then
            local p = c / n
            e = e - p * (math.log(p) / LOG2)
        end
    end
    return e
end

function M.extract(path)
    local f = io.open(path, "rb")
    if not f then return nil, "cannot open" end
    local data = f:read("*a")
    f:close()
    if not data or #data == 0 then return nil, "empty" end

    local size = #data
    local hist = {}
    for i = 0, 255 do hist[i] = 0 end
    local sum, sq, nullc, ffc, printc = 0, 0, 0, 0, 0

    for i = 1, size do
        local b = data:byte(i)
        hist[b] = hist[b] + 1
        sum = sum + b; sq = sq + b * b
        if b == 0 then nullc = nullc + 1 end
        if b == 255 then ffc = ffc + 1 end
        if b >= 0x20 and b <= 0x7e then printc = printc + 1 end
    end

    local mean = sum / size
    local var = math.max(0, sq / size - mean * mean)
    local top = 0
    for i = 0, 255 do if hist[i] > top then top = hist[i] end end

    local feat = {
        size_log = math.log(size + 1),
        entropy = entropy_from_hist(hist, size),
        byte_mean = mean,
        byte_stddev = math.sqrt(var),
        null_ratio = nullc / size,
        printable_ratio = printc / size,
        top_byte_ratio = top / size,
        ff_ratio = ffc / size,
    }

    -- Windowed entropy
    local nw = math.floor(size / WINDOW)
    if nw >= 2 then
        local wes = {}
        for w = 0, nw - 1 do
            local wh = {}
            for i = 0, 255 do wh[i] = 0 end
            local s = w * WINDOW + 1
            for i = s, s + WINDOW - 1 do
                local b = data:byte(i); wh[b] = wh[b] + 1
            end
            wes[#wes + 1] = entropy_from_hist(wh, WINDOW)
        end
        local esum = 0
        for _, v in ipairs(wes) do esum = esum + v end
        local emean = esum / #wes
        local evar, hi, lo = 0, 0, 0
        for _, v in ipairs(wes) do
            evar = evar + (v - emean) ^ 2
            if v > 7.0 then hi = hi + 1 end
            if v < 2.0 then lo = lo + 1 end
        end
        feat.entropy_variance = evar / #wes
        feat.high_entropy_ratio = hi / #wes
        feat.low_entropy_ratio = lo / #wes
    else
        feat.entropy_variance = 0
        feat.high_entropy_ratio = 0
        feat.low_entropy_ratio = 0
    end

    -- Structural + library features via FFI
    feat.section_count = 0
    feat.import_count = 0
    feat.export_count = 0
    feat.has_libssl = 0
    feat.has_libcrypto = 0
    feat.has_libcurl = 0
    feat.has_libz = 0
    feat.has_lzma = 0
    feat.has_ncurses = 0
    feat.has_readline = 0
    feat.has_libpython = 0
    feat.has_libperl = 0
    feat.has_libruby = 0

    if ffi2_ok and ffi2 and type(ffi2.extract_elf_features) == "function" then
        local ok, r = pcall(ffi2.extract_elf_features, path)
        if ok and r then
    if size >= 18 and data:byte(1) == 0x7f and data:byte(2) == 0x45
       and data:byte(3) == 0x4c and data:byte(4) == 0x46 then
        feat.is_elf = 1.0
        feat.elf_class_num = 0.0 + data:byte(5)
        local le = data:byte(6) == 1
        local b1, b2 = data:byte(17), data:byte(18)
        feat.elf_type_num = 0.0 + (le and (b1 + b2*256) or (b1*256 + b2))
    else
        feat.is_elf = 0.0
        feat.elf_class_num = 0.0
        feat.elf_type_num = 0.0
    end
            feat.section_count = r.section_count or 0
            feat.import_count = ((r.import_count or r.dependency_count or 0) + 1)
            feat.export_count = ((r.export_count or 0) + 1)
            feat.has_libssl    = r.has_libssl or 0
            feat.has_libcrypto = r.has_libcrypto or 0
            feat.has_libcurl   = r.has_libcurl or 0
            feat.has_libz      = r.has_libz or 0
            feat.has_lzma      = r.has_lzma or 0
            feat.has_ncurses   = r.has_ncurses or 0
            feat.has_readline  = r.has_readline or 0
            feat.has_libpython = r.has_libpython or 0
            feat.has_libperl   = r.has_libperl or 0
            feat.has_libruby   = r.has_libruby or 0
        end
    end

    -- String-scanning fallback for statically-linked symbols
    if data then
        if data:find("libssl", 1, true) or data:find("SSL_", 1, true) then
            feat.has_libssl = 1
        end
        if data:find("libcrypto", 1, true) or data:find("EVP_", 1, true) then
           feat.has_libcrypto = 1
        end
        if data:find("libcurl", 1, true) or data:find("curl_easy_", 1, true) then
            feat.has_libcurl = 1
        end
        if data:find("libz", 1, true) or data:find("deflate", 1, true) then
            feat.has_libz = 1
        end
        if data:find("lzma", 1, true) or data:find("LZMA_", 1, true) then
            feat.has_lzma = 1
        end
        if data:find("libpython", 1, true) or data:find("PyEval_", 1, true) then
            feat.has_libpython = 1
        end
        if data:find("libperl", 1, true) or data:find("Perl_", 1, true) then
            feat.has_libperl = 1
        end
        if data:find("libruby", 1, true) or data:find("ruby_", 1, true) then
            feat.has_libruby = 1
        end
    end

    -- Build final vector
    local vec = {}
    for i, name in ipairs(FEATURE_NAMES) do
        vec[i] = feat[name] or 0.0
    end

    return { vec = vec, feat = feat, size = size, source = "moabi-features" }
end

return M
