-- MOABI-JSON v1.0
-- Deterministic generic JSON encoder for BOMs, manifests and evidence.

local M = {}

local ESCAPES = {
    ['"']  = '\\"',
    ['\\'] = '\\\\',
    ['\b'] = '\\b',
    ['\f'] = '\\f',
    ['\n'] = '\\n',
    ['\r'] = '\\r',
    ['\t'] = '\\t',
}

local function quote(value)
    value = tostring(value)

    value = value:gsub('[%z\1-\31\\"]', function(ch)
        return ESCAPES[ch] or string.format("\\u%04x", ch:byte())
    end)

    return '"' .. value .. '"'
end

local function is_array(tbl)
    local count = 0
    local highest = 0

    for key in pairs(tbl) do
        if type(key) ~= "number"
           or key < 1
           or key ~= math.floor(key)
        then
            return false
        end

        count = count + 1
        if key > highest then
            highest = key
        end
    end

    return count > 0 and count == highest
end

local function encode_value(value, pretty, depth, active)
    local kind = type(value)

    if kind == "nil" then
        return "null"

    elseif kind == "boolean" then
        return value and "true" or "false"

    elseif kind == "number" then
        if value ~= value
           or value == math.huge
           or value == -math.huge
        then
            return "null"
        end

        if value == math.floor(value) and math.abs(value) < 1e15 then
            return string.format("%.0f", value)
        end

        return string.format("%.15g", value)

    elseif kind == "string" then
        return quote(value)

    elseif kind ~= "table" then
        return "null"
    end

    if active[value] then
        error("cannot encode cyclic table")
    end
    active[value] = true

    local newline = pretty and "\n" or ""
    local separator = pretty and ": " or ":"
    local indent = pretty and string.rep("  ", depth) or ""
    local child_indent = pretty and string.rep("  ", depth + 1) or ""
    local parts = {}

    if is_array(value) then
        for i = 1, #value do
            parts[#parts + 1] =
                child_indent
                .. encode_value(value[i], pretty, depth + 1, active)
        end

        active[value] = nil

        if #parts == 0 then
            return "[]"
        end

        return "["
            .. newline
            .. table.concat(parts, "," .. newline)
            .. newline
            .. indent
            .. "]"
    end

    local keys = {}
    for key in pairs(value) do
        keys[#keys + 1] = key
    end

    table.sort(keys, function(a, b)
        return tostring(a) < tostring(b)
    end)

    for _, key in ipairs(keys) do
        parts[#parts + 1] =
            child_indent
            .. quote(key)
            .. separator
            .. encode_value(value[key], pretty, depth + 1, active)
    end

    active[value] = nil

    if #parts == 0 then
        return "{}"
    end

    return "{"
        .. newline
        .. table.concat(parts, "," .. newline)
        .. newline
        .. indent
        .. "}"
end

function M.encode(value, pretty)
    return encode_value(value, pretty == true, 0, {})
end

function M.write(path, value, pretty)
    local file, err = io.open(path, "w")
    if not file then
        return nil, err
    end

    file:write(M.encode(value, pretty))
    file:write("\n")
    file:close()

    return true
end

return M
