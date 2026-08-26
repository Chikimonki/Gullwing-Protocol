-- ============================================================================
-- moabi-engine.lua — The Kestrel: Gullwing's embedded LLM engine registry
--
-- Selection order (GULLWING_ENGINE=auto):
--   kestrel-ffi   libkestrel.so in-process via LuaJIT FFI   (Tier 1)
--   kestrel-coli  loopback `coli serve`, OpenAI-compatible  (Tier 0)
--   ollama        127.0.0.1:11434 fallback                  (classic)
--
-- Everything is loopback-or-in-process. No network. Air-gap safe by design.
-- ============================================================================

local M = {}
M._VERSION = "kestrel 0.1.0"

-- ----------------------------------------------------------------------------
-- Configuration (env-overridable)
-- ----------------------------------------------------------------------------
local cfg = {
  engine     = os.getenv("GULLWING_ENGINE") or "auto",   -- auto|ffi|coli|ollama
  models_dir = os.getenv("GULLWING_MODELS") or "/mnt/d/models",
  koli_url   = os.getenv("KOLIBRI_URL")     or "http://127.0.0.1:8089",
  ollama_url = os.getenv("OLLAMA_URL")      or "http://127.0.0.1:11434",
  model      = os.getenv("GULLWING_LLM")    or "phi4-mini",
  timeout_s  = tonumber(os.getenv("GULLWING_LLM_TIMEOUT")) or 120,
  lib_path   = os.getenv("KESTREL_LIB"),   -- optional explicit libkestrel.so
}

-- ----------------------------------------------------------------------------
-- Evidence-first prompt builder — the grounded format proven on /usr/bin/ls.
-- Keep this in lockstep with the regression fixture (docs acceptance #4).
-- ----------------------------------------------------------------------------
function M.build_prompt(evidence)
  return table.concat({
    "You are a binary security analyst embedded in the Gullwing Protocol.",
    "Use ONLY the evidence below. Do not speculate beyond it.",
    "",
    "EVIDENCE (8-layer convergent analysis):",
    evidence,
    "",
    "Respond with:",
    "1) Classification of the binary (e.g. system_utility, third_party,",
    "   suspicious) and your confidence.",
    "2) Any inherent-risk caveat, including that binaries can be tampered",
    "   with and integrity must be verified against a trusted source.",
    "3) Notable linkage context from the evidence (e.g. access-control",
    "   libraries) and what it implies.",
    "Be concise, factual, evidence-first.",
  }, "\n")
end

-- ----------------------------------------------------------------------------
-- Minimal JSON plumbing (zero deps; swap for Gullwing's JSON lib if present)
-- ----------------------------------------------------------------------------
local function json_escape(s)
  s = s:gsub("\\", "\\\\"):gsub('"', '\\"')
  s = s:gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
  return s
end

-- Extract OpenAI-style content: {"choices":[{"message":{"content":"..."}}]}
-- Pattern-anchored scan with proper escape handling (no full JSON parser).
local function extract_content(body)
  local _, open = body:find('"content"%s*:%s*"')
  if not open then return nil end
  local i, out = open + 1, {}
  while i <= #body do
    local c = body:sub(i, i)
    if c == "\\" then
      local n = body:sub(i + 1, i + 1)
      if     n == "n" then out[#out + 1] = "\n"
      elseif n == "t" then out[#out + 1] = "\t"
      elseif n == "r" then out[#out + 1] = "\r"
      else                 out[#out + 1] = n end
      i = i + 2
    elseif c == '"' then
      break
    else
      out[#out + 1] = c
      i = i + 1
    end
  end
  return table.concat(out)
end

-- HTTP POST via curl + tempfile (no shell-quoting hazards, zero deps)
local function http_post_json(url, path, json_body)
  local tmp = os.tmpname()
  local f = assert(io.open(tmp, "w"))
  f:write(json_body); f:close()
  local cmd = string.format(
    "curl -s -m %d -X POST -H 'Content-Type: application/json' -d @%s %s%s",
    cfg.timeout_s, tmp, url, path)
  local h = io.popen(cmd, "r")
  local body = h and h:read("*a") or ""
  if h then h:close() end
  os.remove(tmp)
  return body
end

local function http_ok(url, path)
  local h = io.popen(string.format("curl -s -m 3 -o /dev/null -w '%%{http_code}' %s%s", url, path))
  local code = h and h:read("*a") or "000"
  if h then h:close() end
  return code:match("^2") ~= nil
end

-- ----------------------------------------------------------------------------
-- Engine: kestrel-ffi (Tier 1)
-- ----------------------------------------------------------------------------
local ffi_engine = nil
local function try_ffi()
  local ok, ffi = pcall(require, "ffi")
  if not ok then return nil end
  local paths = {}
  if cfg.lib_path then paths[#paths + 1] = cfg.lib_path end
  local self_dir = (arg and arg[0]) and arg[0]:match("^(.*)/[^/]+$") or "."
  paths[#paths + 1] = (self_dir or ".") .. "/../engine/libkestrel.so"
  paths[#paths + 1] = "./libkestrel.so"
  paths[#paths + 1] = "libkestrel.so"

  pcall(function()
    ffi.cdef[[
      typedef struct kestrel kestrel_t;
      typedef struct {
        const char *model_dir; int max_tokens; float temperature;
        long long ram_budget_mb;
      } kestrel_cfg_t;
      typedef struct { const char *text; long long tokens; long long elapsed_ms; } kestrel_reply_t;
      const char *kestrel_version(void);
      kestrel_t *kestrel_open(const kestrel_cfg_t *cfg);
      void kestrel_close(kestrel_t *k);
      int kestrel_ask(kestrel_t *k, const char *prompt, kestrel_reply_t *out);
      void kestrel_free_reply(kestrel_reply_t *reply);
      int kestrel_stats_json(kestrel_t *k, char *buf, size_t cap);
    ]]
  end)

  local K
  for _, p in ipairs(paths) do
    local okl, lib = pcall(ffi.load, p)
    if okl then K = lib; break end
  end
  if not K then return nil end

  local kcfg = ffi.new("kestrel_cfg_t", { cfg.models_dir, 512, 0.0, 12000 })
  local handle = K.kestrel_open(kcfg)
  if handle == nil then return nil end

  return {
    name = "kestrel-ffi",
    version = ffi.string(K.kestrel_version()),
    ask = function(prompt)
      local reply = ffi.new("kestrel_reply_t")
      local rc = K.kestrel_ask(handle, prompt, reply)
      if rc ~= 0 then return nil, "kestrel_ask failed" end
      local text = reply.text ~= nil and ffi.string(reply.text) or ""
      local ms = tonumber(reply.elapsed_ms)
      K.kestrel_free_reply(reply)
      return text, nil, ms
    end,
    close = function() K.kestrel_close(handle) end,
  }
end

-- ----------------------------------------------------------------------------
-- Engine: kestrel-coli (Tier 0) — loopback OpenAI-compatible
-- ----------------------------------------------------------------------------
local function try_coli()
  if not http_ok(cfg.koli_url, "/v1/models") then return nil end
  return {
    name = "kestrel-coli",
    version = "coli-serve (loopback)",
    ask = function(prompt)
      local body = http_post_json(cfg.koli_url, "/v1/chat/completions",
        string.format('{"model":"glm","messages":[{"role":"user","content":"%s"}],"temperature":0}',
          json_escape(prompt)))
      local text = extract_content(body)
      if not text then return nil, "koli: unparseable response" end
      return text
    end,
  }
end

-- ----------------------------------------------------------------------------
-- Engine: ollama (fallback, unchanged behaviour)
-- ----------------------------------------------------------------------------
local function try_ollama()
  if not http_ok(cfg.ollama_url, "/api/tags") then return nil end
  return {
    name = "ollama",
    version = cfg.model,
    ask = function(prompt)
      local body = http_post_json(cfg.ollama_url, "/api/generate",
        string.format('{"model":"%s","prompt":"%s","stream":false,"options":{"temperature":0,"num_ctx":4096}}',
          cfg.model, json_escape(prompt)))
      if not body:find('"response"%s*:') then return nil, "ollama: unparseable response" end
      -- reuse the extractor: /api/generate uses "response", not "content"
      local text = extract_content((body:gsub('"response"', '"content"', 1)))
      if not text then return nil, "ollama: unparseable response" end
      return text
    end,
  }
end

-- ----------------------------------------------------------------------------
-- Registry
-- ----------------------------------------------------------------------------
local function detect()
  local order = { ffi = try_ffi, coli = try_coli, ollama = try_ollama }
  if cfg.engine ~= "auto" then
    local e = order[cfg.engine] and order[cfg.engine]()
    return e, cfg.engine
  end
  for _, key in ipairs({ "ffi", "coli", "ollama" }) do
    local e = order[key]()
    if e then return e, key end
  end
  return nil, "none"
end

function M.ask(evidence)
  local engine = detect()
  if not engine then
    return nil, "no engine available (tried kestrel-ffi, kestrel-coli, ollama)"
  end
  local prompt = M.build_prompt(evidence)
  local text, err, ms = engine.ask(prompt)
  if not text then return nil, err end
  return { engine = engine.name, version = engine.version, text = text, ms = ms }
end

-- ----------------------------------------------------------------------------
-- Self-test:  luajit src/moabi-engine.lua selftest
-- ----------------------------------------------------------------------------
function M.selftest()
  print("kestrel selftest — " .. M._VERSION)
  local prompt = M.build_prompt("[1.IDENTITY] /usr/bin/ls, 142KB, sha256=…\n[3.SEMANTICS] libc.so.6, libselinux.so.1")
  assert(prompt:find("evidence%-first"), "prompt builder")
  print("[ok] prompt builder")

  local ffi_e = try_ffi()
  if ffi_e then
    print("[ok] kestrel-ffi loaded (" .. ffi_e.version .. ")")
    local text, err = ffi_e.ask("selftest")
    if text then print("[ok] ffi ask round-trip: " .. text:sub(1, 60) .. "…")
    else print("[warn] ffi ask: " .. tostring(err)) end
    if ffi_e.close then ffi_e.close() end
  else
    print("[--] kestrel-ffi unavailable (libkestrel.so not found — expected pre-build)")
  end

  local coli_e = try_coli()
  print(coli_e and "[ok] kestrel-coli reachable" or "[--] kestrel-coli not running (start: coli serve)")

  local oll_e = try_ollama()
  print(oll_e and "[ok] ollama reachable" or "[--] ollama not running")

  local _, which = detect()
  print("engine selection: " .. which)
end

-- test hook (also useful for frontend debugging)
M._extract_content = extract_content

if arg and arg[1] == "selftest" then
  M.selftest()
end

return M
