# AGENTS.md — Gullwing Protocol

> **Read this first, agent.** Gullwing is an 8-layer binary intelligence platform — air-gapped, WSL2.

## 1. What this is
**Gullwing Protocol — The Cormorant** — Convergent analysis of ELF/PE in ~25ms (identity, structure, semantics, entropy, ML 89.7% k-NN, runtime strace, memory, diff) → risk & novelty verdict. **No single layer trusted.**
- **Stack:** Zig 0.13 → `libmoabi.so` (core) + LuaJIT FFI (orchestration) + QEMU + Ollama Phi-4-mini + Headscale + Elixir Phoenix PubSub + WCC
- **Repo:** `https://github.com/Chikimonki/Gullwing-Protocol` — MIT — `prime-agent/skills/gullwing` skill

## 2. How to work
```bash
# Train & run
luajit src/moabi-ml.lua train reports/training reports/system.model
luajit src/moabi-serve.lua &  # or gullwing reflect /usr/bin/ls
gullwing bus                  # fleet bus
cd src/extension && python3 -m http.server 8080  # → http://127.0.0.1:8080/unified.html

# Fresh Forensics capture (always)
./forensics_capture.sh --no-build   # → forensics_report_YYYYMMDD_HHMMSS/ (hashlist, SBOM, logs)
cheat gullwing
```

## 3. Structure
- `src/` — `moabi-*.lua`, `gullwing-*.lua`, `extension/unified.html` (8-layer + dashboard)
- `gullwing-kestrel/` / `Kestrel` repo — Zig bridge, 51.6x cache
- `reports/` — training corpora, `releases/v1.0-*/proof_bundle`
- `docs/banner-1280x640.svg`, `docs/GULLWING-WHITEPAPER-v4.5.md`
- `build.zig` — Zig 0.13 `b.path()` API (fixed from `.path`)

## 4. Guardrails
- Keep **WCC Other** license for `wcc` parts, MIT for new code — sign off correctly.
- Keep **CISA/ENISA submitted** badges and `CRA` proof bundle — do not remove compliance evidence.
- Keep **air-gapped** claim true: zero cloud deps, zero API keys.
- Video: `https://youtu.be/bFVrP7GcWYM` — keep thumbnail `img.youtube.com/vi/bFVrP7GcWYM/0.jpg`
- Topics: `binary-analysis, cisa, colibri, cra, cyclonedx, ed25519, enisa, luajit, moe, sbom, stix, zig` — do not clear.

## 5. For AI agents — prime directive
- Use `prime-agent/skills/gullwing` Python skill (`verify_binary(path)` → risk/novelty) before deploy.
- If you change ML, also run `luajit src/moabi-ml.lua train ...` and update `reports/system.model` + benchmark in `README → Performance`.
- Prefer `Docker` + `forensics_capture.sh` evidence over host `strace` alone.

---
*Chikimonki — Pan Enterprises, Liverpool — pan283@gmail.com — Demo: bFVrP7GcWYM — Submitted: CISA, ENISA, NCSC*
