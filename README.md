# GULLWING v4.1 — Convergent Binary Intelligence Platform

> *"Lua is Portuguese for Moon. Moon is reflection."*

Gullwing is a purple-hat, cross-platform, multi-layered, reflective binary analysis engine with temporal memory forensics, automated supply chain monitoring, and cryptographic attestation — running entirely in-process via LuaJIT FFI to native Zig libraries.

Inspired by the reflective architecture principles articulated by Jonathan Brossard at [moabi.com](https://moabi.com/vivatech-2026-innovation-can-no-longer-move-forward-without-cybersecurity/): *"Organisations must be able to understand, assess and verify the technologies on which they rely."*

---

## Key Capabilities

- **8-layer convergent reflection** — identity, structure, semantics, entropy, ML classification, runtime tracing, memory inspection, and memory differential comparison
- **Two-dimensional verdicts** — separates Risk (CLEAR/NOTABLE/SUSPICIOUS/HOSTILE) from Novelty (NORMAL/ELEVATED/EXTREME)
- **In-process execution** — zero subprocess overhead for static analysis; Zig FFI for zero-copy ELF/PE parsing
- **Cross-platform** — analyzes Linux ELF and Windows PE binaries from the same codebase; runs on WSL
- **Embedded binary extraction** — finds executables inside ZIP, PDF, GZ, and UEFI firmware images
- **Supply chain monitoring** — real-time filesystem watching with automatic delta alerts
- **Automated response** — quarantine, attest, and restore on CRITICAL verdicts
- **Cryptographic attestation** — Ed25519 signing of evidence objects with third-party verification
- **Cross-vendor equivalence** — scores whether binaries from different compilers/distros are functionally equivalent
- **HTTP API** — REST endpoint on localhost:9393 for browser and tool integration
- **SBOM generation** — CycloneDX 1.6 JSON export with cryptographic hashes per component
- **Model provenance** — Model-BOM with hyperparameters, feature importance, and training metadata (EU AI Act compliant)
- **Self-introspection** — every verdict includes layer completeness, source provenance, and agreement scores
- **Unified command** — all capabilities accessible through a single `gullwing` binary

---

## Quick Start

### 1. Train the Model

```bash
gullwing train reports/training reports/system.model
```

Training data is organized in class subdirectories:
```
training/
├── system_utility/    # ls, cp, cat, grep, ps...
├── network_tool/      # curl, wget, ssh, nc...
├── interpreter/       # python3, perl, ruby, lua...
├── compression/       # xz, gzip, bzip2, tar...
├── shared_library/    # libc.so, libssl.so...
├── shell/             # bash, sh, zsh...
├── text_tool/         # sed, awk, sort, diff...
├── browser/           # chrome.exe, brave.exe, msedge.exe...
└── packed/            # UPX-compressed samples
```

### 2. Analyze a Binary

```bash
gullwing reflect /usr/bin/ls
```

### 3. Extract Embedded Binaries

```bash
# From a ZIP archive
gullwing extract suspicious.zip --reflect

# From UEFI firmware
gullwing extract bios_dump.bin --reflect
```

### 4. Monitor a Directory

```bash
gullwing watch /usr/bin 5.0
```

### 5. Start the HTTP API

```bash
gullwing serve
curl -X POST http://127.0.0.1:9393/reflect -d "path=/usr/bin/ls"
```

---

## The Gullwing Imperator

All tools accessible through a single unified command:

```bash
gullwing COMMAND [args...]
```

| Command | Function |
|---------|----------|
| `gullwing reflect` | Full 8-layer convergent analysis |
| `gullwing extract` | Find embedded executables (ZIP, PDF, GZ, UEFI) |
| `gullwing watch` | Real-time filesystem monitoring with auto-delta + agent |
| `gullwing delta` | Supply chain differential comparison |
| `gullwing attest` | Ed25519 cryptographic evidence signing |
| `gullwing compare` | Cross-vendor binary equivalence scoring |
| `gullwing serve` | HTTP API server for browser integration |
| `gullwing train` | ML model training and validation |
| `gullwing sbom` | CycloneDX 1.6 SBOM generation |
| `gullwing pe` | Windows PE binary analysis |
| `gullwing qemu` | Cross-architecture QEMU emulation |
| `gullwing modelbom` | Model provenance documentation |
| `gullwing view` | Dashboard viewer for SBOM files |
| `gullwing agent` | Automated response: quarantine, attest, restore |

---

## The 8-Layer Evidence Model

```
                     Target Binary
                           │
    ┌──────────────────────┼──────────────────────┐
    ▼                      ▼                      ▼
[1. IDENTITY]        [2. STRUCTURE]        [3. SEMANTICS]
(Path, Size, SHA256) (ELF Class, Sections) (Libraries, Symbols)
    │                      │                      │
    ├──────────────────────┼──────────────────────┘
    ▼                      ▼
[4. ENTROPY]         [5. MACHINE LEARNING]
(Global/Windowed)    (Weighted k-NN, LOO CV)
    │                      │
    ├──────────────────────┘
    ▼
[6. RUNTIME] ────────► [7. MEMORY] ────────► [8. MEMORY DIFF]
(Syscall Profile)    (Page Mappings)       (Disk vs Memory Δ)
    │                      │                      │
    └──────────┬───────────┴──────────────────────┘
               ▼
       [CONVERGENCE]
 (Risk & Novelty Verdict)
               │
               ▼
        [INTROSPECTION]
  (Provenance & Confidence)
```

---

### The Convergence Matrix

```
                LOW NOVELTY              EXTREME NOVELTY
              ┌─────────────────────┬─────────────────────┐
    HOSTILE   │ Known Bad           │ Adversarial         │
              │ (Signature Match)   │ (Packed Dropper)    │
              ├─────────────────────┼─────────────────────┤
    CLEAR     │ Known Good          │ Novel Utility       │
              │ (Standard Tool)     │ (Custom Zig Binary) │
              └─────────────────────┴─────────────────────┘
```

Risk and Novelty are independent axes. A binary can be CLEAR risk but EXTREME novelty (legitimate custom tool) or HOSTILE risk but NORMAL novelty (known malware family).

---

## Automated Supply Chain Defense

The Gullwing defense pipeline operates without human intervention:

```
File changes in watched directory
    │
    ▼
gullwing-watch detects change (polling, 2s interval)
    │
    ▼
moabi-extract finds any embedded binaries
    │
    ▼
moabi-reflect runs 8-layer analysis (26ms static)
    │
    ▼
moabi-delta compares against baseline
    │
    ▼
CRITICAL verdict → alert written to log
    │
    ▼
gullwing-agent quarantines the file
    │
    ▼
gullwing-attest signs the evidence
    │
    ▼
Baseline restored if available
    │
    ▼
Operator notified with full delta report
```

**Detection-to-quarantine time: under 2 seconds.**

---

## Embedded Binary Extraction

Gullwing can find executables hidden inside other file formats:

| Format | Detection Method | Example |
|--------|-----------------|---------|
| ZIP/Office/JAR/APK | Archive extraction + header scan | `gullwing extract malware.zip --reflect` |
| PDF | ELF/PE magic byte scanning | `gullwing extract invoice.pdf --reflect` |
| GZ/BZ2/XZ | Decompress + header check | `gullwing extract payload.gz --reflect` |
| UEFI Firmware | PE\0\0 signature search + MZ backward scan | `gullwing extract bios.bin --reflect` |

---

## Cryptographic Attestation

```bash
gullwing attest generate                         # Create Ed25519 keypair
gullwing attest sign reports/ls.evidence.json    # Sign evidence
gullwing attest verify ls.evidence.json ls.sig   # Verify (exit 0 = authentic)
```

Tampered evidence fails verification instantly. Keys stored in `reports/keys/`.

---

## Cross-Vendor Equivalence

```bash
gullwing compare vendor_a.json vendor_b.json
```

Scores whether binaries from different compilers/distros are functionally equivalent:

| Score | Verdict |
|-------|---------|
| 85%+ | FUNCTIONALLY EQUIVALENT |
| 65-84% | LIKELY EQUIVALENT |
| 45-64% | PARTIALLY EQUIVALENT |
| <45% | NOT EQUIVALENT |

---

## Example Output

```
================================================================
  MOABI EVIDENCE — CONVERGENT REFLECTION
================================================================

  [IDENTITY]
    Path:       /usr/bin/ls
    Size:       142312 bytes
    SHA-256:    0148f5ab...
    Executable: true

  [STRUCTURE]
    ELF:        true    Class: ELF64    Type: DYN
    Sections:   31      Imports: 2      Exports: 128

  [SEMANTICS]
    Libraries:  libc.so.6, libselinux, libselinux.so.1

  [ML VERDICT]
    Class:      system_utility
    Confidence: 99.999999966535%
    Anomaly:    false

  [RUNTIME]
    Syscalls:   152 total, 23 unique
    Network:    0 (0.0%)    File I/O: 96 (63.2%)

  [MEMORY]
    Regions:    12 (exec 3)    RWX: 0    Anon-exec: 0

  [MEMORY DIFFERENTIAL]
    Match ratio: 1.0000    Max |delta H|: 0.0000

  [CONVERGENCE]
    Risk: CLEAR (score 0)    Novelty: NORMAL (score 0)

  [INTROSPECTION]
    Completeness: 8/8 layers (100%)    Total: 131.43 ms
================================================================
```

### Supply Chain Alert

```
[2026-07-25 10:07:09] /tmp/test_ls — SUPPLY CHAIN CHANGE — CRITICAL
  Weight: 16.0  |  Changes: 9  |  Critical: 1

══════════════════════════════════════════════════════════════
  GULLWING AGENT — AUTOMATED RESPONSE
══════════════════════════════════════════════════════════════
  Target:    /tmp/test_ls
  Verdict:   SUPPLY CHAIN CHANGE — CRITICAL
  Action:    QUARANTINED → /mnt/d/moabi/reports/quarantine/test_ls.20260725-100709
  Evidence signed and logged.
══════════════════════════════════════════════════════════════
```

---

## Performance

Full 8-layer analysis on `/usr/bin/ls` (142KB ELF64):

| Layer | Time |
|-------|------|
| Identity | ~10 ms |
| Structure | <1 ms |
| Semantics | <1 ms |
| Entropy | <1 ms |
| ML Classification | ~20 ms |
| Runtime (strace) | ~35 ms |
| Memory inspection | ~30 ms |
| Memory differential | ~30 ms |
| **Total** | **~130 ms** |

Static-only: ~25 ms. Embedded extraction + reflect: ~50 ms per binary.

---

## Regulatory Compliance

| Requirement | How Gullwing Delivers |
|-------------|----------------------|
| **SBOM generation** (CRA Annex VII) | CycloneDX 1.6 with cryptographic hashes |
| **Risk assessment** (CRA Annex I) | 8-layer convergent analysis with scored verdicts |
| **Vulnerability monitoring** (CRA Art. 10) | `gullwing watch` — real-time binary change detection |
| **Integrity verification** (CRA Annex I) | `gullwing attest` — Ed25519 cryptographic signing |
| **Technical documentation** (AI Act Art. 11) | Model-BOM with hyperparameters, training data |
| **Accuracy evidence** (AI Act Art. 15) | LOO cross-validation with 89.7% baseline |
| **Human oversight** (AI Act Art. 14) | Every verdict includes signals, confidence, introspection |
| **Automated response** (CRA Art. 10) | `gullwing agent` — quarantine, attest, restore |

---

## Requirements

- LuaJIT 2.1+
- Zig 0.13.0 (only for rebuilding `libmoabi.so`)
- Linux kernel 5.x+ (for `/proc` memory inspection)
- OpenSSL 3.0+ (for `gullwing attest`)
- Optional: QEMU (cross-architecture emulation)
- Optional: inotify-tools (filesystem monitoring)

---

## License

MIT — open source, open compliance.

---

*Gullwing v4.1 — Convergent Binary Intelligence Platform. In-process. Cross-platform. Purple-hat. Reflective.*
```

Test Gullwings's 10 capabilities:

# 1. Core analysis
gullwing reflect /usr/bin/ls --static-only 2>&1 | grep -E "Class:|Risk:|Novelty:|Libraries:"

# 2. Supply chain delta
gullwing delta /mnt/d/moabi/reports/ls.evidence.json /mnt/d/moabi/reports/curl.evidence.json 2>&1 | grep -E "Status:|Verdict|Weight:"

# 3. Cross-vendor equivalence
gullwing compare /mnt/d/moabi/reports/ls.evidence.json /mnt/d/moabi/reports/ls.evidence.json 2>&1 | grep -E "Score:|Verdict:"

# 4. Embedded extraction
gullwing extract /tmp/uefi_sample.bin 2>&1 | grep -E "Result:|EFI"

# 5. Cryptographic attestation
gullwing attest sign /mnt/d/moabi/reports/ls.evidence.json 2>&1 | grep -E "Status:|Sig SHA"

# 6. SBOM generation
gullwing sbom /usr/bin --out /tmp/test_sbom.cdx.json 2>&1 | grep -E "Components:|ELF:|PE:"

# 7. PE analysis
gullwing pe "/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" 2>&1 | grep -E "Machine:|Sections:|Imports:"

# 8. HTTP API health
curl -s http://127.0.0.1:9393/status 2>/dev/null

# 9. API reflect endpoint
curl -s -X POST http://127.0.0.1:9393/reflect -d "path=/usr/bin/ls" 2>/dev/null | head -1 | cut -c1-80

# 10. Agent status
gullwing agent status 2>&1



The Frontend Manual

Here's the frontend manual — plain English, no jargon.

---

# Gullwing Frontend — User Guide

## The Three Interfaces

Gullwing has three ways to interact with it. You only need to remember what each one does.

---

## 1. The Popup (Click the Gullwing Icon)

**Where:** Click the 🪽 icon in your browser toolbar.

**What it shows:**
- **Green dot** = Gullwing API is running. **Red dot** = API is down.
- **Manual Scan box** — type a file path, click "Scan Binary", get instant results.
- **Recent Analyses** — the last 10 things Gullwing analyzed.

**When to use it:** You downloaded something and want to check it right now. Type the path, hit enter, see the verdict.

---

## 2. The Dashboard (dashboard.html)

**Where:** Open `dashboard.html` in your browser. Bookmark it.

**What it shows:**
- **System card** — is the ML model loaded? How long has Gullwing been running?
- **Risk bars** — how many CLEAR vs HOSTILE files have been seen. Green = good, red = bad.
- **Quarantine card** — files that were automatically locked away because they were dangerous.
- **SBOM card** — how many binaries are in your latest software inventory.
- **Live feed** — every alert in real time. Watch for red.

**When to use it:** You want to see everything at once. Leave it open on a second monitor.

---

## 3. The API (in the terminal)

**Where:** Terminal running `gullwing serve`.

**What it does:** The engine. The popup and dashboard talk to this. You don't interact with it directly — it just runs.

**When to check it:** If the popup shows a red dot, the API is down. Restart it with `gullwing serve`.

---

## What Happens When You Download Something

1. You click a download link
2. The extension grabs the file path
3. Sends it to the API
4. Gullwing analyzes it in ~25ms
5. A notification pops up: 🟢 CLEAR or 🔴 HOSTILE
6. If HOSTILE, the file is quarantined automatically

**You don't need to do anything.** It happens in the background.

---

## What Happens When a Site Traps Your Back Button

1. You try to leave a site
2. The site forces you back
3. After 3 times in 5 seconds, Gullwing detects the trap
4. A notification appears: "Back Button Trap Detected"
5. Click "Close tab" to escape

---

## Quick Troubleshooting

| Problem | Fix |
|---------|-----|
| Popup icon is grey | Go to `chrome://extensions`, click refresh on Gullwing |
| Popup shows red dot | Run `gullwing serve` in terminal |
| Dashboard is empty | Make sure `gullwing serve` is running |
| No download notifications | Check the API is online (green dot in popup) |
| Back button detection not working | Reload the extension in `chrome://extensions` |

---

## One Sentence Summary

**Popup** = quick scan. **Dashboard** = full view. **API** = the engine. All three work together. The extension does the rest automatically.


Extension - Added to Brave Browser Beta

Run from Terminal: gullwing serve

Full Output: 

# Generate an SBOM so the SBOM card populates
gullwing sbom /usr/bin --out /mnt/d/moabi/reports/latest_sbom.cdx.json

# Start the agent so quarantine stats are live
gullwing agent status

# The alert feed populates automatically when watch detects changes
