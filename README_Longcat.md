# MOABI — Reflective Binary Analysis Platform

**Lua = moon = reflection.** MOABI is a seven-layer binary analysis engine that
reflects the structural, semantic, behavioral, and memory reality of a binary
into a single coherent evidence object.

MOABI does not replace human judgment. It makes that judgment auditable.

---

## Architecture
Binary
│
▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Identity path, size, SHA-256, executable │
│ Layer 2: Structure ELF headers, sections, imports │
│ Layer 3: Semantics libraries, symbols, toolchain │
│ Layer 4: Entropy global + windowed byte entropy │
│ Layer 5: ML 30-feature k-NN classification │
│ Layer 6: Runtime live syscall profiling (strace) │
│ Layer 7: Memory post-load page inspection │
└─────────────────────────────────────────────────────────────┘
│
▼
Evidence Object (moabi-evidence)
│
▼
Convergence / Policy Engine
│
▼
Risk + Novelty Verdict

text


### Layer descriptions

| Layer | Source | What it reveals |
|---|---|---|
| Identity | file I/O | What file is this? |
| Structure | ELF header bytes | What shape is it? |
| Semantics | FFI + string scan | What does it link against? |
| Entropy | byte histogram | How random is the content? |
| ML | k-NN on 30 features | What known family is it closest to? |
| Runtime | strace | What syscalls does it actually make? |
| Memory | /proc/pid/maps + /proc/pid/mem | What does it look like after loading? |

### The verdict is two-dimensional
Risk: CLEAR / NOTABLE / SUSPICIOUS / HOSTILE
Novelty: NORMAL / ELEVATED / EXTREME

text


A binary can be novel without being hostile. A binary can be familiar yet
corrupted. MOABI reports both axes independently.

---

## Components

| File | Purpose |
|---|---|
| `src/moabi-reflect.lua` | Single entry point — orchestrates all 7 layers |
| `src/moabi-features.lua` | Canonical 30-feature extractor |
| `src/moabi-evidence.lua` | Evidence grammar + convergence engine |
| `src/moabi-ml.lua` | k-NN classifier with permutation importance |
| `src/moabi-memory.lua` | Live process memory inspection |
| `src/moabi-qemu.lua` | Tier-2 QEMU user-mode escalation |
| `src/moabi-sbom.lua` | Batch scanning + SBOM manifest generation |
| `src/moabi-ffi2.lua` | Zig FFI bridge for structural ELF features |
| `src/collect-samples-v2.sh` | Training data collector |

---

## Usage

```bash
# Single binary analysis
luajit src/moabi-reflect.lua /usr/bin/curl

# With JSON export
luajit src/moabi-reflect.lua /usr/bin/curl --json

# Static only (no runtime profiling)
luajit src/moabi-reflect.lua /usr/bin/curl --static-only

# Batch SBOM scan
luajit src/moabi-sbom.lua /mnt/d/moabi/bin --static-only

# Tier-2 QEMU escalation
luajit src/moabi-qemu.lua /path/to/suspicious

# Retrain model
luajit src/moabi-ml.lua train reports/training reports/system.model

# Validate + feature importance
luajit src/moabi-ml.lua validate reports/system.model
Training
The model at reports/system.model was trained on 139 binaries across 8
classes:

Class	Samples
system_utility	55
shared_library	29
text_tool	15
network_tool	13
moabi_tool	10
compression	8
interpreter	5
shell	4
Cross-validation accuracy: 89.8%

To add new training samples:

Bash

mkdir -p reports/training/<class_name>
cp <binary> reports/training/<class_name>/
luajit src/moabi-ml.lua train reports/training reports/system.model
Performance
Phase	Typical time
Static triage (Layers 1-5)	10-15 ms
Runtime profiling (Layer 6)	30-60 ms
Memory inspection (Layer 7)	30-100 ms
Full analysis	80-170 ms
Measured on WSL2, x64, NVMe storage.

v1.0 Status
Complete. All seven layers functional. SBOM export working. QEMU Tier-2
escalation functional for cross-architecture triage.

v2.0 Roadmap
Milestone	Description
Memory v1.3	Disk-vs-runtime executable segment entropy comparison
QEMU System Mode	Full guest containment with memory snapshot capability
Training data expansion	30+ samples per class for 95%+ accuracy
Semantic cleanup	Distinguish DT_NEEDED from string-scan indicators
Design principles
Evidence over labels. A class label is one input to a verdict, not the
verdict itself.
Convergence over voting. Independent evidence streams are correlated,
not counted.
Honesty over confidence. If the model has not seen a family, it says so.
Reflection over replacement. The platform makes human judgment
auditable; it does not replace it.
License
CRA 2024 / EU Cyber Resilience Act guideline-compliant binary analysis.
Built for high-assurance environments where interpretability matters more than
raw throughput.

text


---

## Final lock commands

```bash
cd /mnt/d/moabi
cat > archive/v1.0/LOCK.md <<'EOF'
MOABI v1.0 LOCKED
Date: 2026-07-17
Accuracy: 89.8% (139 samples, 8 classes)
Layers: 7/7 functional
SBOM: working
QEMU Tier-2: working (user-mode)
Memory: working (post-load inspection)

Known limitations:
- Training data imbalance (interpreter=5, shell=4)
- QEMU user-mode is not a security boundary
- String-scan library detection may produce false positives
- Memory timing varies 30-100ms under WSL scheduling

Next: v2.0 = Memory v1.3 + QEMU System Mode + training expansion
EOF
Summary
text

v1.0: locked
  7 layers
  89.8% accuracy
  80-170ms full analysis
  SBOM export
  QEMU user-mode Tier-2

v2.0: next
  Memory v1.3 (disk-vs-runtime segment entropy)
  QEMU System Mode (true containment)
  Training expansion (30+/class)
