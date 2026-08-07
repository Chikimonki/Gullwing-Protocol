# MOABI — Convergent Binary Analysis Platform

**Version:** 1.0  
**Architecture:** Zig (core) + LuaJIT FFI (orchestration)  
**Principal Alignment:** EU Cyber Resilience Act (CRA) 2024, EU AI Act, Data Act 2025, NIS2, DORA, UK Security and Resilience Bill

---

## What MOABI Is

MOABI is an in-process, cross-platform binary evidence engine that independently observes what software actually contains and does — rather than trusting what publishers declare.

It produces:

- A **CycloneDX 1.6 counter-BOM** derived from observed file hashes, ELF/PE structure, and nested dependency graphs
- A **Model-BOM** recording the cryptographic identity, training lineage, and feature importance of the ML classifier
- A **scan manifest** recording scope, completeness, and tool provenance
- Per-binary **evidence objects** containing static structure, runtime syscall profiles, live memory telemetry, and ML verdict

The gap MOABI closes: most organisations treat SBOMs as compliance paperwork submitted by the publisher. MOABI independently verifies what shipped and ran.

---

## Regulatory Alignment

| Regulation | Requirement | MOABI Evidence |
|---|---|---|
| **CRA 2024 Art. 10** | Vulnerability handling | Per-binary hash + ELF/PE dependency graph |
| **CRA 2024 Art. 13** | Exploitation mitigation | Runtime syscall profile + memory entropy |
| **CRA 2024 Art. 14** | Incident reporting | Signed scan manifest + evidence trail |
| **EU AI Act Art. 13** | Transparency | Model-BOM: training data, hyperparameters, explainability |
| **EU AI Act Art. 15** | Accuracy | LOO cross-validation accuracy recorded in Model-BOM |
| **Data Act 2025** | Data portability | CycloneDX JSON — machine-readable, schema-validated |
| **NIS2 Art. 21** | Supply chain security | Counter-BOM: declared vs observed comparison |
| **DORA Art. 6** | ICT risk management | Evidence objects + risk/novelty verdict per binary |
| **UK Security & Resilience Bill** | Critical infrastructure | Cross-platform scan: Linux ELF + Windows PE |

---

## Architecture: Seven-Layer Reflective Evidence

```text
Binary on disk or in memory
          │
┌─────────▼──────────────────────────────────────────┐
│  Layer 1 — Identity                                │
│  SHA-256 hash, file size, path, execution flag     │
├────────────────────────────────────────────────────┤
│  Layer 2 — Structure                               │
│  ELF/PE header, section count, type, architecture │
├────────────────────────────────────────────────────┤
│  Layer 3 — Semantics                               │
│  Dynamic dependencies, symbol families, toolchain  │
├────────────────────────────────────────────────────┤
│  Layer 4 — Entropy Profile                         │
│  Shannon entropy, windowed variance, packer signal │
├────────────────────────────────────────────────────┤
│  Layer 5 — Machine Learning                        │
│  28-feature weighted k-NN, risk/novelty scores     │
├────────────────────────────────────────────────────┤
│  Layer 6 — Runtime                                 │
│  strace syscall histogram, network, execve         │
├────────────────────────────────────────────────────┤
│  Layer 7 — Memory Telemetry                        │
│  /proc/pid/maps, executable page entropy, RWX      │
└────────────────────────────────────────────────────┘
          │
┌─────────▼──────────────────────────────────────────┐
│  Convergence Engine                                │
│  Risk:    CLEAR / NOTABLE / SUSPICIOUS / HOSTILE   │
│  Novelty: NORMAL / ELEVATED / EXTREME              │
│  Evidence: corroborated multi-stream verdict       │
└────────────────────────────────────────────────────┘
Performance:

Operation	Time
Static 7-layer analysis	~100 ms
ML classification only	~12 ms
Memory telemetry only	~30 ms
Full analysis + strace	~200 ms
CycloneDX SBOM generation	~5 ms per binary
The Counter-BOM Concept
Standard SBOM tooling (cdxgen, syft, trivy) generates a BOM from source manifests, build metadata, or package databases. That BOM reflects what the developer declared.

MOABI generates a BOM from the delivered binary on disk:

text

Publisher declares:       MOABI observes:
notepad.exe               notepad.exe
 └─ imports:               └─ SHA-256: confirmed / CHANGED
     kernel32.dll           └─ imports: 55 DLLs, 310 functions
     user32.dll             └─ entropy: 6.4826
     gdi32.dll              └─ suspicious: CreateProcessW [medium]
                            └─ amdxc64.so (ELF inside System32)
The delta between declared and observed is where supply-chain compromise, tampering, and undeclared dependencies live.

Output Artifacts
Every MOABI scan produces four artefacts:

text

/mnt/d/moabi/releases/<timestamp>/
├── software.cdx.json       CycloneDX 1.6 counter-BOM
├── modelbom.json           AI/ML Model Bill of Materials
├── scan-manifest.json      Scope, completeness, and provenance
├── SHA256SUMS              Integrity checksums
└── evidence/               Per-binary evidence objects (JSON)
    ├── notepad.exe.evidence.json
    ├── moabi-entropy.evidence.json
    └── ...
CycloneDX 1.6 Counter-BOM (software.cdx.json)
Standards-compliant CycloneDX with MOABI extensions embedded as moabi:* properties:

JSON

{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "components": [
    {
      "bom-ref": "urn:moabi:sha256:459c937b...",
      "type": "application",
      "name": "curl",
      "hashes": [{ "alg": "SHA-256", "content": "459c937b..." }],
      "properties": [
        { "name": "moabi:format",  "value": "ELF" },
        { "name": "moabi:entropy", "value": "6.4184" },
        { "name": "moabi:risk",    "value": "CLEAR" },
        { "name": "moabi:novelty", "value": "ELEVATED" }
      ]
    }
  ]
}
Compatible with the CycloneDX Transparency Exchange API (Koala).

Model-BOM (modelbom.json)
Records the classifier's complete lineage in compliance with EU AI Act Article 13 transparency requirements:

JSON

{
  "bomFormat": "MOABI-ModelBOM",
  "metadata": {
    "model_hash": "b7ba2a67...",
    "provenance": {
      "engine": "moabi-ml",
      "normalization_algorithm": "Online Welford Incremental"
    }
  },
  "hyperparameters": {
    "algorithm": "Weighted k-Nearest Neighbors",
    "k": 5,
    "anomaly_threshold": 3.3005
  },
  "dataset": {
    "total_samples": 773,
    "features_dimension": 28
  },
  "explainability": {
    "method": "Permutation Importance (LOO accuracy drop)",
    "baseline_accuracy": 0.8926,
    "metrics": { "ff_ratio": 0.0427, "entropy_variance": 0.0453 }
  }
}
Usage
Full reflective analysis
Bash

luajit /mnt/d/moabi/src/moabi-reflect.lua /usr/bin/curl
luajit /mnt/d/moabi/src/moabi-reflect.lua /mnt/c/Windows/System32/notepad.exe --static-only
CycloneDX counter-BOM generation
Bash

# Linux binaries
luajit /mnt/d/moabi/src/moabi-sbom.lua /mnt/d/moabi/bin \
    --out /mnt/d/moabi/reports/moabi-software.cdx.json

# Windows System32
luajit /mnt/d/moabi/src/moabi-sbom.lua /mnt/c/Windows/System32 \
    --out /mnt/d/moabi/reports/windows-system32.cdx.json
Terminal dashboard
Bash

luajit /mnt/d/moabi/src/moabi-view.lua \
    /mnt/d/moabi/reports/moabi-software.cdx.json
ML training and validation
Bash

luajit /mnt/d/moabi/src/moabi-ml.lua train \
    /mnt/d/moabi/reports/training \
    /mnt/d/moabi/reports/system.model

luajit /mnt/d/moabi/src/moabi-ml.lua validate \
    /mnt/d/moabi/reports/system.model
Model-BOM
Bash

luajit /mnt/d/moabi/src/moabi-model-bom.lua \
    /mnt/d/moabi/reports/system.model
Tier-2 QEMU escalation
Bash

luajit /mnt/d/moabi/src/moabi-qemu.lua /usr/bin/curl
luajit /mnt/d/moabi/src/moabi-qemu.lua \
    /mnt/d/moabi/bin/libmoabi-arm64.so --arch arm64
Release artifact generation
Bash

/mnt/d/moabi/src/moabi-release.sh /mnt/d/moabi/bin
Component Map
text

/mnt/d/moabi/src/
├── moabi-reflect.lua       Canonical entry point — 7-layer orchestration
├── moabi-evidence.lua      Evidence schema, convergence, risk/novelty split
├── moabi-features.lua      28-dimensional feature extractor (ELF + FFI)
├── moabi-ml.lua            Weighted k-NN classifier, Welford normalisation
├── moabi-pe.lua            Windows PE/COFF static analyser
├── moabi-memory.lua        Live process memory telemetry (/proc/pid/mem)
├── moabi-diff.lua          Disk vs memory entropy differential
├── moabi-qemu.lua          Tier-2 QEMU user-mode escalation
├── moabi-sbom.lua          CycloneDX 1.6 counter-BOM generator
├── moabi-model-bom.lua     AI/ML Model-BOM generator
├── moabi-view.lua          Terminal dashboard for CycloneDX JSON
├── moabi-ffi2.lua          Zig → LuaJIT zero-copy FFI bridge
└── moabi-release.sh        Release artifact packaging

/mnt/d/moabi/bin/
├── libmoabi.so             Compiled Zig FFI core (x86-64)
├── libmoabi-arm64.so       ARM64 cross-target
└── libmoabi-riscv64.so     RISC-V cross-target
Data Act 2025 and EU Omnibus
The EU Data Act 2025 adds three obligations directly relevant to MOABI:

1. Data portability (Article 23)

Software and embedded device manufacturers must make operational data available in interoperable formats. MOABI's CycloneDX output satisfies this for binary-level operational evidence. The moabi:* property namespace is interoperable with any CycloneDX consumer including the Transparency Exchange API.

2. Cloud switching (Article 25)

Organisations must be able to export and port their data from cloud services. A counter-BOM generated by MOABI from the delivered cloud agent binary provides independent verification that the binary matches what the cloud provider declared — without relying on the provider's own attestation.

3. Smart connected products (Article 4)

Manufacturers of connected products (IoT, embedded systems) must provide access to product-generated data. For firmware and embedded ELF binaries on such devices, MOABI can generate a counter-BOM from the delivered firmware image via /mnt/ mount points or extracted filesystem images.

The relevant integration point is:

text

Manufacturer's SBOM → CycloneDX Transparency Exchange
MOABI counter-BOM   → CycloneDX Transparency Exchange
Regulator queries   → Transparency Exchange compares both
This is the "trust and verify" architecture the Data Act envisions but does not specify technically. MOABI provides the observation layer.

v2.0 Roadmap
Component	Capability	Status
moabi-memory_v1.3.lua	Differential disk-vs-memory entropy	In development
moabi-qemu-system.lua	Full VM containment + guest memory	Planned
moabi-pe-runtime.lua	PE runtime via Wine/guest agent	Planned
Training expansion	50+ samples per class → 95%+ accuracy	Ongoing
Signing integration	minisign / cosign for release artefacts	Planned
Intellectual Context
Lua is Portuguese for moon. The moon reflects.

MOABI is named for the reflective principle at its core. The Zig engines generate analytical light; LuaJIT reflects and integrates it into a coherent evidence object. Every verdict is traceable to the evidence that produced it. Every evidence object records its own provenance. The system can examine its own reasoning.

This is not compliance paperwork. It is forensic science.

Licence
Copyright © 2026 CCUK. All rights reserved.

This software is provided for research and evaluation purposes.
Contact the author before redistribution or commercial deployment.
