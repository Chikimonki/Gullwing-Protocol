## Gullwing Protocol — Complete Security Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CRA Ready](https://img.shields.io/badge/CRA-Sep%2011%2C%202026-blue)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
[![CISA Submitted](https://img.shields.io/badge/CISA-Submitted-green)](https://www.cisa.gov)
[![Open Source](https://img.shields.io/badge/Open%20Source-100%25-brightgreen)](https://github.com/Chikimonki/Gullwing-Protocol)
[![Lua](https://img.shields.io/badge/Lua-74.7%25-blue)](https://www.lua.org)
[![Zig](https://img.shields.io/badge/Zig-14.7%25-orange)](https://ziglang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL%20%7C%20macOS-lightgrey)](https://github.com/Chikimonki/Gullwing-Protocol)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen)](https://github.com/Chikimonki/Gullwing-Protocol/pulls)
[![Stars](https://img.shields.io/github/stars/Chikimonki/Gullwing-Protocol?style=social)](https://github.com/Chikimonki/Gullwing-Protocol/stargazers)
[![Forks](https://img.shields.io/github/forks/Chikimonki/Gullwing-Protocol?style=social)](https://github.com/Chikimonki/Gullwing-Protocol/forks)


**A complete security department in a box: detect, audit, comply, and explain — fully open-source, fully air-gapped, running on your infrastructure.**

*"The Cormorant dives. The Gullwing watches. The Kestrel carries. The Solver proves."*

---

### What It Is

Gullwing Protocol bundles four purpose-built components — a binary analyst, a vulnerability auditor, a compliance officer, and a local AI explainer — into one MIT-licensed suite. No cloud, no API keys, no per-seat licensing. Everything runs on hardware you control.

| # | Component | Role | Capabilities |
|---|-----------|------|--------------|
| 1 | 🦅 Gullwing Cormorant | Detective | 8-layer convergent binary analysis · ~25 ms static analysis · automated quarantine · CRA evidence generation |
| 2 | 🔍 Witchcraft Solver | Auditor | Vulnerability research via symbolic execution · concrete exploitation witnesses · works on stripped binaries |
| 3 | 🏛 Party Vault | Compliance Officer | KYC/AML verification · regulatory classification · LEI validation (ISO 17442) · audit-trail generation |
| 4 | 🤖 Kestrel | AI Analyst | Local-LLM analysis · security implications · plain-English explanations · air-gapped capable |

---

### Why Gullwing

#### 1. Data Sovereignty

The strongest reason to choose Gullwing — full data sovereignty:

| | Cloud tools | Gullwing |
|---|-------------|----------|
| Data location | Third-party servers | Your infrastructure |
| API keys | Required | None |
| Internet needed | Yes | No — fully air-gapped |

Ideal for air-gapped and network-isolated environments, for banks and critical-infrastructure operators that must keep data in-country (GDPR, PSD2), and for anyone who cannot accept third-party data exposure.

#### 2. Open, Auditable, Independently Verifiable

Not "trust us" — "verify it yourself."

- MIT-licensed, every line public and auditable.
- Published SHA-256 hashes for released artifacts.
- Reproducible builds so anyone can rebuild and confirm the binary matches.
- The tool can also monitor its own integrity at runtime.

The trust anchor is that a third party can independently rebuild, hash, and verify — not that the tool vouches for itself.

#### 3. A Polyglot, Diverse Stack

Gullwing uses the best tool for each layer:

| Layer | Language | Why |
|-------|----------|-----|
| Orchestration | LuaJIT FFI | Lightweight, embeddable glue |
| Compute kernels | Zig | Fast systems code with strong safety tooling |
| Distributed bus | Elixir/Phoenix PubSub | Resilient fleet messaging |
| Ingestion | Perl | Battle-tested text/record processing |

This diversity is an engineering strength — each layer uses a fit-for-purpose technology, and the codebase stays small and auditable.

#### 4. Fast Enough for Continuous Monitoring

Typical measured figures (your mileage varies by hardware):

| Capability | Typical |
|------------|---------|
| Static analysis | ~25 ms per binary |
| Supply-chain change detection | ~2 s |
| Watch mode | Real-time directory monitoring |
| Automated quarantine | On detection, without human intervention |

Watch mode + automated response means Gullwing can run continuously, flagging and isolating changes as they happen.

#### 5. Regulatory Alignment

Gullwing helps you prepare evidence for the regimes below. (It assists compliance; the legal obligation remains with the regulated organisation.)

| Regime | Relevant Gullwing capability | Key dates |
|--------|------------------------------|-----------|
| EU Cyber Resilience Act | CycloneDX 1.6 SBOM · binary-delta supply-chain verification · incident data capture (STIX 2.1) | Reporting duties begin 11 Sept 2026; full conformity 11 Dec 2027 |
| DORA | ICT risk management · digital operational resilience · incident reporting | Applicable from 17 January 2025 |
| CISA no-cost services | Self-assessed mapping to CISA's cybersecurity services | — |
| NIS2 | Incident data capture & supply-chain visibility | — |
| UN R155/R156 (vehicle ECU) | Gullwing-Auto binary protection | — |
| KYC/AML | Party Vault | — |

⚠️ Gullwing generates and organises the technical evidence. It does not replace legal advice or a formal conformity assessment.

#### 6. No Recurring Costs

No per-seat licensing, no cloud fees, no API charges. MIT-licensed and local — you pay once in hardware and never in subscription.

#### 7. Training Built In

Six arcade-style games teach binary-security fundamentals — a genuinely unusual way to build team intuition. (A differentiator, not a compliance checkbox.)

#### 8. Sector Demonstrations

Fourteen sandboxed demonstrations show Gullwing against realistic sector data:

🏦 Private Banking · 🇪🇺 CRA Importers · 🏛 Clearing Houses · 🎟 Ticketing · 🎰 Gaming & Casinos · 📈 Exchanges · 🏥 Healthcare · ⚡ Energy Grid · 📡 Telecoms · ✈️ Aviation · 🚢 Maritime · ⛓ Blockchain · 🏭 Critical Manufacturing · 📦 Ship Manifests

#### 9. Roadmap

- **Post-quantum signatures** — Ed25519 attestation today; a migration path to post-quantum signatures (e.g. CRYSTALS-Dilithium) as standards mature. (Ed25519 itself is not post-quantum.)
- **Model-BOM readiness** for emerging AI-regulation requirements.
- **Extensible 8-layer model** — the community can add layers and integrations.

---

### Quick Start

```bash
# Clone the suite
git clone https://github.com/Chikimonki/Gullwing-Protocol.git
cd Gullwing-Protocol

# Initialize submodules
git submodule update --init --recursive

# Run the security pipeline on a target binary
./scripts/security-pipeline.sh /usr/bin/ls

# Run all demos
./scripts/run-ultimate-suite.sh
```

---

### Trust & Verification Checklist

Anyone can independently verify Gullwing:

1. Clone the repo and read every line (MIT).
2. Check the published SHA-256 hashes of release artifacts.
3. Reproduce the build and confirm the binary matches its hash.
4. Run the tool on a known target and inspect the output.
5. Review the ML model integrity checks.
6. Exercise the quarantine feature on a test binary.
7. Audit the generated compliance reports.

**We don't ask for trust — we provide the means to verify.**

---

### Summary

| | |
|---|---|
| **SOVEREIGNTY** | Air-gapped — your data never leaves your network |
| **OPEN** | MIT-licensed — independently rebuildable and verifiable |
| **SPEED** | ~25ms analysis · ~2s supply-chain detection |
| **COMPLIANCE** | Evidence generation for CRA · DORA · CISA · NIS2 · UN R155/R156 · KYC/AML |
| **COST** | $0 licensing · $0 cloud · $0 API |
| **TRAINING** | 6 games that teach binary security |
| **COVERAGE** | 14 sector demonstrations |
| **ROADMAP** | Post-quantum-ready · AI-regulation-ready · extensible |

---

### License

MIT — 100% open source.

---

*A complete security department in a box — detect, audit, comply, explain. On your hardware.*

## ⚠️ Docker Requirements (Optional)

The Witchcraft Solver (wsolver) has two modes:

### Basic Mode (No Docker Required)
```bash
cd wsolver
make        # Builds native tools (~1MB)
./wsolve <binary>
Works for basic binary analysis.

Full Mode (Docker Required — ~5GB)
bash
cd wsolver
make docker # Builds solver image (KLEE, SeaHorn, SMACK, IKOS)
Requires ~5GB disk space. On WSL, ensure Docker data is on D: drive:
See WSL-DOCKER-SETUP.md for instructions.

Note: The core Gullwing Protocol (detection, quarantine, AI analysis) works without Docker.
