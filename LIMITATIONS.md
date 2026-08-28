# Gullwing Protocol — Known Limitations

## Honest Assessment (August 2026)

### What Gullwing Does Well
- Fast binary analysis (25ms static)
- Threat detection and quarantine
- CRA compliance documentation
- Training games
- 15 sector demos

### What Gullwing Does (With Nuance)

| Capability | What Gullwing Does | What It Doesn't Do |
|------------|-------------------|-------------------|
| **Sandbox** | Quarantine removes execute permissions (chmod 000) | Doesn't contain already-running processes |
| **Firewall** | Detects network anomalies via fleet bus | Doesn't block ports or filter packets |
| **Antivirus** | YARA integration (10,000+ rules) + LLM rule generation | Not a real-time signature scanner by default |
| **SIEM** | STIX 2.1 export, audit logs, evidence bundles | Doesn't replace Splunk/ELK for aggregation |
| **Formal verifier** | 8-layer analysis is heuristic, not proof | wsolver (separate project) may provide symbolic execution — see @endrazine's README |
| **Pentest suite** | Gullwing core does not perform penetration testing | wsolver is a separate research tool — we have not independently verified its capabilities |

**Bottom line:** Gullwing provides *partial* coverage in each area. It's strongest at binary analysis, quarantine, and compliance. It's weakest at network filtering and process containment.

### What Requires Understanding
- **ML confidence ≠ certainty** — 99.99% still means 1 in 10,000 wrong
- **Entropy ≠ malicious** — Packed binaries can be legitimate
- **Risk CLEAR ≠ safe to run** — No known indicators, not proof of safety
- **wsolver UNSAFE ≠ exploitable** — KLEE witnesses may be lifting artifacts

### Performance Boundaries
- **Static analysis:** ~25ms (fast, but shallow)
- **Deep analysis:** ~3.4s (deeper, but not exhaustive)
- **wsolver:** Minutes-hours (thorough, but research-grade)
- **LLM analysis:** Depends on model (helpful, but not authoritative)

### Platform Limitations
- **Linux/WSL/macOS:** Fully supported
- **Windows native:** Not supported (use WSL)
- **ARM/RISC-V:** Via QEMU only (slower)
- **PE binaries:** Via WCC conversion (some features limited)

### Scale Limitations
- **Single machine:** Default mode
- **Fleet mode:** Requires Headscale setup
- **Enterprise scale:** Untested at >1000 nodes

### Security Model
- **Quarantine:** Filesystem permissions (not kernel-level)
- **Attestation:** Ed25519 (not post-quantum yet)
- **ML model:** Could be evaded by sophisticated adversaries
- **Supply chain:** Detects changes, doesn't prevent them

## What This Means

Gullwing is **both a detective AND a bodyguard**.

As a **detective**, it investigates: "What is this binary? Has it changed? Is it suspicious?"

As a **bodyguard**, it acts: "This binary is quarantined. This change is blocked. This threat is isolated."

The difference from a human bodyguard? Gullwing never sleeps, never blinks, and reacts in 25 milliseconds.

For complete security, use Gullwing alongside:
- Firewalls (network protection)
- Sandboxes (execution isolation)
- SIEM (log aggregation)
- Antivirus (signature detection)
- Penetration testing (active exploitation)

**Gullwing's unique value:** Speed (25ms), automation (quarantine), and accessibility (Aunt Maggie can use it).

## Honest Pitch

> "Gullwing won't stop every attack. But it will tell you — in 25ms — if a binary has changed, if it looks suspicious, and if you should quarantine it. That's the first line of defense, not the last."

## Roadmap to Address Limitations

- [ ] Post-quantum signatures (CRYSTALS-Dilithium)
- [ ] Native Windows support
- [ ] Kernel-level quarantine
- [ ] Larger ML training dataset
- [ ] Enterprise-scale testing
- [ ] Formal verification integration
- [ ] SIEM connectors
- [ ] Sandbox integration


## About Witchcraft Solver (wsolver)

wsolver is **Jonathan Brossard's (@endrazine) research project**, not ours. We include it as a submodule for convenience, but:

- We have **not independently verified** its claims
- We have **not tested** it in production
- We **do not vouch for** its accuracy or completeness
- We **refer readers** to the [wsolver README](https://github.com/endrazine/wsolver) for authoritative information

**Our integration is experimental.** Use wsolver at your own discretion and refer to @endrazine's documentation for limitations, requirements, and proper usage.
