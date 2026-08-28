# Gullwing Protocol — Known Limitations

## Honest Assessment (August 2026)

### What Gullwing Does Well
- Fast binary analysis (25ms static)
- Threat detection and quarantine
- CRA compliance documentation
- Training games
- 15 sector demos

### What Gullwing Does NOT Do (Yet)
- **Not a sandbox** — Quarantine isolates files but doesn't contain execution
- **Not a firewall** — Network-level protection is outside scope
- **Not an antivirus** — Doesn't scan for known malware signatures by default
- **Not a SIEM** — Doesn't replace Splunk/ELK for log aggregation
- **Not a formal verifier** — 8-layer analysis is heuristic, not proof
- **Not a penetration testing suite** — wsolver finds some bugs, not all

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

Gullwing is a **detective**, not a **bodyguard**. It tells you what's wrong. It doesn't physically prevent attacks.

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
