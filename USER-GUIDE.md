# Gullwing Protocol — Complete User Guide

## Quick Start

```bash
# For everyone
gullwing check /path/to/file        # Is this safe? (25ms)
gullwing scan /path/to/folder       # Check everything in a folder
gullwing protect                     # Activate bodyguard mode

# For IT staff
gullwing watch /path/to/directory   # Continuous monitoring
gullwing report                      # Generate compliance report
gullwing sbom /path/to/directory    # Generate SBOM (CycloneDX 1.6)

# For security teams
gullwing reflect /path/to/binary    # Full 8-layer analysis
gullwing delta old.json new.json    # Supply chain comparison
gullwing quarantine /path/to/file   # Isolate suspicious binary

# For experts
gullwing reflect --deep-memory /path/to/binary  # Deep analysis (3.4s)
cd wsolver && ./wsolve /path/to/binary          # Symbolic execution (optional)
```

## Start the Dashboard

```bash
./start-server.sh                    # Start API (port 9393)
cd src/extension && python3 -m http.server 8081 --bind 127.0.0.1 &
# Open http://127.0.0.1:8081/unified.html
```

## The 8-Layer Analysis

Gullwing examines binaries through 8 independent layers:

| Layer | What It Checks | Time |
|-------|---------------|------|
| 1. Identity | Path, size, SHA-256 | ~10ms |
| 2. Structure | ELF/PE format, sections | <1ms |
| 3. Semantics | Libraries, symbols | <1ms |
| 4. Entropy | Global/windowed entropy | <1ms |
| 5. Machine Learning | Weighted k-NN classification | ~12ms |
| 6. Runtime | Syscall profiling | ~35ms |
| 7. Memory | Page mappings, RWX detection | ~30ms |
| 8. Memory Differential | Disk vs memory comparison | ~30ms |

**Total: ~25ms static, ~3.4s deep**

## The Security Pipeline

```
DETECT → QUARANTINE → INVESTIGATE → EXPLAIN → DOCUMENT
(25ms)   (0.025s)     (optional)    (seconds)  (automated)
```

## Arcade Games (6 Total)

Learn binary security through play:

| Game | What You Learn | Command |
|------|---------------|---------|
| 🏌️ Assembly Golf | x86_64 assembly basics | `gullwing arcade 1` |
| 🦆 COBOL Quest | Banking bug hunting | `gullwing arcade cobol` |
| 🔍 Binary Detective | 8-layer analysis clues | `gullwing arcade detective` |
| 📊 Entropy Hunter | Packed malware detection | `gullwing arcade entropy` |
| 💰 Procurement Pursuit | Supply chain decisions | `gullwing arcade procurement` |
| 🌐 Fleet Commander | Distributed monitoring | `gullwing arcade fleet` |

## 15 Sector Sandboxes

Each sandbox demonstrates Gullwing in a specific sector:

```bash
./sandboxes/MockBank/demo.sh          # Private Banking
./sandboxes/CRA-Importers/demo.sh     # EU Importers
./sandboxes/PartyVault/demo.sh        # Clearing Houses
./sandboxes/TicketMaster/demo.sh      # Ticket Sales
./sandboxes/CasinoGuard/demo.sh       # Casinos
./sandboxes/StockMarket/demo.sh       # Stock Market
./sandboxes/Healthcare/demo.sh        # Healthcare (NHS)
./sandboxes/Energy/demo.sh            # Energy Grid
./sandboxes/Telecom/demo.sh           # Telecommunications
./sandboxes/Aviation/demo.sh          # Aviation
./sandboxes/Maritime/demo.sh          # Maritime
./sandboxes/Blockchain/demo.sh        # Blockchain
./sandboxes/Weapons/demo.sh           # Export Control
./sandboxes/Shipping/demo.sh          # Ship Manifests
./sandboxes/DiskGuardian/demo.sh      # Disk Guardian
```

## Bird Variants (Modular Tools)

| Variant | Simple Command | Purpose |
|---------|---------------|---------|
| Sandpiper | `gullwing check file` | Standalone analysis |
| Gannet | `gullwing fastscan folder` | High-velocity batch |
| Egret | `gullwing watch folder` | Continuous monitoring |
| Buzzard | `gullwing isolate file` | Binary quarantine |
| Curlew | `gullwing verify-supplier dir` | Supplier verification |
| Crane | `gullwing predict folder` | Strategic forecasting |
| Flamingo | `gullwing legal-check dir` | Legal text filter |
| Owl | `gullwing watch-rules` | Regulatory intelligence |
| Swan | `gullwing modernise file` | COBOL modernisation |
| Tern | `gullwing convert file` | COBOL→Rust |
| Skylark | `gullwing dora-check` | DORA compliance |
| Auto | `gullwing vehicle-check file` | Vehicle ECU |

## Compliance

### EU Cyber Resilience Act (CRA)
**Deadline:** September 11, 2026

Gullwing provides evidence for:
- ✅ SBOM (CycloneDX 1.6)
- ✅ Ed25519 attestation
- ✅ Supply chain verification
- ✅ 24-hour reporting capability
- ✅ Training records

### Other Frameworks
- ✅ CISA 8/8 Cybersecurity Goals
- ✅ DORA (ICT risk management)
- ✅ NIS2 (incident reporting)
- ✅ UN R155/R156 (vehicle ECU)
- ✅ KYC/AML (Party Vault)

## Resource Requirements

| Mode | CPU | RAM | Disk |
|------|-----|-----|------|
| Light watch | 1-2% | 30MB | 50MB core |
| Medium watch | 5-10% | 100MB | 50MB core |
| Deep scan | Moderate | 100MB | +quarantine |
| LLM (phi4-mini) | Moderate | 2.5GB | +model |
| LLM (qwen3.5:9b) | Moderate | 6.6GB | +model |
| wsolver Docker | High | 2-4GB | +5GB image |

**Gullwing is lightweight by design.** Heavy features are optional.

## Known Limitations

Gullwing is **both a detective AND a bodyguard** — it investigates AND it acts.

**Strongest at:**
- Binary analysis (25ms)
- Automated quarantine (0.025s)
- Compliance documentation
- Training games

**Partial coverage in:**
- Sandboxing (quarantine removes permissions, not process containment)
- Firewall (detects network anomalies, doesn't block ports)
- Antivirus (YARA rules, not real-time signature scanning)
- SIEM (exports STIX 2.1, not full log aggregation)

**Not covered:**
- Kernel-level attacks (Gullwing runs in userspace)
- Hardware attacks (physical access)
- Zero-days in Gullwing itself (mitigated by reflexive security)

## Witchcraft Solver (wsolver)

wsolver is **Jonathan Brossard's (@endrazine) research project**, included as a submodule. We have not independently verified its claims. Refer to the [wsolver README](https://github.com/endrazine/wsolver) for authoritative information.

**Gullwing is complete without wsolver.**

## Docker Setup (WSL)

On WSL, Docker stores images on C: drive by default. Move to D: drive:

```bash
sudo systemctl stop docker
sudo tee /etc/docker/daemon.json << 'EOF'
{"data-root": "/mnt/d/docker-data"}
EOF
sudo systemctl start docker
```

## Server Management

```bash
./kill-servers.sh        # Kill all Gullwing servers
./restart-everything.sh  # Clean restart
./server-control.sh status  # Check status
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Port 9393 in use | `./kill-servers.sh` |
| Port 8081 in use | `fuser -k 8081/tcp` |
| Frontend not loading | Start Python server (see Quick Start) |
| Docker image missing | `cd wsolver && make docker` |
| Ollama not responding | `sudo systemctl restart ollama` |

## Trust & Verification

Anyone can independently verify Gullwing:

1. Clone the repo and read every line (MIT)
2. Check published SHA-256 hashes
3. Reproduce the build
4. Run the tool on a known target
5. Review ML model integrity checks
6. Exercise quarantine on a test binary
7. Audit generated compliance reports

**We don't ask for trust — we provide the means to verify.**
