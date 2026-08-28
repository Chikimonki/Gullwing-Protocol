# Gullwing Protocol — Detailed User Guide

## Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Core Components](#core-components)
4. [The 8-Layer Analysis](#the-8-layer-analysis)
5. [Security Pipeline](#security-pipeline)
6. [Arcade Games](#arcade-games)
7. [15 Sector Sandboxes](#15-sector-sandboxes)
8. [Compliance](#compliance)
9. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites
- LuaJIT 2.1+
- Python 3.8+
- Docker (optional, for wsolver)
- Ollama (optional, for AI analysis)

### Clone and Setup
```bash
git clone https://github.com/Chikimonki/Gullwing-Protocol.git
cd Gullwing-Protocol
git submodule update --init --recursive
Build
bash
# Build core tools
make

# Build wsolver (optional)
cd wsolver && make && cd ..
Quick Start
1. Start the Server
bash
./start-server.sh
2. Analyze a Binary
bash
gullwing reflect /usr/bin/ls
3. Run the Security Pipeline
bash
./security-pipeline.sh /path/to/binary
4. Open the Frontend
bash
cd src/extension
python3 -m http.server 8081 --bind 127.0.0.1 &
# Open http://127.0.0.1:8081/unified.html
Core Components
1. 🦅 Gullwing Cormorant (Detective)
Purpose: Binary analysis and threat detection

Commands:

bash
gullwing reflect <binary>           # 8-layer analysis
gullwing watch <directory>          # Real-time monitoring
gullwing quarantine <binary>        # Isolate suspicious binary
gullwing delta <old> <new>          # Supply chain comparison
gullwing sbom <directory>           # Generate SBOM
2. 🔍 Witchcraft Solver (Auditor)
Purpose: Vulnerability discovery

Commands:

bash
cd wsolver
./wsolve <binary>                   # Find vulnerabilities
./wsolve <binary> <output_dir>      # Custom output location
3. 🏛 Party Vault (Compliance Officer)
Purpose: Regulatory compliance

Features:

KYC/AML verification

LEI validation (ISO 17442)

Regulatory classification

Audit trail generation

4. 🤖 Kestrel (AI Analyst)
Purpose: Plain-English security explanations

Commands:

bash
gullwing ask <binary> "What are the security implications?"
The 8-Layer Analysis
Gullwing's convergent model examines binaries through 8 independent layers:

text
Layer 1: IDENTITY     — Path, size, SHA-256 hash
Layer 2: STRUCTURE    — ELF/PE format, sections, imports
Layer 3: SEMANTICS    — Libraries, symbols, strings
Layer 4: ENTROPY      — Global and windowed entropy
Layer 5: ML           — Weighted k-NN classification
Layer 6: RUNTIME      — Syscall profiling
Layer 7: MEMORY       — Page mappings, RWX detection
Layer 8: MEMORY DIFF  — Disk vs memory comparison
No single layer is trusted. Agreement between layers produces truth.

Security Pipeline
The complete pipeline runs in 5 phases:

Phase 1: Detect (25ms)
bash
gullwing reflect /path/to/binary
Output: Risk score, novelty score, ML classification

Phase 2: Quarantine (0.025s)
bash
gullwing quarantine /path/to/binary
Output: Isolated binary, forensic copy, audit record

Phase 3: Investigate
bash
wsolve /path/to/binary
Output: Vulnerability report with exploitation witnesses

Phase 4: Explain
bash
gullwing ask /path/to/binary "What are the implications?"
Output: Plain-English security analysis

Phase 5: Document
bash
gullwing sbom /path/to/directory
Output: CRA-compliant SBOM, attestation, reports

Arcade Games
6 Training Games:
🏌️ Assembly Golf — Learn x86_64 assembly

bash
gullwing arcade 1
🦆 COBOL Quest — Find banking bugs

bash
gullwing arcade cobol
🔍 Binary Detective — Identify binaries from clues

bash
gullwing arcade detective
📊 Entropy Hunter — Detect packed malware

bash
gullwing arcade entropy
💰 Procurement Pursuit — Supply chain decisions

bash
gullwing arcade procurement
🌐 Fleet Commander — Monitor distributed systems

bash
gullwing arcade fleet
15 Sector Sandboxes
Each sandbox demonstrates Gullwing in a specific sector:

Sandbox	Sector	Demo Command
MockBank	Banking	cd sandboxes/MockBank && ./bank-demo.sh
CRA-Importers	Importers	cd sandboxes/CRA-Importers && ./cra-compliance-check.sh
PartyVault	Clearing Houses	cd sandboxes/PartyVault && ./party-vault-demo.sh
TicketMaster	Tickets	cd sandboxes/TicketMaster && ./verify-tickets.sh
CasinoGuard	Casinos	cd sandboxes/CasinoGuard && ./verify-casino.sh
StockMarket	Trading	cd sandboxes/StockMarket && ./verify-market.sh
Healthcare	Medical	cd sandboxes/Healthcare && ./verify-healthcare.sh
Energy	Grid	cd sandboxes/Energy && ./verify-energy.sh
Telecom	Networks	cd sandboxes/Telecom && ./verify-telecom.sh
Aviation	Flight	cd sandboxes/Aviation && ./verify-aviation.sh
Maritime	Navigation	cd sandboxes/Maritime && ./verify-maritime.sh
Blockchain	Crypto	cd sandboxes/Blockchain && ./verify-blockchain.sh
Weapons	Arms	cd sandboxes/Weapons && ./verify-weapons.sh
Shipping	Cargo	cd sandboxes/Shipping && ./verify-shipping.sh
DiskGuardian	Disk	cd sandboxes/DiskGuardian && ./monitor-disk.sh
Compliance
EU Cyber Resilience Act (CRA)
Deadline: September 11, 2026

Gullwing provides:

✅ SBOM generation (CycloneDX 1.6)

✅ Ed25519 attestation

✅ 24-hour exploit reporting

✅ Supply chain verification

✅ Training records

CISA 8/8 Goals
✅ Vulnerability Scanning

✅ Cyber Hygiene

✅ Supply Chain Risk Management

✅ Incident Response

✅ Threat Intelligence Sharing

✅ Ransomware Readiness

✅ Cloud Security

✅ ICS/OT Security

DORA
✅ ICT risk management

✅ Digital operational resilience

✅ Incident reporting

Troubleshooting
Server won't start (port 9393 in use)
bash
./server-control.sh restart
Docker build fails (wsolver)
bash
# Move Docker to D: drive
sudo tee /etc/docker/daemon.json << 'EOF'
{
  "data-root": "/mnt/d/docker-data"
}
