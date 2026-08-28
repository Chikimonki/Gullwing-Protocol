Gullwing Protocol — Complete Security Suite
License: MIT
Tests
CRA
CISA
Open Source
Lua
Zig
Platform
PRs Welcome
Stars
Forks

A complete security department in a box: detect, audit, comply, and explain — fully open-source, fully air-gapped, running on your infrastructure.

"The Cormorant dives. The Gullwing watches. The Kestrel carries. The Solver proves."

What It Is
Gullwing Protocol bundles four purpose-built components — a binary analyst, a vulnerability auditor, a compliance officer, and a local AI explainer — into one MIT-licensed suite. No cloud, no API keys, no per-seat licensing. Everything runs on hardware you control.

#	Component	Role	Capabilities
1	🦅 Gullwing Cormorant	Detective	8-layer convergent binary analysis · ~25 ms static analysis · automated quarantine · CRA evidence generation
2	🔍 Witchcraft Solver	Auditor	Vulnerability research via symbolic execution · concrete exploitation witnesses · works on stripped binaries
3	🏛 Party Vault	Compliance Officer	KYC/AML verification · regulatory classification · LEI validation (ISO 17442) · audit-trail generation
4	🤖 Kestrel	AI Analyst	Local-LLM analysis · security implications · plain-English explanations · air-gapped capable
Why Gullwing
1. Data Sovereignty
The strongest reason to choose Gullwing — full data sovereignty:

Cloud tools	Gullwing
Data location	Third-party servers	Your infrastructure
API keys	Required	None
Internet needed	Yes	No — fully air-gapped
Ideal for air-gapped and network-isolated environments, for banks and critical-infrastructure operators that must keep data in-country (GDPR, PSD2), and for anyone who cannot accept third-party data exposure.

2. Open, Auditable, Independently Verifiable
Not "trust us" — "verify it yourself."

MIT-licensed, every line public and auditable.
Published SHA-256 hashes for released artifacts.
Reproducible builds so anyone can rebuild and confirm the binary matches.
The tool can also monitor its own integrity at runtime.
The trust anchor is that a third party can independently rebuild, hash, and verify — not that the tool vouches for itself.

3. A Polyglot, Diverse Stack
Gullwing uses the best tool for each layer:

Layer	Language	Why
Orchestration	LuaJIT FFI	Lightweight, embeddable glue
Compute kernels	Zig	Fast systems code with strong safety tooling
Ingestion & glue	Perl	Battle-tested text/record processing
Tooling, demos & reporting	Python	Fast iteration for pipelines and analysis harnesses
This diversity is an engineering strength — each layer uses a fit-for-purpose technology, and the codebase stays small and auditable.

4. Fast Enough for Continuous Monitoring
Typical measured figures (your mileage varies by hardware):

Capability	Typical
Static analysis	~25 ms per binary
Supply-chain change detection	~2 s
Watch mode	Real-time directory monitoring
Automated quarantine	On detection, without human intervention
Watch mode + automated response means Gullwing can run continuously, flagging and isolating changes as they happen.

5. Regulatory Alignment
Gullwing helps you prepare evidence for the regimes below. (It assists compliance; the legal obligation remains with the regulated organisation.)

Regime	Relevant Gullwing capability	Key dates
EU Cyber Resilience Act	CycloneDX 1.6 SBOM · binary-delta supply-chain verification · incident data capture (STIX 2.1)	Reporting duties begin 11 Sept 2026; full conformity 11 Dec 2027
DORA	ICT risk management · digital operational resilience · incident reporting	Applicable from 17 January 2025
CISA no-cost services	Self-assessed mapping to CISA's cybersecurity services	—
NIS2	Incident data capture & supply-chain visibility	—
UN R155/R156 (vehicle ECU)	Gullwing-Auto binary protection	—
KYC/AML	Party Vault	—
⚠️ Gullwing generates and organises the technical evidence. It does not replace legal advice or a formal conformity assessment.

6. No Recurring Costs
No per-seat licensing, no cloud fees, no API charges. MIT-licensed and local — you pay once in hardware and never in subscription.

7. Training Built In
Six arcade-style games teach binary-security fundamentals — a genuinely unusual way to build team intuition. (A differentiator, not a compliance checkbox.)

8. Sector Demonstrations
Fourteen sandboxed demonstrations show Gullwing against realistic sector data:

🏦 Private Banking · 🇪🇺 CRA Importers · 🏛 Clearing Houses · 🎟 Ticketing · 🎰 Gaming & Casinos · 📈 Exchanges · 🏥 Healthcare · ⚡ Energy Grid · 📡 Telecoms · ✈️ Aviation · 🚢 Maritime · ⛓ Blockchain · 🏭 Critical Manufacturing · 📦 Ship Manifests

9. Roadmap
Post-quantum signatures — Ed25519 attestation today; a migration path to post-quantum signatures (e.g. CRYSTALS-Dilithium) as standards mature. (Ed25519 itself is not post-quantum.)
Model-BOM readiness for emerging AI-regulation requirements.
Extensible 8-layer model — the community can add layers and integrations.
🏢 Sector Demonstrations (14 Sandboxes + 1 Bonus Utility)
Each sandbox demonstrates Gullwing's capabilities in a specific sector:

1. 🏦 Private Banking
Problem: Binary tampering in banking systems
Gullwing Solution: 25ms binary analysis, automated quarantine
Demo: ./sandboxes/MockBank/bank-demo.sh

2. 🇪🇺 CRA Importers
Problem: CRA Article 14 importer obligations
Gullwing Solution: SBOM generation, supply chain verification
Demo: ./sandboxes/CRA-Importers/cra-compliance-check.sh

3. 🏛 Clearing Houses
Problem: KYC/AML compliance, party data management
Gullwing Solution: Multi-language stack, regulatory classification
Demo: ./sandboxes/PartyVault/party-vault-demo.sh

4. 🎟️ Ticket Sales
Problem: Counterfeit tickets, scalping bots
Gullwing Solution: Hash verification, supply chain tracking
Demo: ./sandboxes/TicketMaster/verify-tickets.sh

5. 🎰 Casinos & Gaming
Problem: RNG tampering, slot machine integrity
Gullwing Solution: Binary integrity verification, tamper detection
Demo: ./sandboxes/CasinoGuard/verify-casino.sh

6. 📈 Stock Market
Problem: Trading algorithm manipulation, HFT integrity
Gullwing Solution: Anomaly detection, real-time monitoring
Demo: ./sandboxes/StockMarket/verify-market.sh

7. 🏥 Healthcare (NHS)
Problem: Ransomware attacks on medical systems
Gullwing Solution: Instant quarantine (0.025s), patient data protection
Demo: ./sandboxes/Healthcare/verify-healthcare.sh

8. ⚡ Energy Grid
Problem: SCADA system attacks, grid instability
Gullwing Solution: Critical infrastructure protection, automated response
Demo: ./sandboxes/Energy/verify-energy.sh

9. 📡 Telecommunications
Problem: Network equipment tampering
Gullwing Solution: Firmware verification, continuous monitoring
Demo: ./sandboxes/Telecom/verify-telecom.sh

10. ✈️ Aviation
Problem: Flight system tampering, navigation spoofing
Gullwing Solution: Firmware integrity, supply chain verification
Demo: ./sandboxes/Aviation/verify-aviation.sh

11. 🚢 Maritime
Problem: Navigation system spoofing, cargo fraud
Gullwing Solution: Manifest validation, integrity checking
Demo: ./sandboxes/Maritime/verify-maritime.sh

12. ⛓️ Blockchain
Problem: Private key theft, exchange compromise
Gullwing Solution: Quarantine, fund protection
Demo: ./sandboxes/Blockchain/verify-blockchain.sh

13. 🛃 Export Control & Dual-Use Goods
Problem: Export control violations, sanctions-screening gaps
Gullwing Solution: Transaction flagging, compliance enforcement
Demo: ./sandboxes/Weapons/verify-weapons.sh

14. 📦 Ship Manifests
Problem: Cargo fraud, undeclared goods
Gullwing Solution: Manifest verification, customs hold
Demo: ./sandboxes/Shipping/verify-shipping.sh

Bonus Utility: 💾 Disk Guardian
Problem: Disk space exhaustion causing system crashes
Gullwing Solution: Real-time monitoring, automated cleanup, forensic logging
Demo: ./sandboxes/DiskGuardian/monitor-disk.sh

Requirements
Gullwing core runs on Linux, WSL2 and macOS.

Dependency	Used for
Bash + coreutils	Pipelines and demo scripts
LuaJIT	Orchestration layer
Zig toolchain	Compute kernels
Perl	Ingestion and record processing
Python 3	Tooling, demos, reporting
Docker (optional, ~5 GB)	Full Witchcraft Solver mode (KLEE, SeaHorn, SMACK, IKOS)
On storage-constrained systems, point Docker's data root at a larger volume before building the solver image.

Quick Start
Bash

# Clone the suite
git clone https://github.com/Chikimonki/Gullwing-Protocol.git
cd Gullwing-Protocol

# Initialize submodules
git submodule update --init --recursive

# Run the security pipeline on a target binary
./scripts/security-pipeline.sh /usr/bin/ls

# Run all demos
./scripts/run-ultimate-suite.sh
Running the Tests
Bash

# Full suite: demos plus deterministic test gates
./scripts/run-ultimate-suite.sh
Party Vault ships its own verification suite (latest run: 18 PASS · 0 FAIL · 1 KNOWN-FAIL, the known-fail documented in-repo).

Witchcraft Solver — Docker Modes (Optional)
The Witchcraft Solver (wsolver) has two modes:

Basic Mode (No Docker Required)
Bash

cd wsolver
make        # Builds native tools (~1MB)
./wsolve <binary>
Works for basic binary analysis.

Full Mode (Docker Required — ~5GB)
Bash

cd wsolver
make docker # Builds solver image (KLEE, SeaHorn, SMACK, IKOS)
Requires ~5GB disk space. See WSL-DOCKER-SETUP.md for constrained-system setup notes.

Note: The core Gullwing Protocol (detection, quarantine, AI analysis) works without Docker.

🏭 Super Factories (AI-Compatible Build System)
Gullwing Protocol uses a Super Factory architecture for rapid deployment across sectors:

The Core Four (Controls Everything)
YAML

context:   # What the agent knows
  max_tokens: 8192
  focus: "Binary security analysis"

model:     # Which LLM to use
  primary: "qwen3.5:9b"
  secondary: "phi4-mini"

prompt:    # Instructions
  system: "You are a senior security engineer..."

tools:     # What the agent can do
  - file_read
  - file_write
  - shell_execute
  - gullwing_scan
The 5-Phase Workflow
Scout — Understand the codebase
Plan — Create structured implementation plan
Build — Implement following the plan
Test — Run deterministic gates
Review — Validate quality and compliance
Factory Benefits
Rapid deployment — New sector sandbox in minutes
Consistent methodology — Same 8-layer analysis everywhere
AI-ready — Compatible with any local LLM (Ollama and similar)
Reproducible — Deterministic gates ensure quality
Example: Creating a New Sector Sandbox
Bash

# 1. Copy the factory template
cp -r sandboxes/MockBank sandboxes/NewSector

# 2. Edit factory.yaml
# 3. Add mock binaries
# 4. Run the demo
./sandboxes/NewSector/demo.sh
🐦 Specialized Variants (Modular Deployment)
Variant	Purpose	Deploy When
Sandpiper	Standalone 8-layer convergence	Minimal footprint needed
Gannet	High-velocity ingestion	High-volume binary processing
Egret	Continuous monitoring	24/7 surveillance required
Buzzard	Binary quarantine	Isolated threat response
Curlew	Supplier verification	Supply chain audits
Crane	Strategic forecasting	Predictive security planning
Flamingo	Legal text filter	Regulatory document processing
Owl	Regulatory intelligence	Compliance monitoring
Swan	COBOL modernisation	Legacy banking systems
Tern	COBOL to Rust translator	Legacy migration
Skylark	DORA compliance	Financial regulation
Auto	Vehicle ECU protection	Automotive security
Arcade	Training games	Security education
All variants share the same 8-layer core. Deploy only what you need.

Trust & Verification Checklist
Anyone can independently verify Gullwing:

Clone the repo and read every line (MIT).
Check the published SHA-256 hashes of release artifacts.
Reproduce the build and confirm the binary matches its hash.
Run the tool on a known target and inspect the output.
Review the ML model integrity checks.
Exercise the quarantine feature on a test binary.
Audit the generated compliance reports.
We don't ask for trust — we provide the means to verify.

Summary
SOVEREIGNTY	Air-gapped — your data never leaves your network
OPEN	MIT-licensed — independently rebuildable and verifiable
SPEED	~25ms analysis · ~2s supply-chain detection
COMPLIANCE	Evidence generation for CRA · DORA · CISA · NIS2 · UN R155/R156 · KYC/AML
COST	$0 licensing · $0 cloud · $0 API
TRAINING	6 games that teach binary security
COVERAGE	14 sector demonstrations + 1 bonus utility
ROADMAP	Post-quantum-ready · AI-regulation-ready · extensible
Security
Found a vulnerability in Gullwing itself? Please report it responsibly — see 
SECURITY.md
. Do not open a public issue for security findings.

Contributing
PRs are welcome. Read 
CONTRIBUTING.md
 for the workflow, test gates and coding conventions.

License
MIT — 100% open source.

A complete security department in a box — detect, audit, comply, explain. On your hardware.
