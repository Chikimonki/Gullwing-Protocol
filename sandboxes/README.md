# Gullwing Protocol — 15 Sector Sandboxes

## Overview
Each sandbox demonstrates Gullwing's capabilities in a specific sector. All sandboxes use the same 8-layer convergent analysis methodology.

## Quick Start
```bash
# Run all 15 sandboxes
cd sandboxes
./run-all-sandboxes.sh

# Or run individual sandboxes
cd MockBank && ./bank-demo.sh
Sandbox Index
#	Sandbox	Sector	Key Feature Demonstrated
1	MockBank	Private Banking	Threat detection, CRA compliance
2	CRA-Importers	EU Importers	Article 14 compliance, supply chain
3	PartyVault	Clearing Houses	Multi-language stack, KYC/AML
4	TicketMaster	Ticket Sales	Counterfeit detection
5	CasinoGuard	Casinos	RNG integrity, tamper detection
6	StockMarket	Stock Market	Market manipulation detection
7	Healthcare	Healthcare (NHS)	Ransomware quarantine
8	Energy	Energy Grid	SCADA protection
9	Telecom	Telecommunications	Network equipment verification
10	Aviation	Aviation	Flight system integrity
11	Maritime	Maritime	Navigation verification
12	Blockchain	Blockchain	Private key protection
13	Weapons	Weapons Trading	Export control
14	Shipping	Ship Manifests	Cargo verification
15	DiskGuardian	Disk Space	Space monitoring, cleanup
Each Sandbox Contains:
src/ — Mock binaries and data for testing

reports/ — Generated analysis reports

gates/ — Deterministic checkpoints

*.sh — Demo script showing Gullwing in action
