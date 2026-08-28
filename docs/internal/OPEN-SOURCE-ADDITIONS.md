Open-Source Additions — Vetted Candidates for Gullwing
Every entry: permissively licensed, free, and mapped to a specific Gullwing
layer. Rule of thumb maintained throughout: GPL/LGPL tools only ever as
separate processes, never linked — Gullwing's MIT story stays clean.

Priority 1 — direct CRA/SBOM value
Tool	License	What it adds
grype (Anchore)	Apache-2.0	CVE matcher that pairs with syft: SBOM → vulnerability list. Completes the "SBOM + CVE cross-reference" row of the CISA 8/8 table with real tooling
osv-scanner (Google/OSV.dev)	Apache-2.0	Second, independent vulnerability source (OSV database). Two sources = stronger evidence; disagreement between them is itself an audit finding
cdxgen	Apache-2.0	Multi-language CycloneDX generator. Useful for the source-side SBOM that complements Gullwing's binary-side SBOM — the cross-checker then spans BOTH sides
in-toto	Apache-2.0	Supply-chain attestation framework (layouts + signed link metadata). Formalises what the Ed25519 attestation already does ad hoc — auditors recognise the name
Priority 2 — binary-analysis reinforcement
Tool	License	What it adds
LIEF	Apache-2.0	ELF/PE parsing library. Could harden layers 2/3 (structure/semantics) with maintained parsing instead of hand-rolled readelf scraping
binwalk	MIT	Firmware extraction — strengthens the UEFI/embedded carving layer and the Auto variant's ECU image analysis
Ghidra	Apache-2.0	Deep-dive reference tool for validating Gullwing verdicts on suspicious samples (separate process; never linked)
Priority 3 — provenance & hygiene
Tool	License	What it adds
OpenSSF Scorecard	Apache-2.0	Scores the security practice of Gullwing's OWN dependencies — run it on the repo and include the score in the CRA Proof Bundle. Self-audit as marketing
sigstore/cosign	Apache-2.0	Keyless artifact signing for GitHub Releases. Complements the Ed25519 layer with a widely-trusted chain
REUSE tool (FSFE)	GPL-3.0 (CLI only)	Machine-checkable licence headers across the repo — the licence-discipline brand, made provable
Priority 4 — fleet
Tool	License	What it adds
Headscale	BSD-3	Open-source control server for Tailscale clients. Tailscale itself is source-available but NOT open source — worth knowing, and worth saying accurately in the white paper. Headscale keeps the fleet story 100% open if clients ask
Deliberately NOT adopted (recorded for auditors)
TabFM weights — non-commercial licence (see Kestrel design doc §8.2)
radare2 as a library — LGPL; acceptable only as a separate-process tool
Wazuh — GPLv2; excellent but wrong licence posture for embedding
Integration note for the Kestrel
grype + osv-scanner slot into the CI gate as an extra step AFTER the
cross-check: scan the syft SBOM, attach findings to the evidence artifact.
Two independent vulnerability sources + the binary-level delta = the most
defensible CRA evidence stack available at zero licence cost.
