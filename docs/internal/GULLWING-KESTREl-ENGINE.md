The Kestrel — Gullwing's Embedded Inference Engine
The Cormorant dives. The Gullwing watches. The Kestrel carries.

Design specification v1.0 — adds a fully embedded, air-gapped LLM inference
engine to the Gullwing Protocol, replacing the external Ollama dependency
while keeping it as an automatic fallback.

1. Why
Gullwing's brand promise is sovereignty: zero cloud dependencies, zero API
keys, fully air-gapped. Today the gullwing ask feature leans on an
external Ollama process — one more moving part, one more thing an auditor
must trust, one more daemon on the client's machine.

The Kestrel removes it. Inspired by colibrì (Vincenzo Fornaro, Apache-2.0) —
the pure-C engine that runs a 744B MoE model on 25 GB of consumer RAM by
streaming experts from disk — the Kestrel brings that hierarchical-storage
philosophy inside Gullwing:

Zero external processes — inference runs inside Gullwing's own address
space (Tier 1) or via a loopback-only local engine (Tier 0). No network,
ever. 127.0.0.1 is the ceiling.
One fewer trust surface for CRA/NIS evidence files: the Ask-LLM layer
becomes part of the attested binary set.
MoE-class models on humble hardware — the streaming-expert technique
is what lets frontier-scale models run on the machines our users actually
own.
2. Architecture
text

                       gullwing ask <binary>
                                │
                    src/moabi-engine.lua
                    (engine registry + evidence-first prompt)
                                │
        ┌───────────────────────┼────────────────────────┐
        ▼                       ▼                        ▼
 [kestrel-ffi]           [kestrel-coli]            [ollama]
  Tier 1: in-process      Tier 0: loopback           fallback
  libkestrel.so via       127.0.0.1 coli serve       127.0.0.1:11434
  LuaJIT FFI              (OpenAI-compatible)        (unchanged)
        │                       │
   Zig-compiled bridge     colibrì's own coli
   over colibrì glm.c      binary, unmodified
Selection order is automatic: kestrel-ffi → kestrel-coli → ollama.
Override with GULLWING_ENGINE=ffi|coli|ollama|auto.

Tier 0 — kestrel-coli (works today)
colibrì ships coli serve: one model process, OpenAI-compatible HTTP API,
bound locally. The Kestrel orchestrator health-checks it, POSTs Gullwing's
evidence-first prompt, and parses the reply. No signature guesswork, no
source modification — guaranteed-correct inference using Fornaro's kernels
exactly as shipped. Still fully local: the listener is loopback-only.

Tier 1 — kestrel-ffi (the polish)
glm.c is currently a self-contained program (own main() loop); it does
not yet expose an embeddable C API. Tier 1 adds one:

engine/kestrel_bridge.h — a stable C ABI (init / generate / free)
owned by Gullwing, immune to colibrì's internal churn.
engine/kestrel_bridge.c — the seam. Contains clearly marked ADAPT
blocks where colibrì's forward pass is wired in. Compiles standalone in
stub mode so the interface is testable before the wiring lands.
Built with Zig (zig cc), producing libkestrel.so next to
libmoabi.so — two birds, one toolchain. Zig's cross-compilation also
carries the Kestrel to Gullwing's ARM/RISC-V/MIPS targets.
The embeddable-API patch is a candidate upstream contribution to
colibrì — standing on the rock with the author, not against it.
3. Model ladder (hardware honesty)
Tier	Model	Params	Fits	Notes
Today	Phi-4-mini / Qwen2.5-7B via Ollama	3.8B / 7B	16 GB	dense models; mmap is enough
Ask-LLM upgrade	Bonsai 27B (PrismML, Apache-2.0)	27B @ 1-bit (3.9 GB) or ternary (~7.2 GB GGUF)	16 GB	262K context, multimodal, tool-calling; run via PrismML's llama.cpp fork (CPU-only on reference build); vendor benchmarks only so far — re-run the /usr/bin/ls grounding fixture before adopting
Stretch	Qwen3-30B-A3B via Kestrel	30B (3B active)	16 GB + NVMe	MoE streaming is UNWORKABLE on 5400 RPM HDD — deferred to the future build
Flagship	GLM-5.2 via Kestrel	744B	≥25 GB + NVMe	colibrì's reference configuration
Reference build (DESKTOP-SH1TRJ9 — the machine Gullwing is built on)
i5-8265U (4C/8T, AVX2, dual-channel DDR4) — CPU-only inference by design
16 GB RAM (~10–11 GB usable under Windows)
GPU Radeon 520 + Intel UHD 620: deliberately UNUSED (no ROCm class support;
shared-memory iGPU adds complexity for near-zero gain). CPU path is the
portable, air-gap-clean choice — and it's the one that ships everywhere.
C: = 128 GB NVMe (near full), D: = 1 TB 5400 RPM HDD → models STORE on D:,
resident entirely in RAM at runtime; expert-STREAMING (MoE) impossible on
this drive. This is physics, documented, not aspiration.
Dense models gain nothing from expert streaming — they stay on the Ollama
path. The Kestrel earns its keep on MoE models, where only ~3B–17B active
parameters must be resident. Streaming requires NVMe; on spinning rust the
prefetch cannot outrun the disk. Model directory defaults to
/mnt/d/models (Windows D: under WSL2), configurable via GULLWING_MODELS.

4. Licensing and attribution
colibrì engine: Apache-2.0 (JustVugg/colibri). The build script
vendors LICENSE and records the exact commit SHA in engine/MANIFEST.txt.
GLM-5.2 weights: MIT (Z.ai).
Gullwing additions (bridge, orchestrator, this document): MIT, per the
project license.
5. Configuration
Variable	Default	Purpose
GULLWING_ENGINE	auto	ffi / coli / ollama / auto
GULLWING_MODELS	/mnt/d/models	model directory (D: drive)
KOLIBRI_URL	http://127.0.0.1:8089	Tier 0 loopback endpoint
OLLAMA_URL	http://127.0.0.1:11434	fallback endpoint
GULLWING_LLM	phi4-mini	model name for Ollama path
6. Acceptance criteria
gullwing ask /usr/bin/ls returns a grounded verdict with no engine
running but Ollama up (fallback path).
With coli serve up, the same command routes to Kestrel and the response
carries engine=kestrel-coli.
Air-gap test: pull the network (or block egress), all three tiers still
serve — loopback only, by construction.
Regression: the /usr/bin/ls evidence-prompt output stays grounded
(class system_utility, integrity caveat present) — this is now a
pinned fixture, same as the binary detection matrix.
libkestrel.so stub builds clean with both gcc and zig cc;
readelf -d ground truth committed with the release.
7. Out of scope (v1)
Fine-tuning, multi-model serving, GPU tiers (colibrì's optional CUDA/Metal
backends may be wired later through the same bridge), and the 744B flagship
on sub-25 GB machines — physics, not ambition.

8. Revision 2 — Engine pluralism (August 2026)
Two releases changed the design's centre of gravity:

8.1 WASTE (Marco Bambini / SQLite Cloud, 30 July 2026)
An open-source (Apache-2.0, github.com/sqliteai/waste) C engine that runs
the full 2.78T-parameter Kimi K3 — a 982 GB container — on a 64 GB MacBook
Pro by streaming ~17 GB of expert data per token from disk, bypassing the OS
page cache and managing expert caching directly. Critically, WASTE ships:

an embeddable C API — the exact interface Tier 1 wants, available today
an OpenAI-compatible HTTP server and CLI
ARM + x86 CPU implementations; macOS/Linux/Windows; text AND image input
This removes the blocker noted in §2: Tier 1 no longer waits for colibrì to
grow an embeddable API. kestrel_bridge.h therefore becomes a backend
contract, not a colibrì wrapper:

Backend	Path	Status
waste	embeddable C API via Zig-compiled adapter	Tier 1-capable NOW
colibri	Tier 0 loopback today; Tier 1 when upstream API lands	works today
ollama	loopback fallback for dense models	works today
The registry selects by model class: MoE → waste/colibri (streaming),
dense → ollama (mmap). The bridge ABI is the moat; the engines are
interchangeable. Gullwing rides whichever engine wins.

Hardware honesty: K3's container is 982 GB — far beyond a 16 GB machine at
any speed. The model ladder (§3) stands; WASTE's stated goal of a general
runtime for small systems aligns with our stretch target (Qwen3-30B-A3B).

8.2 TabFM (Google Research, 30 June 2026) — evaluated, NOT adopted
TabFM is a zero-shot tabular foundation model (classification/regression
via in-context learning), not an inference engine. Evaluated for Gullwing's
ML layer and declined, for three documented reasons:

Licence trap: code is Apache-2.0, but the pretrained weights carry a
NON-COMMERCIAL licence. Shipping them inside a commercial audit product
would be a compliance breach — precisely the failure mode Gullwing's
provenance discipline (MANIFEST.txt, licence attestation) exists to catch.
Stack mismatch: JAX/PyTorch + Python runtime contradicts the
zero-dependency, air-gapped design.
No capability gain: Gullwing's weighted k-NN layer is lean,
interpretable, and trains locally; XGBoost/LightGBM remain the fully-open
alternatives if tabular ML is ever needed.
The rejection is recorded here deliberately: auditors ask why a tool was NOT
adopted as often as why one was.

8.3 What the pattern means
July 2026 produced two zero-dependency C engines from veteran solo builders
that moved frontier models onto consumer hardware — colibrì (744B / 25 GB)
and WASTE (2.78T / 64 GB) — within three weeks of each other. The frontier
of inference has moved from GPU procurement to storage-hierarchy systems
engineering. That is C/Zig/LuaJIT territory — the stack Gullwing was already
built on. Open source won this round against hosted free tiers, and the
Kestrel's engine-plural design is how Gullwing stays attached to the winning
side without being owned by any single engine.
