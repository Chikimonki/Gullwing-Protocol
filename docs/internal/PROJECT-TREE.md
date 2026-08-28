Gullwing Protocol — Project Tree & Roadmap
Target layout for /mnt/d/moabi (root) with /mnt/d/moabi/src as the main
working directory. Everything in this package is placed relative to that root.

text

/mnt/d/moabi/
│
├── README.md                          existing — merge in docs/README-ADDENDUM.md
├── README_Longcat.md                  existing
├── LICENSE                            ★ ADD (MIT — the legal blocker, fix #1)
├── .gitignore                         ★ ADD (build artifacts, vendored engines)
├── PROJECT-TREE.md                    ★ this file
│
├── .github/
│   └── workflows/
│       └── gullwing-gate.yml          ★ CI gate — MUST live exactly here for
│                                         GitHub Actions to see it
│
├── bin/                               existing (gullwing entry scripts)
│
├── docs/
│   ├── FRONTEND-GUIDE.md              existing
│   ├── GULLWING-WHITEPAPER-v4.5.md    ★ COMMIT — README links it but it's
│   │                                     missing from the repo (dead link!)
│   ├── GULLWING-KESTREL-ENGINE.md     ★ embedded engine design (Rev 2)
│   ├── GULLWING-AUTO-V5.1-UPDATE.md   ★ vehicle-variant update spec (R155/R156)
│   ├── README-ADDENDUM.md             ★ paste-into-README section + test plan
│   └── OPEN-SOURCE-ADDITIONS.md       ★ candidate components, vetted
│
├── src/                               ← your main working directory
│   ├── moabi-ml.lua                   existing
│   ├── (…your existing modules…)      existing
│   ├── moabi-engine.lua               ★ Kestrel orchestrator — wire into
│   │                                     the `gullwing ask` call site
│   └── extension/                     existing frontend (unified.html etc.)
│
├── engine/                            ★ new — the Kestrel engine room
│   ├── build-kestrel.sh               vendors colibrì + WASTE, builds, manifests
│   ├── kestrel_bridge.h               stable C ABI (Gullwing-owned)
│   ├── kestrel_bridge.c               Tier 1 seam (ADAPT blocks marked)
│   ├── libkestrel.so                  BUILD ARTIFACT — gitignored
│   ├── MANIFEST.txt                   BUILD ARTIFACT — regenerated each build
│   └── vendor/                        BUILD ARTIFACT — gitignored
│       ├── colibri/                   (Apache-2.0, vendored by build script)
│       └── waste/                     (Apache-2.0, vendored by build script)
│
├── tests/                             ★ new — the verification suite
│   ├── moabi_test_harness.sh          fixtures + self-checks (v5.1 core)
│   ├── moabi_test_scenarios.sh        4-scenario detection matrix
│   └── sbom_crosscheck.py             SBOM gap gate (exit 1 on gaps)
│
├── ci/
│   └── gullwing-gate.gitlab-ci.yml    GitLab variant — rename to
│                                       .gitlab-ci.yml at repo root IF you
│                                       ever mirror to Codeberg/GitLab
│
└── business/                          ★ outreach & launch material
    ├── Gullwing_APH10_One_Pager.docx  Anthony Harrison follow-up attachment
    ├── email_to_anthony.md            the drafted follow-up email
    ├── olle_intro_sv.md               Swedish intro for Olle's visit
    └── git-upload-cheatsheet.md       gh CLI recipes + repo housekeeping
Installation (WSL2)
Bash

# from wherever you place this package (e.g. ~/gullwing-project):
cd ~/gullwing-project
cp -rn . /mnt/d/moabi/          # -n = never overwrite your existing files
chmod +x /mnt/d/moabi/tests/*.sh /mnt/d/moabi/engine/*.sh
cd /mnt/d/moabi && git add -A && git commit -m "Add Kestrel engine, verification suite, CI gate"
cp -rn is deliberately non-destructive: it adds new files and never
touches anything you already have. Review with git status before pushing.

One mandatory wiring change
gullwing ask currently calls Ollama directly. Point it at the registry:

Lua

local engine = require("moabi-engine")        -- src/moabi-engine.lua
local res, err = engine.ask(layer_evidence_text)
if res then print(res.engine, res.text) else print("ERR", err) end
Selection is automatic: kestrel-ffi → kestrel-coli → ollama. Override with
GULLWING_ENGINE=ffi|coli|ollama.

Roadmap
Phase 0 — Housekeeping (day 1)
Commit LICENSE + the missing white paper; consolidate to one canonical repo;
GitHub About/description/topics; video metadata fix. Send Anthony's email.

Phase 1 — v5.1 release
libssl regex fix in the parser; run tests/ suite locally; push; the CI gate
badge lights up on its own (
gullwing-gate.yml
).

Phase 2 — Kestrel Tier 0

build-kestrel.sh
 → coli serve → GULLWING_ENGINE=coli gullwing ask.
Verify the 5-point test plan in docs/README-ADDENDUM.md.

Phase 3 — Kestrel Tier 1
Wire the WASTE embeddable C API through kestrel_bridge.c (ADAPT blocks);
upstream an embeddable-API patch to colibrì. Cut a GitHub Release with
signed artifacts — dogfood the Ed25519 attestation.

Phase 4 — Relationships & revenue
APH10 pilot → Innovate UK (partner: APH10) → CISA thread → LinkedIn launch.
Gullwing-Auto updated per docs/GULLWING-AUTO-V5.1-UPDATE.md in parallel.

The Cormorant dives. The Gullwing watches. The Kestrel carries.
