# Witchcraft Solver Integration — Honest Assessment

## Important Disclaimer

**Witchcraft Solver (wsolver) is Jonathan Brossard's (@endrazine) research project.**

We include it as a git submodule for convenience, but:

- ❌ We have **not independently verified** its claims
- ❌ We have **not tested** it in production environments
- ❌ We **do not vouch for** its accuracy or completeness
- ✅ We **do refer readers** to the authoritative source

**Authoritative information:** [wsolver README](https://github.com/endrazine/wsolver)

## What We Know (From @endrazine's README)

wsolver claims to:
- Find 0-days in stripped binaries
- Use symbolic execution (KLEE, SeaHorn, SMACK, IKOS)
- Provide concrete exploitation witnesses
- Work on ELF binaries (PE and Mach-O planned)

## What We Have NOT Verified

- Whether these claims are accurate
- Whether it works on real-world production binaries
- Whether the Docker image builds correctly on all systems
- Whether the LLM triage produces reliable results
- Whether the confidence levels are meaningful

## Our Integration Status

| Aspect | Status |
|--------|--------|
| Git submodule | ✅ Added |
| Native tools compiled (`make`) | ✅ Works |
| Docker image | ⚠️ Not built (disk constraints) |
| Full pipeline tested | ❌ Not yet |
| Production use | ❌ Not recommended |

## How We Use It

We include wsolver as an **optional component** for users who want to explore symbolic execution. Our integration:

1. Does **not** claim wsolver's capabilities as our own
2. Does **not** vouch for its accuracy
3. Does **not** include it in our core functionality
4. Does **refer** users to @endrazine for authoritative information

## For Users

If you want to use wsolver:
1. Read the [wsolver README](https://github.com/endrazine/wsolver) thoroughly
2. Understand its limitations (it's research-grade)
3. Test it yourself on known samples
4. Report issues to @endrazine, not to us

## Our Core (Without wsolver)

Gullwing Protocol works completely without wsolver:
- ✅ 8-layer binary analysis (25ms)
- ✅ Automated quarantine (0.025s)
- ✅ AI analysis (Kestrel)
- ✅ Compliance (CRA, CISA, DORA)
- ✅ Training (6 arcade games)
- ✅ 15 sector demos

**wsolver is optional.** Gullwing is complete without it.
