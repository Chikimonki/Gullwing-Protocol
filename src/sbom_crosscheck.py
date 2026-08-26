#!/usr/bin/env python3
"""
sbom_crosscheck.py — verify dependency trees are actually *reported*, not just scanned.

Compares the component lists of two CycloneDX JSON SBOMs, e.g.:
    A = Moabi/Gullwing export
    B = syft dir:<target> -o cyclonedx-json   (reference scanner)

Output:
  - components in both
  - components only in A (extras)
  - components only in B  <-- these are your DETECTION GAPS (the libssl class)

Exit codes: 0 = identical sets, 1 = gaps found, 2 = usage/parse error.
Useful in CI: any unexplained gap blocks the CRA attestation step.

Usage:
    python3 sbom_crosscheck.py moabi_sbom.json syft_sbom.json
    python3 sbom_crosscheck.py moabi_sbom.json syft_sbom.json --json gaps.json
"""
import json, sys

def collect(doc):
    """Extract (name, version) pairs from a CycloneDX doc, tolerating
    common layout differences between generators."""
    comps = set()
    stack = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "name" in node and ("version" in node or "purl" in node or "components" in node):
                name = node.get("name", "").strip()
                ver  = node.get("version", "") or ""
                if name:
                    comps.add((name, ver.strip()))
            for v in node.values():
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
    # Drop the root component itself if it looks like the scanned target
    root = (doc.get("metadata") or {}).get("component", {}).get("name")
    if root:
        comps = {c for c in comps if c[0] != root}
    return comps

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(2)
    path_a, path_b = sys.argv[1], sys.argv[2]
    json_out = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--json" else None

    try:
        with open(path_a) as f: a = collect(json.load(f))
        with open(path_b) as f: b = collect(json.load(f))
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr); sys.exit(2)

    both, only_a, only_b = a & b, a - b, b - a
    fmt = lambda s: f"{s[0]}{('@'+s[1]) if s[1] else ''}"

    print(f"Components in BOTH ({len(both)}):")
    for c in sorted(both): print(f"   {fmt(c)}")
    print(f"\nOnly in A/Moabi ({len(only_a)}):")
    for c in sorted(only_a): print(f"   {fmt(c)}")
    print(f"\nOnly in B/syft -> DETECTION GAPS ({len(only_b)}):")
    for c in sorted(only_b): print(f"   {fmt(c)}")

    if json_out:
        with open(json_out, "w") as f:
            json.dump({"both": sorted(map(fmt, both)),
                       "only_a": sorted(map(fmt, only_a)),
                       "gaps": sorted(map(fmt, only_b))}, f, indent=2)
        print(f"\n[wrote {json_out}]")

    if only_b:
        print("\nRESULT: GAPS FOUND — scanner A missed components the reference"
              "\nscanner sees. Investigate before attesting dependency coverage.")
        sys.exit(1)
    print("\nRESULT: no gaps — dependency tree reporting verified.")

if __name__ == "__main__":
    main()
