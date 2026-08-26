"""Gullwing verification skill for Prime Agent — verify binaries before deployment."""

import subprocess
import json
import os

GULLWING_API = "http://127.0.0.1:9393"

def verify_binary(path: str) -> dict:
    """Run Gullwing 8-layer analysis on a binary and return the verdict."""
    try:
        result = subprocess.run(
            ["curl", "-s", "-X", "POST", f"{GULLWING_API}/reflect",
             "-d", f"path={path}"],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout)
        evidence = data.get("evidence", data)
        convergence = evidence.get("convergence", {})
        ml = evidence.get("ml", {})
        
        return {
            "path": path,
            "class": ml.get("class", "unknown"),
            "confidence": ml.get("confidence", 0),
            "risk": convergence.get("risk_tier", "UNKNOWN"),
            "novelty": convergence.get("novelty_tier", "UNKNOWN"),
            "signals": convergence.get("signals", []),
            "verdict": "CLEAR" if convergence.get("risk_tier") in ["CLEAR", "NOTABLE"] else "BLOCKED"
        }
    except Exception as e:
        return {"path": path, "error": str(e), "verdict": "ERROR"}

def verify_and_deploy(path: str, deploy_command: str = None) -> bool:
    """Verify a binary. If CLEAR, optionally deploy. If HOSTILE, quarantine."""
    result = verify_binary(path)
    
    if result["verdict"] == "CLEAR":
        print(f"✅ {path}: {result['class']} ({result['confidence']:.1f}%) — {result['risk']}")
        if deploy_command:
            os.system(deploy_command)
        return True
    elif result["verdict"] == "ERROR":
        print(f"⚠️  {path}: Verification failed — {result.get('error', 'unknown')}")
        return False
    else:
        print(f"❌ {path}: BLOCKED — {result['risk']} risk")
        # Quarantine
        quarantine_path = f"/mnt/d/moabi/reports/quarantine/{os.path.basename(path)}.{int(__import__('time').time())}"
        os.rename(path, quarantine_path)
        print(f"   Quarantined to: {quarantine_path}")
        return False
