# SecretShield pre-commit full repo scan script
# Scans entire repo and fails if real credential patterns (HIGH_CONFIDENCE+) found outside tests/

import json
import sys
import subprocess

result = subprocess.run(
    ["secret-shield", "scan", ".", "--format", "json"],
    capture_output=True,
    text=True,
)

if result.returncode not in (0, 1):
    print(f"secret-shield failed: {result.stderr}", file=sys.stderr)
    sys.exit(1)

data = json.loads(result.stdout)
findings = data.get("findings", [])
suspicious = [
    f
    for f in findings
    if not f["location"]["path"].startswith("tests/") and f["confidence"] >= 3
]

if suspicious:
    print("FAIL: Real credential patterns found:", file=sys.stderr)
    for f in suspicious:
        print(
            f'  {f["location"]["path"]}:{f["location"]["line"]} {f["rule_id"]} conf={f["confidence"]}',
            file=sys.stderr,
        )
    sys.exit(1)

print("OK: No real credential patterns in repo")
