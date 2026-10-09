# SecretShield pre-commit scan script
# Scans staged files and fails if real credential patterns (HIGH_CONFIDENCE+) found outside tests/

import json
import sys
import subprocess

# Get staged files
result = subprocess.run(
    ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
    capture_output=True,
    text=True,
)
staged_files = result.stdout.strip().split("\n")
if not staged_files or staged_files == [""]:
    print("No staged files to scan")
    sys.exit(0)

# Run secret-shield on staged files
cmd = ["secret-shield", "scan"] + staged_files + ["--format", "json"]
result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode not in (0, 1):
    print(f"secret-shield failed: {result.stderr}", file=sys.stderr)
    sys.exit(1)

try:
    data = json.loads(result.stdout)
except json.JSONDecodeError:
    print(
        f"Failed to parse secret-shield output: {result.stdout[:200]}", file=sys.stderr
    )
    sys.exit(1)

findings = data.get("findings", [])
suspicious = []
for f in findings:
    path = f["location"]["path"]
    if not path.startswith("tests/"):
        # Check for HIGH_CONFIDENCE (3) or VERIFIED (4) - vendor rule matches
        if f["confidence"] >= 3:
            suspicious.append(f)

if suspicious:
    print("FAIL: Real credential patterns found in staged files:", file=sys.stderr)
    for f in suspicious:
        print(
            f"  {f['location']['path']}:{f['location']['line']} {f['rule_id']} conf={f['confidence']}",
            file=sys.stderr,
        )
    sys.exit(1)

print("OK: No real credential patterns in staged files")
