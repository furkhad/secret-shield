# SecretShield pre-commit validation script
# Checks that pyproject.toml has all required fields

import tomllib
import sys

with open("pyproject.toml", "rb") as f:
    data = tomllib.load(f)

required = [
    "project.name",
    "project.version",
    "project.description",
    "project.requires-python",
    "project.license",
    "build-system",
]

for key in required:
    parts = key.split(".")
    d = data
    for p in parts:
        if p not in d:
            print(f"Missing: {key}", file=sys.stderr)
            sys.exit(1)
        d = d[p]

print("pyproject.toml OK")