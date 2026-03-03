# Python Integration Guide

Proof is JSON-native, so Python integrations should emit artifacts as JSON and call the Proof CLI for verification at CI/runtime boundaries.

## 1. Produce a JSON Artifact

Create a record JSON file in Python that follows `schemas/v1/proof-record-v1.schema.json` and a valid record type schema.

```python
import json
from datetime import datetime, timezone

record = {
    "record_id": "prf-2026-03-03T12:00:00Z-example",
    "record_version": "1.0",
    "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "source": "python-worker",
    "source_product": "example-service",
    "record_type": "decision",
    "event": {"action": "allow"},
    "integrity": {"record_hash": "sha256:..."}
}

with open("record.json", "w", encoding="utf-8") as f:
    json.dump(record, f, indent=2)
```

## 2. Verify with the CLI

Use the CLI as the verification boundary:

```bash
proof verify --json record.json
```

For signature checks:

```bash
proof verify --json --signatures --public-key <hex-or-base64> record.json
```

## 3. Consume Schemas in Python Tooling

- Base schema: `schemas/v1/proof-record-v1.schema.json`
- Type-specific schemas: `schemas/v1/types/*.schema.json`

Recommended pattern:

1. Validate JSON in Python before writing artifacts.
2. Re-verify with `proof verify` in CI and deployment gates.

## 4. Exit-Code Behavior for Automation

Use Proof exit codes directly in Python subprocess orchestration:

- `0`: success
- `1`: internal/runtime error
- `2`: verification failure
- `3`: policy/schema violation
- `4`: approval required
- `5`: regression drift detected
- `6`: invalid input
- `7`: dependency missing
- `8`: unsafe operation blocked

Example:

```python
import subprocess

proc = subprocess.run(["proof", "verify", "--json", "record.json"], capture_output=True, text=True)
if proc.returncode != 0:
    raise RuntimeError(f"proof verify failed (exit={proc.returncode}): {proc.stderr}")
```
