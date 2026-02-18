#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import time

if len(sys.argv) < 2:
    print("usage: check_command_budgets.py <runtime_slo_budgets.json>", file=sys.stderr)
    sys.exit(2)

with open(sys.argv[1], "r", encoding="utf-8") as f:
    budgets = json.load(f)

for cmd, b in budgets.items():
    p95 = float(b.get("p95_ms", 1e9))
    samples = []
    for _ in range(3):
        start = time.time()
        argv = cmd.split()
        if argv and argv[0] == "proof" and pathlib.Path("./proof").exists():
            argv[0] = "./proof"
        subprocess.run(argv + ["--help"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        samples.append((time.time() - start) * 1000.0)
    samples.sort()
    ms = samples[min(len(samples)-1, 1)]
    if ms > p95:
        print(f"budget exceeded for {cmd}: {ms:.1f}ms > {p95:.1f}ms", file=sys.stderr)
        sys.exit(1)

print("command budget check passed")
