#!/usr/bin/env python3
import json
import re
import sys

if len(sys.argv) < 3:
    print("usage: check_bench_regression.py <bench_output> <baseline.json>", file=sys.stderr)
    sys.exit(2)

bench_output, baseline_path = sys.argv[1], sys.argv[2]
with open(baseline_path, "r", encoding="utf-8") as f:
    baseline = json.load(f)

current = {}
pattern = re.compile(r'^(Benchmark\S+)\s+\d+\s+(\d+)\s+ns/op')
with open(bench_output, "r", encoding="utf-8") as f:
    for line in f:
        m = pattern.match(line.strip())
        if m:
            current[m.group(1)] = int(m.group(2))

for name, cfg in baseline.items():
    if name not in current:
        continue
    allowed = float(cfg.get("baseline_ns_op", 0)) * float(cfg.get("max_regression_factor", 4.0))
    if current[name] > allowed:
        print(f"benchmark regression: {name} {current[name]} > {allowed}", file=sys.stderr)
        sys.exit(1)

print("benchmark regression check passed")
