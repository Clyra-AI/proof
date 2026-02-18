#!/usr/bin/env python3
import sys

if len(sys.argv) < 3:
    print("usage: check_go_coverage.py <coverprofile> <min_percent>")
    sys.exit(2)

cover = sys.argv[1]
min_pct = float(sys.argv[2])

covered = 0
count = 0
with open(cover, "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith("mode:"):
            continue
        parts = line.strip().split()
        if len(parts) != 3:
            continue
        stmts = int(parts[1])
        hit = int(parts[2])
        count += stmts
        if hit > 0:
            covered += stmts

pct = (covered / count * 100.0) if count else 100.0
print(f"coverage={pct:.2f}%")
if pct < min_pct:
    sys.exit(1)
