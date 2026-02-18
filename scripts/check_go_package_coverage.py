#!/usr/bin/env python3
import collections
import pathlib
import subprocess
import sys

if len(sys.argv) < 3:
    print("usage: check_go_package_coverage.py <coverprofile> <min_percent> [allowlist_csv]", file=sys.stderr)
    sys.exit(2)

coverprofile = sys.argv[1]
min_percent = float(sys.argv[2])
allowlist = set()
if len(sys.argv) > 3:
    for item in sys.argv[3].split(","):
        item = item.strip()
        if item:
            allowlist.add(item)

cmd = ["go", "tool", "cover", "-func", coverprofile]
proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]

by_pkg = collections.defaultdict(list)
for line in lines:
    if line.startswith("total:"):
        continue
    # example: core/canon/canon.go:24:\tCanonicalize\t80.0%
    path_and_rest = line.split("\t")
    if len(path_and_rest) < 3:
        continue
    file_part = path_and_rest[0].split(":", 1)[0]
    pct_part = path_and_rest[-1]
    if not pct_part.endswith("%"):
        continue
    pct = float(pct_part[:-1])
    pkg = str(pathlib.Path(file_part).parent)
    by_pkg[pkg].append(pct)

failures = []
for pkg, pcts in sorted(by_pkg.items()):
    if pkg in allowlist:
        continue
    avg = sum(pcts) / len(pcts)
    print(f"{pkg}: {avg:.2f}%")
    if avg < min_percent:
        failures.append((pkg, avg))

if failures:
    print("\npackage coverage failures:", file=sys.stderr)
    for pkg, avg in failures:
        print(f"- {pkg}: {avg:.2f}% < {min_percent:.2f}%", file=sys.stderr)
    sys.exit(1)
