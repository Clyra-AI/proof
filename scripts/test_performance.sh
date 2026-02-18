#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go build -o ./proof ./cmd/proof
GOMAXPROCS=1 go test ./... -run '^$' -bench . -benchmem -count=5 | tee perf/bench_output.txt
./scripts/check_bench_regression.py perf/bench_output.txt perf/bench_baseline.json
./scripts/check_command_budgets.py perf/runtime_slo_budgets.json
