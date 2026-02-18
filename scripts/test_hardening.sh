#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go test ./core/... ./cmd/proof -count=1
