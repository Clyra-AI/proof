#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/.tmp-proof-contract"
trap 'rm -f "${BIN}"' EXIT

go build -o "${BIN}" "${ROOT}/cmd/proof"

set +e
"${BIN}" verify /definitely/missing >/dev/null 2>&1
code=$?
set -e

if [[ "${code}" -ne 6 ]]; then
  echo "expected exit code 6 for invalid input, got ${code}"
  exit 1
fi

echo "exit code contract check passed"
