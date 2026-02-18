#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/.tmp-proof-contract"
TMPDIR="$(mktemp -d)"
trap 'rm -f "${BIN}"; rm -rf "${TMPDIR}"' EXIT

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

cat > "${TMPDIR}/record.json" <<'JSON'
{
  "record_id":"prf-test",
  "record_version":"1.0",
  "timestamp":"2026-02-17T12:00:00Z",
  "source":"axym",
  "source_product":"axym",
  "record_type":"decision",
  "event":{"action":"allow"},
  "controls":{},
  "integrity":{"record_hash":"sha256:bad"}
}
JSON

set +e
"${BIN}" verify "${TMPDIR}/record.json" >/dev/null 2>&1
code=$?
set -e

if [[ "${code}" -ne 2 ]]; then
  echo "expected exit code 2 for verification failure, got ${code}"
  exit 1
fi

echo "verification failure contract check passed"
