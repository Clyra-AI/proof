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

cat > "${TMPDIR}/generate_cosign_record.go" <<'GO'
package main

import (
	"encoding/json"
	"os"
	"time"

	"github.com/Clyra-AI/proof"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run generate_cosign_record.go <output>")
	}

	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 30, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	if err != nil {
		panic(err)
	}
	r.Integrity.Signature = "cosign:ZmFrZXNpZw=="
	r.Integrity.SigningKeyID = "cosign:test-key"

	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], raw, 0o600); err != nil {
		panic(err)
	}
}
GO

go run "${TMPDIR}/generate_cosign_record.go" "${TMPDIR}/cosign_record.json"

mkdir -p "${TMPDIR}/empty-path"
set +e
PATH="${TMPDIR}/empty-path" "${BIN}" verify --signatures --cosign-key "${TMPDIR}/cosign.pub" "${TMPDIR}/cosign_record.json" >/dev/null 2>&1
code=$?
set -e

if [[ "${code}" -ne 7 ]]; then
  echo "expected exit code 7 for missing dependency, got ${code}"
  exit 1
fi

echo "dependency missing contract check passed"
