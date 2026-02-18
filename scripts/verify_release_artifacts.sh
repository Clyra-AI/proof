#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${1:-dist}"

if [[ ! -f "${DIST_DIR}/checksums.txt" ]]; then
  echo "missing ${DIST_DIR}/checksums.txt"
  exit 1
fi

(
  cd "${DIST_DIR}"
  sha256sum -c checksums.txt
)

if [[ -f "${DIST_DIR}/checksums.txt.sig" && -f "${DIST_DIR}/checksums.txt.pem" ]]; then
  if command -v cosign >/dev/null 2>&1; then
    cosign verify-blob --certificate "${DIST_DIR}/checksums.txt.pem" --signature "${DIST_DIR}/checksums.txt.sig" "${DIST_DIR}/checksums.txt"
  else
    echo "cosign not installed; skipping signature verification"
  fi
fi

echo "release artifact verification passed"
