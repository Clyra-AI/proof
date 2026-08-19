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
    verify_args=(
      verify-blob
      --certificate "${DIST_DIR}/checksums.txt.pem"
      --signature "${DIST_DIR}/checksums.txt.sig"
    )

    cert_identity="${COSIGN_CERT_IDENTITY:-}"
    cert_issuer="${COSIGN_CERT_ISSUER:-}"

    if [[ -n "${cert_identity}" ]]; then
      verify_args+=(--certificate-identity "${cert_identity}")
    fi
    if [[ -n "${cert_issuer}" ]]; then
      verify_args+=(--certificate-oidc-issuer "${cert_issuer}")
    fi

    verify_args+=("${DIST_DIR}/checksums.txt")
    cosign "${verify_args[@]}"
  else
    echo "cosign not installed; skipping signature verification"
  fi
fi

echo "release artifact verification passed"
