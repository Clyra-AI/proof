#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow="${repo_root}/.github/workflows/release.yml"

require_pattern() {
  local pattern="$1"
  if ! grep -Fq -- "$pattern" "${workflow}"; then
    echo "release workflow missing: ${pattern}" >&2
    exit 1
  fi
}

line_for() {
  grep -n -m1 -F -- "$1" "${workflow}" | cut -d: -f1
}

require_pattern "args: release --clean --skip=publish"
require_pattern "run: ./scripts/verify_release_artifacts.sh dist"
require_pattern "run: ./scripts/release_security_scan.sh dist"
require_pattern "cosign sign-blob --yes"
require_pattern 'mktemp -d dist/.signing.XXXXXX'
require_pattern "actions/attest-build-provenance@v2"
require_pattern "gh release upload"
require_pattern "--clobber"
require_pattern "gh release create"
require_pattern "dist/*.tar.gz"
require_pattern "dist/*.zip"
require_pattern "dist/sbom.spdx.json"
require_pattern '[[ ${#assets[@]} -ne 10 ]]'

checksums_line="$(line_for 'run: ./scripts/verify_release_artifacts.sh dist')"
scan_line="$(line_for 'run: ./scripts/release_security_scan.sh dist')"
sign_line="$(line_for 'cosign sign-blob --yes')"
provenance_line="$(line_for 'actions/attest-build-provenance@v2')"
publish_line="$(line_for 'gh release create')"

if [[ "${checksums_line}" -ge "${scan_line}" || "${scan_line}" -ge "${sign_line}" || "${sign_line}" -ge "${provenance_line}" || "${provenance_line}" -ge "${publish_line}" ]]; then
  echo "release integrity steps are out of order" >&2
  exit 1
fi

echo "release workflow contract checks passed"
