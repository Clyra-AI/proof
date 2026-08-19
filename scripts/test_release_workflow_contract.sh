#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow="${repo_root}/.github/workflows/release.yml"
repair_workflow="${repo_root}/.github/workflows/release-repair.yml"
publish_script="${repo_root}/scripts/publish_release_assets.sh"

require_pattern() {
  local file="$1"
  local pattern="$2"
  if ! grep -Fq -- "${pattern}" "${file}"; then
    echo "${file} missing: ${pattern}" >&2
    exit 1
  fi
}

line_for() {
  local file="$1"
  local pattern="$2"
  grep -n -m1 -F -- "${pattern}" "${file}" | cut -d: -f1
}

require_pattern "${workflow}" "args: release --clean --skip=publish"
require_pattern "${workflow}" "run: ./scripts/verify_release_artifacts.sh dist"
require_pattern "${workflow}" "run: ./scripts/release_security_scan.sh dist"
require_pattern "${workflow}" "run: ./scripts/prepare_release_signatures.sh dist"
require_pattern "${workflow}" "if: steps.checksum_signatures.outputs.mode == 'sign'"
require_pattern "${workflow}" 'RELEASE_TAG: ${{ github.ref_name }}'
require_pattern "${workflow}" 'COSIGN_CERT_IDENTITY: https://github.com/${{ github.workflow_ref }}'
require_pattern "${workflow}" "actions/attest-build-provenance@v2"
require_pattern "${workflow}" "run: ./scripts/publish_release_assets.sh dist"
require_pattern "${workflow}" "refusing to overwrite"
require_pattern "${publish_script}" "gh api --include"
require_pattern "${publish_script}" "HTTP/[0-9.]+"
require_pattern "${publish_script}" "refusing to create or overwrite"
require_pattern "${publish_script}" "check_release_asset_set.py"
require_pattern "${publish_script}" "--require-published"
if grep -Fq -- "--clobber" "${workflow}" || grep -Fq -- "--clobber" "${publish_script}"; then
  echo "normal release publication must not clobber assets" >&2
  exit 1
fi
if grep -Eq 'run:.*\$\{\{ github\.ref_name \}\}' "${workflow}"; then
  echo "normal release run steps must not interpolate the tag directly" >&2
  exit 1
fi

require_pattern "${repair_workflow}" "path: release-source"
require_pattern "${repair_workflow}" "path: trusted-source"
require_pattern "${repair_workflow}" 'ref: ${{ github.sha }}'
require_pattern "${repair_workflow}" "git -C release-source rev-parse HEAD"
require_pattern "${repair_workflow}" "git -C trusted-source rev-parse HEAD"
require_pattern "${repair_workflow}" "trusted-source/scripts/release_security_scan.sh dist"
require_pattern "${repair_workflow}" "trusted-source/scripts/check_release_asset_set.py"
require_pattern "${repair_workflow}" "COSIGN_CERT_IDENTITY: https://github.com/Clyra-AI/proof/.github/workflows/release.yml@refs/tags/v0.5.0"
require_pattern "${repair_workflow}" "refusing to overwrite"
if grep -Fq -- "--clobber" "${repair_workflow}"; then
  echo "repair workflow must not clobber downloaded or published assets" >&2
  exit 1
fi

checksums_line="$(line_for "${workflow}" 'run: ./scripts/verify_release_artifacts.sh dist')"
scan_line="$(line_for "${workflow}" 'run: ./scripts/release_security_scan.sh dist')"
sign_line="$(line_for "${workflow}" 'cosign sign-blob --yes')"
provenance_line="$(line_for "${workflow}" 'actions/attest-build-provenance@v2')"
publish_line="$(line_for "${workflow}" 'run: ./scripts/publish_release_assets.sh dist')"

if [[ "${checksums_line}" -ge "${scan_line}" || "${scan_line}" -ge "${sign_line}" || "${sign_line}" -ge "${provenance_line}" || "${provenance_line}" -ge "${publish_line}" ]]; then
  echo "release integrity steps are out of order" >&2
  exit 1
fi

malicious_tag='v1.2.3"$(printf${IFS}INJECTED)"'
if ! git check-ref-format "refs/tags/${malicious_tag}"; then
  echo "malicious tag fixture is not a valid Git tag; test is ineffective" >&2
  exit 1
fi
malicious_output=""
if malicious_output="$(RELEASE_TAG="${malicious_tag}" "${publish_script}" /missing-dist "${malicious_tag}" Clyra-AI/proof 2>&1)"; then
  echo "malicious tag was unexpectedly accepted" >&2
  exit 1
fi
if grep -Fq "invalid release tag" <<<"${malicious_output}"; then
  :
else
  echo "malicious tag was not rejected before publication" >&2
  exit 1
fi

echo "release workflow contract checks passed"
