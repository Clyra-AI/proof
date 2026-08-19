#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

DIST_DIR="${1:-dist}"
RELEASE_TAG="${2:?release tag is required}"
REPOSITORY="${3:-${GITHUB_REPOSITORY:?repository is required}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! "${RELEASE_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid release tag: ${RELEASE_TAG}" >&2
  exit 1
fi
if [[ ! -d "${DIST_DIR}" || -L "${DIST_DIR}" ]]; then
  echo "release distribution directory is missing or unsafe: ${DIST_DIR}" >&2
  exit 1
fi

version="${RELEASE_TAG#v}"
assets=(
  "${DIST_DIR}/checksums.txt"
  "${DIST_DIR}/checksums.txt.sig"
  "${DIST_DIR}/checksums.txt.pem"
  "${DIST_DIR}/sbom.spdx.json"
  "${DIST_DIR}/proof_${version}_darwin_amd64.tar.gz"
  "${DIST_DIR}/proof_${version}_darwin_arm64.tar.gz"
  "${DIST_DIR}/proof_${version}_linux_amd64.tar.gz"
  "${DIST_DIR}/proof_${version}_linux_arm64.tar.gz"
  "${DIST_DIR}/proof_${version}_windows_amd64.zip"
  "${DIST_DIR}/proof_${version}_windows_arm64.zip"
)
for asset in "${assets[@]}"; do
  if [[ ! -f "${asset}" || -L "${asset}" ]]; then
    echo "release asset is missing or unsafe: ${asset}" >&2
    exit 1
  fi
done

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/proof-release-publish.XXXXXX")"
trap 'rm -rf -- "${tmp_root}"' EXIT
api_response="${tmp_root}/api-response"
api_error="${tmp_root}/api-error"
release_json="${tmp_root}/release.json"
missing_assets="${tmp_root}/missing-assets"

set +e
gh api --include "repos/${REPOSITORY}/releases/tags/${RELEASE_TAG}" >"${api_response}" 2>"${api_error}"
api_status=$?
set -e

if [[ ${api_status} -ne 0 ]]; then
  if ! grep -Eiq '^HTTP/[0-9.]+[[:space:]]+404([[:space:]]|$)' "${api_response}"; then
    cat "${api_response}" "${api_error}" >&2
    echo "release lookup failed without an HTTP 404; refusing to create or overwrite" >&2
    exit "${api_status}"
  fi

  gh release create "${RELEASE_TAG}" "${assets[@]}" \
    --repo "${REPOSITORY}" \
    --verify-tag \
    --title "${RELEASE_TAG}" \
    --generate-notes
else
  gh release view "${RELEASE_TAG}" --repo "${REPOSITORY}" --json isDraft,isPrerelease,publishedAt,assets >"${release_json}"
  python3 "${SCRIPT_DIR}/check_release_asset_set.py" \
    "${release_json}" "${DIST_DIR}" "${version}" \
    --allow-missing --require-published --missing-output "${missing_assets}"

  missing=()
  while IFS= read -r name; do
    [[ -n "${name}" ]] && missing+=("${name}")
  done <"${missing_assets}"
  if [[ ${#missing[@]} -gt 0 ]]; then
    upload_assets=()
    for name in "${missing[@]}"; do
      upload_assets+=("${DIST_DIR}/${name}")
    done
    gh release upload "${RELEASE_TAG}" "${upload_assets[@]}" --repo "${REPOSITORY}"
  fi
fi

gh release view "${RELEASE_TAG}" --repo "${REPOSITORY}" --json isDraft,isPrerelease,publishedAt,assets >"${release_json}"
python3 "${SCRIPT_DIR}/check_release_asset_set.py" \
  "${release_json}" "${DIST_DIR}" "${version}" --require-published
