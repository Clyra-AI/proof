#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

DIST_DIR="${1:-dist}"
RELEASE_TAG="${2:?release tag is required}"
REPOSITORY="${3:-${GITHUB_REPOSITORY:?repository is required}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_IDENTITY="${COSIGN_CERT_IDENTITY:?cosign certificate identity is required}"
CERT_ISSUER="${COSIGN_CERT_ISSUER:?cosign certificate issuer is required}"

if [[ ! "${RELEASE_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid release tag: ${RELEASE_TAG}" >&2
  exit 1
fi
if [[ ! -d "${DIST_DIR}" || -L "${DIST_DIR}" ]]; then
  echo "release distribution directory is missing or unsafe: ${DIST_DIR}" >&2
  exit 1
fi

for name in checksums.txt.sig checksums.txt.pem; do
  if [[ -e "${DIST_DIR}/${name}" || -L "${DIST_DIR}/${name}" ]]; then
    echo "local checksum signature asset already exists; refusing to overwrite: ${DIST_DIR}/${name}" >&2
    exit 1
  fi
done

emit_mode() {
  local mode="$1"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'mode=%s\n' "${mode}" >>"${GITHUB_OUTPUT}"
  fi
  printf 'checksum signature mode: %s\n' "${mode}"
}

tmp_root="$(mktemp -d "${DIST_DIR}/.signature-reuse.XXXXXX")"
trap 'rm -rf -- "${tmp_root}"' EXIT
api_response="${tmp_root}/api-response"
api_error="${tmp_root}/api-error"
release_json="${tmp_root}/release.json"
signature_json="${tmp_root}/signature.json"
download_dir="${tmp_root}/download"
reuse_dir="${tmp_root}/reuse"

set +e
gh api --include "repos/${REPOSITORY}/releases/tags/${RELEASE_TAG}" >"${api_response}" 2>"${api_error}"
api_status=$?
set -e

if [[ ${api_status} -ne 0 ]]; then
  if ! grep -Eiq '^HTTP/[0-9.]+[[:space:]]+404([[:space:]]|$)' "${api_response}"; then
    cat "${api_response}" "${api_error}" >&2
    echo "release lookup failed without an HTTP 404; refusing to sign or overwrite" >&2
    exit "${api_status}"
  fi
  emit_mode sign
  exit 0
fi

gh release view "${RELEASE_TAG}" \
  --repo "${REPOSITORY}" \
  --json isDraft,isPrerelease,publishedAt,assets >"${release_json}"
python3 "${SCRIPT_DIR}/check_release_asset_set.py" \
  "${release_json}" "${DIST_DIR}" "${RELEASE_TAG#v}" \
  --metadata-only --require-published

pair_state="$(python3 - "${release_json}" "${signature_json}" <<'PY'
import json
import pathlib
import sys

release_path = pathlib.Path(sys.argv[1])
signature_path = pathlib.Path(sys.argv[2])
data = json.loads(release_path.read_text(encoding="utf-8"))
assets = data["assets"]
names = [asset.get("name") if isinstance(asset, dict) else None for asset in assets]
if any(not isinstance(name, str) for name in names) or len(names) != len(set(names)):
    raise SystemExit("release assets must have unique string names")

signature_names = {"checksums.txt.sig", "checksums.txt.pem"}
present = signature_names & set(names)
if present and present != signature_names:
    raise SystemExit("release has a partial checksum signature pair")
if not present:
    print("missing")
    raise SystemExit(0)

signature_path.write_text(
    json.dumps({"assets": [asset for asset in assets if asset["name"] in signature_names]}, sort_keys=True),
    encoding="utf-8",
)
print("present")
PY
)"

if [[ "${pair_state}" == missing ]]; then
  emit_mode sign
  exit 0
fi

mkdir -p "${download_dir}"
gh release download "${RELEASE_TAG}" \
  --repo "${REPOSITORY}" \
  --pattern checksums.txt.sig \
  --pattern checksums.txt.pem \
  -D "${download_dir}"
python3 "${SCRIPT_DIR}/check_release_asset_set.py" \
  "${signature_json}" "${download_dir}" "${RELEASE_TAG#v}" \
  --allow-missing

mkdir -p "${reuse_dir}"
for name in checksums.txt.sig checksums.txt.pem; do
  if [[ ! -f "${download_dir}/${name}" || -L "${download_dir}/${name}" ]]; then
    echo "downloaded checksum signature asset is missing or unsafe: ${name}" >&2
    exit 1
  fi
  cp -- "${download_dir}/${name}" "${reuse_dir}/${name}"
done

for name in checksums.txt.sig checksums.txt.pem; do
  ln "${reuse_dir}/${name}" "${DIST_DIR}/${name}"
done

COSIGN_CERT_IDENTITY="${CERT_IDENTITY}" \
COSIGN_CERT_ISSUER="${CERT_ISSUER}" \
  "${SCRIPT_DIR}/verify_release_artifacts.sh" "${DIST_DIR}"
emit_mode reuse
