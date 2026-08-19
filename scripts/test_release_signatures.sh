#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/proof-release-signatures.XXXXXX")"
trap 'rm -rf -- "${test_root}"' EXIT

remote_dir="${test_root}/remote"
mkdir -p "${remote_dir}"
printf 'remote signature\n' >"${remote_dir}/checksums.txt.sig"
printf 'remote certificate\n' >"${remote_dir}/checksums.txt.pem"

fake_gh="${test_root}/bin/gh"
fake_cosign="${test_root}/bin/cosign"
fake_sha256sum="${test_root}/bin/sha256sum"
mkdir -p "${test_root}/bin"
cat >"${fake_gh}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  api)
    case "${FAKE_GH_MODE}" in
      not-found) printf 'HTTP/2.0 404 Not Found\n'; exit 1 ;;
      api-error) printf 'HTTP/2.0 503 Service Unavailable\n'; exit 1 ;;
      existing) printf 'HTTP/2.0 200 OK\n' ;;
    esac
    ;;
  release)
    case "$2" in
      view) cat "${FAKE_VIEW_JSON}" ;;
      download)
        target=""
        while [[ $# -gt 0 ]]; do
          if [[ "$1" == "-D" ]]; then
            target="$2"
            shift 2
            continue
          fi
          shift
        done
        mkdir -p "${target}"
        cp -- "${FAKE_REMOTE_DIR}/checksums.txt.sig" "${target}/checksums.txt.sig"
        cp -- "${FAKE_REMOTE_DIR}/checksums.txt.pem" "${target}/checksums.txt.pem"
        ;;
    esac
    ;;
esac
SH
cat >"${fake_cosign}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "verify-blob" ]]; then
  printf '%s\n' "$*" >"${FAKE_COSIGN_ARGS}"
  exit 0
fi
echo "unexpected cosign invocation: $*" >&2
exit 1
SH
chmod +x "${fake_gh}" "${fake_cosign}"
cat >"${fake_sha256sum}" <<'SH'
#!/usr/bin/env bash
exec shasum -a 256 "$@"
SH
chmod +x "${fake_sha256sum}"

make_dist() {
  local name="$1"
  local dist="${test_root}/${name}/dist"
  local asset
  mkdir -p "${dist}"
  for asset in \
    sbom.spdx.json \
    proof_0.6.0_darwin_amd64.tar.gz \
    proof_0.6.0_darwin_arm64.tar.gz \
    proof_0.6.0_linux_amd64.tar.gz \
    proof_0.6.0_linux_arm64.tar.gz \
    proof_0.6.0_windows_amd64.zip \
    proof_0.6.0_windows_arm64.zip; do
    printf 'asset:%s\n' "${asset}" >"${dist}/${asset}"
  done
  python3 - "${dist}" <<'PY'
import hashlib
import pathlib
import sys

dist = pathlib.Path(sys.argv[1])
names = ["sbom.spdx.json", *sorted(path.name for path in dist.glob("proof_*.tar.gz")), *sorted(path.name for path in dist.glob("proof_*.zip"))]
(dist / "checksums.txt").write_text(
    "".join(f"{hashlib.sha256((dist / name).read_bytes()).hexdigest()}  {name}\n" for name in names),
    encoding="utf-8",
)
PY
  printf '%s\n' "${dist}"
}

write_json() {
  local path="$1"
  local status="$2"
  local assets_json="$3"
  python3 - "${path}" "${status}" "${assets_json}" "${remote_dir}" <<'PY'
import hashlib
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
status = sys.argv[2]
assets_json = sys.argv[3]
remote_dir = pathlib.Path(sys.argv[4])
assets = json.loads(assets_json)
for asset in assets:
    asset["digest"] = "sha256:" + hashlib.sha256((remote_dir / asset["name"]).read_bytes()).hexdigest()
data = {
    "isDraft": status == "draft",
    "isPrerelease": False,
    "publishedAt": None if status in {"draft", "unpublished"} else "2026-08-19T00:00:00Z",
    "assets": assets,
}
path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
PY
}

signature_assets='[{"name":"checksums.txt.sig"},{"name":"checksums.txt.pem"}]'
partial_assets='[{"name":"checksums.txt.sig"}]'
empty_assets='[]'
complete_json="${test_root}/complete.json"
partial_json="${test_root}/partial.json"
empty_json="${test_root}/empty.json"
draft_json="${test_root}/draft.json"
mismatch_json="${test_root}/mismatch.json"
write_json "${complete_json}" published "${signature_assets}"
write_json "${partial_json}" published "${partial_assets}"
write_json "${empty_json}" published "${empty_assets}"
write_json "${draft_json}" draft "${signature_assets}"
python3 - "${complete_json}" "${mismatch_json}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
data["assets"][0]["digest"] = "sha256:" + "f" * 64
pathlib.Path(sys.argv[2]).write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
PY

run_prepare() {
  local name="$1" mode="$2" release_json="$3" expected="$4"
  local dist output args_file
  dist="$(make_dist "${name}")"
  output="${test_root}/${name}.output"
  args_file="${test_root}/${name}.cosign"
  if [[ "${expected}" != fail ]]; then
    FAKE_GH_MODE="${mode}" FAKE_VIEW_JSON="${release_json}" FAKE_REMOTE_DIR="${remote_dir}" \
      FAKE_COSIGN_ARGS="${args_file}" GITHUB_OUTPUT="${output}" \
      COSIGN_CERT_IDENTITY='https://github.com/Clyra-AI/proof/.github/workflows/release.yml@refs/tags/v0.6.0' \
      COSIGN_CERT_ISSUER='https://token.actions.githubusercontent.com' \
      PATH="${test_root}/bin:/usr/bin:/bin" \
      "${repo_root}/scripts/prepare_release_signatures.sh" "${dist}" v0.6.0 Clyra-AI/proof
  else
    if FAKE_GH_MODE="${mode}" FAKE_VIEW_JSON="${release_json}" FAKE_REMOTE_DIR="${remote_dir}" \
      FAKE_COSIGN_ARGS="${args_file}" GITHUB_OUTPUT="${output}" \
      COSIGN_CERT_IDENTITY='https://github.com/Clyra-AI/proof/.github/workflows/release.yml@refs/tags/v0.6.0' \
      COSIGN_CERT_ISSUER='https://token.actions.githubusercontent.com' \
      PATH="${test_root}/bin:/usr/bin:/bin" \
      "${repo_root}/scripts/prepare_release_signatures.sh" "${dist}" v0.6.0 Clyra-AI/proof; then
      echo "signature preparation unexpectedly succeeded: ${name}" >&2
      exit 1
    fi
    if [[ -e "${dist}/checksums.txt.sig" || -e "${dist}/checksums.txt.pem" ]]; then
      echo "failed signature preparation left a local pair: ${name}" >&2
      exit 1
    fi
    return
  fi
  grep -Fq "mode=${expected}" "${output}" || { echo "unexpected signature mode: ${expected}" >&2; exit 1; }
  if [[ "${expected}" == reuse ]]; then
    cmp -- "${remote_dir}/checksums.txt.sig" "${dist}/checksums.txt.sig"
    cmp -- "${remote_dir}/checksums.txt.pem" "${dist}/checksums.txt.pem"
    grep -Fq -- '--certificate-identity https://github.com/Clyra-AI/proof/.github/workflows/release.yml@refs/tags/v0.6.0' "${args_file}"
    grep -Fq -- '--certificate-oidc-issuer https://token.actions.githubusercontent.com' "${args_file}"
  fi
}

run_prepare existing existing "${complete_json}" reuse
run_prepare no-pair existing "${empty_json}" sign
run_prepare not-found not-found "${empty_json}" sign
run_prepare api-error api-error "${empty_json}" fail
run_prepare partial existing "${partial_json}" fail
run_prepare draft existing "${draft_json}" fail
run_prepare mismatch existing "${mismatch_json}" fail

echo "release signature preparation contract checks passed"
