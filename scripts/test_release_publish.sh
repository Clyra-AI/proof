#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/proof-release-publish.XXXXXX")"
trap 'rm -rf -- "${test_root}"' EXIT

dist="${test_root}/dist"
mkdir -p "${dist}"
version="0.6.0"
names=(
  checksums.txt checksums.txt.sig checksums.txt.pem sbom.spdx.json
  "proof_${version}_darwin_amd64.tar.gz"
  "proof_${version}_darwin_arm64.tar.gz"
  "proof_${version}_linux_amd64.tar.gz"
  "proof_${version}_linux_arm64.tar.gz"
  "proof_${version}_windows_amd64.zip"
  "proof_${version}_windows_arm64.zip"
)
for name in "${names[@]}"; do
  printf 'fixture:%s\n' "${name}" >"${dist}/${name}"
done

complete_json="${test_root}/complete.json"
missing_json="${test_root}/missing.json"
partial_json="${test_root}/partial.json"
extra_json="${test_root}/extra.json"
mismatch_json="${test_root}/mismatch.json"
different_json="${test_root}/different.json"
draft_json="${test_root}/draft.json"
prerelease_json="${test_root}/prerelease.json"
unpublished_json="${test_root}/unpublished.json"
python3 - "${dist}" "${complete_json}" "${missing_json}" "${partial_json}" "${extra_json}" "${mismatch_json}" "${different_json}" "${draft_json}" "${prerelease_json}" "${unpublished_json}" <<'PY'
import hashlib
import json
import pathlib
import sys

dist = pathlib.Path(sys.argv[1])
paths = [path for path in sorted(dist.iterdir()) if path.is_file()]
assets = [
    {"name": path.name, "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()}
    for path in paths
]
def write(path, selected):
    pathlib.Path(path).write_text(json.dumps({
        "isDraft": False,
        "isPrerelease": False,
        "publishedAt": "2026-08-19T00:00:00Z",
        "assets": selected,
    }, sort_keys=True), encoding="utf-8")

write(sys.argv[2], assets)
write(sys.argv[3], [asset for asset in assets if not asset["name"].endswith((".sig", ".pem"))])
write(sys.argv[4], [asset for asset in assets if not asset["name"].endswith(".pem")])
extra = assets + [{"name": "unexpected.txt", "digest": "sha256:" + "0" * 64}]
write(sys.argv[5], extra)
wrong = [dict(asset) for asset in assets]
wrong[0]["digest"] = "sha256:" + "f" * 64
write(sys.argv[6], wrong)
different = [dict(asset) for asset in assets]
for asset in different:
    if asset["name"] in {"checksums.txt.sig", "checksums.txt.pem"}:
        asset["digest"] = "sha256:" + "0" * 64
write(sys.argv[7], different)
draft = {"isDraft": True, "isPrerelease": False, "publishedAt": None, "assets": assets}
prerelease = {"isDraft": False, "isPrerelease": True, "publishedAt": "2026-08-19T00:00:00Z", "assets": assets}
unpublished = {"isDraft": False, "isPrerelease": False, "publishedAt": None, "assets": assets}
pathlib.Path(sys.argv[8]).write_text(json.dumps(draft, sort_keys=True), encoding="utf-8")
pathlib.Path(sys.argv[9]).write_text(json.dumps(prerelease, sort_keys=True), encoding="utf-8")
pathlib.Path(sys.argv[10]).write_text(json.dumps(unpublished, sort_keys=True), encoding="utf-8")
PY

fake_gh="${test_root}/gh"
cat >"${fake_gh}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  api)
    if [[ "${FAKE_GH_MODE}" == "not-found" ]]; then
      printf 'HTTP/2.0 404 Not Found\n'
      exit 1
    fi
    if [[ "${FAKE_GH_MODE}" == "api-error" ]]; then
      printf 'HTTP/2.0 500 Internal Server Error\n'
      printf 'permission denied\n' >&2
      exit 1
    fi
    printf 'HTTP/2.0 200 OK\n'
    ;;
  release)
    case "$2" in
      view)
        cat "${FAKE_VIEW_JSON}"
        ;;
      create)
        : >"${FAKE_CREATE_MARKER}"
        cp "${FAKE_COMPLETE_JSON}" "${FAKE_VIEW_JSON}"
        ;;
      upload)
        printf '%s\n' "$*" >"${FAKE_UPLOAD_MARKER}"
        cp "${FAKE_COMPLETE_JSON}" "${FAKE_VIEW_JSON}"
        ;;
    esac
    ;;
esac
SH
chmod +x "${fake_gh}"

run_publish() {
  local mode="$1"
  local view_json="$2"
  local expected="$3"
  local view_file="${test_root}/view.json"
  local upload_marker="${test_root}/upload.marker"
  local create_marker="${test_root}/create.marker"
  rm -f "${upload_marker}" "${create_marker}"
  cp "${view_json}" "${view_file}"
  if [[ "${expected}" == pass || "${expected}" == no-upload || "${expected}" == upload ]]; then
    FAKE_GH_MODE="${mode}" FAKE_VIEW_JSON="${view_file}" FAKE_COMPLETE_JSON="${complete_json}" \
      FAKE_UPLOAD_MARKER="${upload_marker}" FAKE_CREATE_MARKER="${create_marker}" \
      PATH="${test_root}:$PATH" GITHUB_REPOSITORY=Clyra-AI/proof \
      "${repo_root}/scripts/publish_release_assets.sh" "${dist}" "v${version}" Clyra-AI/proof
  else
    if FAKE_GH_MODE="${mode}" FAKE_VIEW_JSON="${view_file}" FAKE_COMPLETE_JSON="${complete_json}" \
      FAKE_UPLOAD_MARKER="${upload_marker}" FAKE_CREATE_MARKER="${create_marker}" \
      PATH="${test_root}:$PATH" GITHUB_REPOSITORY=Clyra-AI/proof \
      "${repo_root}/scripts/publish_release_assets.sh" "${dist}" "v${version}" Clyra-AI/proof; then
      echo "publication unexpectedly succeeded for ${mode}" >&2
      exit 1
    fi
  fi
  case "${expected}" in
    pass)
      ;;
    no-upload)
      [[ ! -e "${upload_marker}" ]] || { echo "complete release was overwritten" >&2; exit 1; }
      ;;
    upload)
      [[ -e "${upload_marker}" ]] || { echo "missing assets were not uploaded" >&2; exit 1; }
      ! grep -Fq -- "--clobber" "${upload_marker}" || { echo "upload clobbered assets" >&2; exit 1; }
      ;;
    no-create)
      [[ ! -e "${create_marker}" ]] || { echo "API failure attempted creation" >&2; exit 1; }
      ;;
  esac
}

run_publish not-found "${missing_json}" pass
[[ -e "${test_root}/create.marker" ]] || { echo "404 did not create release" >&2; exit 1; }
run_publish existing "${complete_json}" no-upload
run_publish existing "${missing_json}" upload
run_publish existing "${extra_json}" no-create
run_publish existing "${mismatch_json}" no-create
run_publish existing "${partial_json}" no-create
run_publish existing "${different_json}" no-create
run_publish existing "${draft_json}" no-create
run_publish existing "${prerelease_json}" no-create
run_publish existing "${unpublished_json}" no-create
run_publish api-error "${complete_json}" no-create

echo "release publication contract checks passed"
