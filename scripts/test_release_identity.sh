#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/proof-release-identity.XXXXXX")"
trap 'rm -rf -- "${test_root}"' EXIT
mkdir -p "${test_root}/dist" "${test_root}/bin"
printf 'fixture\n' >"${test_root}/dist/checksums.txt"
: >"${test_root}/dist/checksums.txt.sig"
: >"${test_root}/dist/checksums.txt.pem"

cat >"${test_root}/bin/sha256sum" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat >"${test_root}/bin/cosign" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >"${FAKE_COSIGN_ARGS}"
SH
chmod +x "${test_root}/bin/sha256sum" "${test_root}/bin/cosign"

args_file="${test_root}/cosign.args"
PATH="${test_root}/bin:/usr/bin:/bin" \
  FAKE_COSIGN_ARGS="${args_file}" \
  GITHUB_ACTIONS=true \
  GITHUB_WORKFLOW_REF='Clyra-AI/proof/.github/workflows/release-repair.yml@refs/heads/main' \
  COSIGN_CERT_IDENTITY='https://github.com/Clyra-AI/proof/.github/workflows/release.yml@refs/tags/v0.5.0' \
  COSIGN_CERT_ISSUER='https://token.actions.githubusercontent.com' \
  "${repo_root}/scripts/verify_release_artifacts.sh" "${test_root}/dist" >/dev/null

if ! grep -Fq -- '--certificate-identity https://github.com/Clyra-AI/proof/.github/workflows/release.yml@refs/tags/v0.5.0' "${args_file}"; then
  echo "explicit release identity was not passed to cosign" >&2
  exit 1
fi
if grep -Fq -- 'release-repair.yml@refs/heads/main' "${args_file}"; then
  echo "current repair workflow identity was incorrectly inferred" >&2
  exit 1
fi

PATH="${test_root}/bin:/usr/bin:/bin" \
  FAKE_COSIGN_ARGS="${args_file}" \
  GITHUB_ACTIONS=true \
  GITHUB_WORKFLOW_REF='Clyra-AI/proof/.github/workflows/release-repair.yml@refs/heads/main' \
  "${repo_root}/scripts/verify_release_artifacts.sh" "${test_root}/dist" >/dev/null
if grep -Fq -- '--certificate-identity' "${args_file}" || grep -Fq -- '--certificate-oidc-issuer' "${args_file}"; then
  echo "workflow identity was inferred without explicit configuration" >&2
  exit 1
fi

echo "release identity contract checks passed"
