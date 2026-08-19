#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/proof-release-security-XXXXXX")"
trap 'rm -rf -- "${test_root}"' EXIT

fake_grype="${test_root}/grype"
fake_govuln="${test_root}/govulncheck"
cat >"${fake_grype}" <<'SH'
#!/usr/bin/env bash
set -eu
mode="${FAKE_GRYPE_MODE:?}"
if [[ "$1" == "db" && "$2" == "update" ]]; then
  case "$mode" in
    success|vulnerability|scan-collision|stale-simple) echo "database refresh complete"; exit 0 ;;
    stale|stale-success) echo "[0000]  WARN current database is invalid error=the vulnerability database was built 22 weeks ago (max allowed age is 5 days)"; exit 1 ;;
    generic) echo "network unavailable"; exit 42 ;;
    collision) echo "fatal: max allowed age parser configuration is invalid"; exit 41 ;;
  esac
fi
if [[ "$1" == dir:* ]]; then
  case "$mode" in
    success|stale-success) echo "no vulnerabilities"; exit 0 ;;
    scan-collision) echo "fatal: max allowed age parser configuration is invalid"; exit 41 ;;
    vulnerability) echo "1 vulnerability found: CVE-2099-0001"; exit 1 ;;
    stale) echo "[0000] ERROR failed to load vulnerability db: the vulnerability database was built 22 weeks ago (max allowed age is 5 days)"; exit 1 ;;
    stale-simple) echo "db could not be loaded: the vulnerability database was built 23 weeks ago (max allowed age is 5 days)"; exit 1 ;;
    generic) echo "should not scan after generic update failure"; exit 99 ;;
    collision) echo "fatal: max allowed age parser configuration is invalid"; exit 41 ;;
  esac
fi
echo "unexpected fake grype invocation: $*" >&2
exit 98
SH
cat >"${fake_govuln}" <<'SH'
#!/usr/bin/env bash
set -eu
echo "$*" >>"${FAKE_GOVULN_LOG:?}"
exit 0
SH
chmod +x "${fake_grype}" "${fake_govuln}"

make_dist() {
  local name="$1"
  local dist="${test_root}/${name}/dist"
  mkdir -p "${dist}/scan-root/release"
  : >"${dist}/scan-root/release/proof"
  printf '%s\n' "${dist}"
}

make_archive_dist() {
  local dist work target
  dist="${test_root}/archives/dist"
  work="${test_root}/archives/work"
  mkdir -p "${dist}" "${work}"
  for target in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
    mkdir -p "${work}/${target}"
    : >"${work}/${target}/proof"
    tar -czf "${dist}/proof_0.6.0_${target}.tar.gz" -C "${work}/${target}" proof
  done
  for target in windows_amd64 windows_arm64; do
    mkdir -p "${work}/${target}"
    : >"${work}/${target}/proof.exe"
    (cd "${work}/${target}" && zip -q "${dist}/proof_0.6.0_${target}.zip" proof.exe)
  done
  printf '%s\n' "${dist}"
}

run_archive_extraction_case() {
  local dist
  dist="$(make_archive_dist)"
  FAKE_GRYPE_MODE=success RELEASE_GRYPE_BIN="${fake_grype}" RELEASE_GOVULNCHECK_BIN="${fake_govuln}" \
    "${repo_root}/scripts/release_security_scan.sh" "${dist}"
  [[ "$(find "${dist}/scan-root" -type f \( -name proof -o -name proof.exe \) | wc -l | tr -d ' ')" == 6 ]] || {
    echo "archive extraction did not produce six release binaries" >&2
    exit 1
  }
}

run_success_case() {
  local dist
  dist="$(make_dist success)"
  FAKE_GRYPE_MODE=success RELEASE_GRYPE_BIN="${fake_grype}" RELEASE_GOVULNCHECK_BIN="${fake_govuln}" \
    "${repo_root}/scripts/release_security_scan.sh" "${dist}" "${dist}/scan-root"
}

run_vulnerability_case() {
  local dist
  dist="$(make_dist vulnerability)"
  if FAKE_GRYPE_MODE=vulnerability RELEASE_GRYPE_BIN="${fake_grype}" RELEASE_GOVULNCHECK_BIN="${fake_govuln}" \
    "${repo_root}/scripts/release_security_scan.sh" "${dist}" "${dist}/scan-root"; then
    echo "real vulnerability failure was incorrectly accepted" >&2
    exit 1
  fi
  if [[ -e "${dist}/scan/govulncheck.log" ]]; then
    echo "real vulnerability failure incorrectly used fallback" >&2
    exit 1
  fi
}

run_stale_case() {
  local dist log
  dist="$(make_dist stale)"
  log="${dist}/govuln-invocations.log"
  FAKE_GRYPE_MODE=stale FAKE_GOVULN_LOG="${log}" RELEASE_GRYPE_BIN="${fake_grype}" RELEASE_GOVULNCHECK_BIN="${fake_govuln}" \
    "${repo_root}/scripts/release_security_scan.sh" "${dist}" "${dist}/scan-root"
  [[ -s "${dist}/scan/govulncheck.log" ]] || { echo "stale fallback did not write govulncheck log" >&2; exit 1; }
  [[ -s "${log}" ]] || { echo "stale fallback did not invoke govulncheck" >&2; exit 1; }
}

run_stale_success_case() {
  local dist log
  dist="$(make_dist stale-success)"
  log="${dist}/govuln-invocations.log"
  FAKE_GRYPE_MODE=stale-success FAKE_GOVULN_LOG="${log}" RELEASE_GRYPE_BIN="${fake_grype}" RELEASE_GOVULNCHECK_BIN="${fake_govuln}" \
    "${repo_root}/scripts/release_security_scan.sh" "${dist}" "${dist}/scan-root"
  [[ -s "${log}" ]] || { echo "stale refresh failure must still trigger fallback after a zero scan" >&2; exit 1; }
}

run_stale_simple_case() {
  local dist log
  dist="$(make_dist stale-simple)"
  log="${dist}/govuln-invocations.log"
  FAKE_GRYPE_MODE=stale-simple FAKE_GOVULN_LOG="${log}" RELEASE_GRYPE_BIN="${fake_grype}" RELEASE_GOVULNCHECK_BIN="${fake_govuln}" \
    "${repo_root}/scripts/release_security_scan.sh" "${dist}" "${dist}/scan-root"
  [[ -s "${log}" ]] || { echo "exact db-could-not-be-loaded freshness diagnostic did not trigger fallback" >&2; exit 1; }
}

run_generic_update_case() {
  local dist
  dist="$(make_dist generic)"
  if FAKE_GRYPE_MODE=generic RELEASE_GRYPE_BIN="${fake_grype}" RELEASE_GOVULNCHECK_BIN="${fake_govuln}" \
    "${repo_root}/scripts/release_security_scan.sh" "${dist}" "${dist}/scan-root"; then
    echo "generic Grype update failure was incorrectly accepted" >&2
    exit 1
  fi
  if [[ -e "${dist}/scan/govulncheck.log" ]]; then
    echo "generic Grype update failure incorrectly used fallback" >&2
    exit 1
  fi
}

run_stale_marker_collision_case() {
  local dist
  dist="$(make_dist collision)"
  if FAKE_GRYPE_MODE=collision RELEASE_GRYPE_BIN="${fake_grype}" RELEASE_GOVULNCHECK_BIN="${fake_govuln}" \
    "${repo_root}/scripts/release_security_scan.sh" "${dist}" "${dist}/scan-root"; then
    echo "generic freshness-marker collision was incorrectly accepted" >&2
    exit 1
  fi
  if [[ -e "${dist}/scan/govulncheck.log" ]]; then
    echo "generic freshness-marker collision incorrectly used fallback" >&2
    exit 1
  fi

  dist="$(make_dist scan-collision)"
  if FAKE_GRYPE_MODE=scan-collision RELEASE_GRYPE_BIN="${fake_grype}" RELEASE_GOVULNCHECK_BIN="${fake_govuln}" \
    "${repo_root}/scripts/release_security_scan.sh" "${dist}" "${dist}/scan-root"; then
    echo "generic scan freshness-marker collision was incorrectly accepted" >&2
    exit 1
  fi
  if [[ -e "${dist}/scan/govulncheck.log" ]]; then
    echo "generic scan freshness-marker collision incorrectly used fallback" >&2
    exit 1
  fi
}

run_success_case
run_archive_extraction_case
run_vulnerability_case
run_stale_case
run_stale_success_case
run_stale_simple_case
run_generic_update_case
run_stale_marker_collision_case
echo "release security scan contract checks passed"
