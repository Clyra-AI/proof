#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

DIST_DIR="${1:-dist}"
SCAN_ROOT="${2:-}"
GRYPE_BIN="${RELEASE_GRYPE_BIN:-grype}"
GOVULNCHECK_BIN="${RELEASE_GOVULNCHECK_BIN:-}"
# Keep this anchored to Grype's complete freshness diagnostic. A loose phrase
# match would let unrelated tool/database errors reach the fallback path.
STALE_DB_PATTERN='(^\[[0-9]{4}\][[:space:]]+(WARN current database is invalid error=the vulnerability database was built [^()[:cntrl:]]+ \(max allowed age is [^()[:cntrl:]]+\)|ERROR failed to load vulnerability db: the vulnerability database was built [^()[:cntrl:]]+ \(max allowed age is [^()[:cntrl:]]+\))$|^db could not be loaded: the vulnerability database was built [^()[:cntrl:]]+ \(max allowed age is [^()[:cntrl:]]+\)$)'

if [[ -z "${DIST_DIR}" || ! -d "${DIST_DIR}" ]]; then
  echo "release security scan requires an existing dist directory: ${DIST_DIR}" >&2
  exit 1
fi

scan_dir="${DIST_DIR}/scan"
mkdir -p "${scan_dir}"

if [[ -z "${SCAN_ROOT}" ]]; then
  SCAN_ROOT="${DIST_DIR}/scan-root"
  rm -rf -- "${SCAN_ROOT}"
  mkdir -p "${SCAN_ROOT}"
  shopt -s nullglob
  for archive in "${DIST_DIR}"/proof_*.tar.gz; do
    out_dir="${SCAN_ROOT}/$(basename "${archive}" .tar.gz)"
    mkdir -p "${out_dir}"
    tar -xzf "${archive}" -C "${out_dir}"
  done
  for archive in "${DIST_DIR}"/proof_*.zip; do
    out_dir="${SCAN_ROOT}/$(basename "${archive}" .zip)"
    mkdir -p "${out_dir}"
    unzip -q "${archive}" -d "${out_dir}"
  done
  shopt -u nullglob
fi

if [[ ! -d "${SCAN_ROOT}" ]]; then
  echo "release security scan root is missing: ${SCAN_ROOT}" >&2
  exit 1
fi
release_binaries=()
while IFS= read -r binary_path; do
  [[ -n "${binary_path}" ]] && release_binaries+=("${binary_path}")
done < <(find "${SCAN_ROOT}" -type f \( -name proof -o -name proof.exe \) | sort)
if [[ -z "${2:-}" && ${#release_binaries[@]} -ne 6 ]]; then
  echo "expected 6 extracted release binaries, found ${#release_binaries[@]}" >&2
  printf '%s\n' "${release_binaries[@]}" >&2
  exit 1
fi
if [[ ${#release_binaries[@]} -eq 0 ]]; then
  echo "release security scan found no proof binaries" >&2
  exit 1
fi

set +e
"${GRYPE_BIN}" db update >"${scan_dir}/grype-db-update.log" 2>&1
db_update_status=$?
set -e
stale_db=0
if [[ ${db_update_status} -ne 0 ]]; then
  cat "${scan_dir}/grype-db-update.log" >&2
  if ! grep -Eiq "${STALE_DB_PATTERN}" "${scan_dir}/grype-db-update.log"; then
    echo "grype database update failed without the specific stale-database freshness error" >&2
    exit "${db_update_status}"
  fi
  stale_db=1
  echo "grype database refresh reported the specific stale-database freshness error; scan result controls fallback" >&2
fi

run_govuln_fallback() {
  echo "grype scan failed only on the specific stale-database freshness error; using pinned govulncheck fallback" >&2
  : >"${scan_dir}/govulncheck.log"
  fallback_status=0
  for binary_path in "${release_binaries[@]}"; do
    echo "==> ${binary_path}" | tee -a "${scan_dir}/govulncheck.log"
    set +e
    if [[ -n "${GOVULNCHECK_BIN}" ]]; then
      "${GOVULNCHECK_BIN}" -mode=binary "${binary_path}" >>"${scan_dir}/govulncheck.log" 2>&1
    else
      go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -mode=binary "${binary_path}" >>"${scan_dir}/govulncheck.log" 2>&1
    fi
    check_status=$?
    set -e
    if [[ ${check_status} -ne 0 && ${fallback_status} -eq 0 ]]; then
      fallback_status=${check_status}
    fi
  done
  cat "${scan_dir}/govulncheck.log"
  return "${fallback_status}"
}

set +e
"${GRYPE_BIN}" "dir:${SCAN_ROOT}" --fail-on high >"${scan_dir}/grype-high.log" 2>&1
high_status=$?
set -e
if [[ ${high_status} -eq 0 ]]; then
  cat "${scan_dir}/grype-high.log"
  if [[ ${stale_db} -eq 1 ]]; then
    run_govuln_fallback
    exit $?
  fi
  exit 0
fi

cat "${scan_dir}/grype-high.log" >&2
if grep -Eiq "${STALE_DB_PATTERN}" "${scan_dir}/grype-high.log" && ! grep -Eiq 'CVE-[0-9]{4}-[0-9]+|[0-9]+[[:space:]]+vulnerabilit(y|ies)[[:space:]]+found' "${scan_dir}/grype-high.log"; then
  run_govuln_fallback
  exit $?
fi

echo "grype vulnerability scan failed; no stale-database fallback is permitted" >&2
exit "${high_status}"
