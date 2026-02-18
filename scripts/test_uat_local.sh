#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUTPUT_DIR="${REPO_ROOT}/.uat_local"
RELEASE_VERSION="${PROOF_UAT_RELEASE_VERSION:-}"

usage() {
  cat <<'EOF'
Run local end-to-end UAT for Proof.

Usage:
  test_uat_local.sh [--output-dir <path>] [--release-version <tag>]

Options:
  --output-dir <path>      UAT artifacts directory (default: .uat_local)
  --release-version <tag>  Optional GitHub release tag to validate release binary path
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ $# -ge 2 ]] || { echo "error: --output-dir requires a value" >&2; exit 2; }
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --release-version)
      [[ $# -ge 2 ]] || { echo "error: --release-version requires a value" >&2; exit 2; }
      RELEASE_VERSION="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "${OUTPUT_DIR}/logs"
SUMMARY_PATH="${OUTPUT_DIR}/summary.txt"
: > "${SUMMARY_PATH}"
rm -f "${OUTPUT_DIR}/generate_uat_artifacts.go"

log() {
  printf '%s\n' "$*" | tee -a "${SUMMARY_PATH}"
}

require_cmd() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    log "FAIL missing command: ${name}"
    exit 1
  fi
}

run_step() {
  local name="$1"
  shift
  local log_path="${OUTPUT_DIR}/logs/${name}.log"
  log "==> ${name}"
  if "$@" >"${log_path}" 2>&1; then
    log "PASS ${name}"
  else
    log "FAIL ${name} (see ${log_path})"
    tail -n 80 "${log_path}" || true
    exit 1
  fi
}

resolve_binary_path() {
  local candidate="$1"
  if [[ -x "${candidate}" ]]; then
    printf '%s' "${candidate}"
    return 0
  fi
  if [[ -x "${candidate}.exe" ]]; then
    printf '%s' "${candidate}.exe"
    return 0
  fi
  return 1
}

run_binary_contract_suite() {
  local label="$1"
  local bin_path="$2"
  local artifacts_dir="$3"

  if [[ ! -x "${bin_path}" ]]; then
    log "FAIL ${label}: binary not executable at ${bin_path}"
    exit 1
  fi

  local record_path="${artifacts_dir}/record.json"
  local chain_path="${artifacts_dir}/chain.json"
  local pub_hex
  local pub_b64
  pub_hex="$(<"${artifacts_dir}/public_key_hex.txt")"
  pub_b64="$(<"${artifacts_dir}/public_key_b64.txt")"

  run_step "${label}_version" "${bin_path}" --version
  run_step "${label}_help" "${bin_path}" --help
  run_step "${label}_types_list" "${bin_path}" types list --json
  run_step "${label}_frameworks_list" "${bin_path}" frameworks list --json
  run_step "${label}_inspect_record" "${bin_path}" inspect "${record_path}" --json
  run_step "${label}_verify_record_hex" "${bin_path}" verify --signatures --public-key "${pub_hex}" "${record_path}"
  run_step "${label}_verify_record_b64" "${bin_path}" verify --signatures --public-key "${pub_b64}" "${record_path}"
  run_step "${label}_verify_chain" "${bin_path}" verify --signatures --public-key "${pub_hex}" "${chain_path}"
  run_step "${label}_chain_verify" "${bin_path}" chain verify "${chain_path}"
}

generate_sample_artifacts() {
  local artifacts_dir="$1"
  mkdir -p "${artifacts_dir}"
  local generator
  generator="$(mktemp "${TMPDIR:-/tmp}/proof-uat-artifacts.XXXXXX.go")"
  cat > "${generator}" <<'GO'
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Clyra-AI/proof"
)

func main() {
	if len(os.Args) != 2 {
		_, _ = fmt.Fprintln(os.Stderr, "usage: go run <generator.go> <output-dir>")
		os.Exit(2)
	}
	outDir := filepath.Clean(os.Args[1])
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create output dir: %v\n", err)
		os.Exit(1)
	}

	key, err := proof.GenerateSigningKey()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
		os.Exit(1)
	}

	chain := proof.NewChain("uat-chain")
	for i := 0; i < 2; i++ {
		rec, err := proof.NewRecord(proof.RecordOpts{
			Timestamp:     time.Date(2026, 2, 18, 10, i, 0, 0, time.UTC),
			Source:        "uat",
			SourceProduct: "proof",
			Type:          "decision",
			Event:         map[string]any{"step": i, "action": "allow"},
		})
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "new record: %v\n", err)
			os.Exit(1)
		}
		if err := proof.AppendToChain(chain, rec); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "append to chain: %v\n", err)
			os.Exit(1)
		}
		if _, err := proof.Sign(&chain.Records[i], key); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "sign record: %v\n", err)
			os.Exit(1)
		}
	}

	recordPath := filepath.Join(outDir, "record.json")
	if err := proof.WriteRecord(recordPath, &chain.Records[0]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write record: %v\n", err)
		os.Exit(1)
	}

	chainPath := filepath.Join(outDir, "chain.json")
	chainRaw, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "marshal chain: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(chainPath, chainRaw, 0o600); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write chain: %v\n", err)
		os.Exit(1)
	}

	pubHexPath := filepath.Join(outDir, "public_key_hex.txt")
	if err := os.WriteFile(pubHexPath, []byte(hex.EncodeToString(key.Public)), 0o600); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write public key hex: %v\n", err)
		os.Exit(1)
	}
	pubB64Path := filepath.Join(outDir, "public_key_b64.txt")
	if err := os.WriteFile(pubB64Path, []byte(base64.StdEncoding.EncodeToString(key.Public)), 0o600); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write public key base64: %v\n", err)
		os.Exit(1)
	}
}
GO
  run_step "generate_sample_artifacts" bash -lc "cd \"${REPO_ROOT}\" && go run \"${generator}\" \"${artifacts_dir}\""
  rm -f "${generator}"
}

create_local_release_archive() {
  local source_bin="$1"
  local release_dir="$2"
  local stage_dir="${release_dir}/stage"
  mkdir -p "${stage_dir}"

  local staged_name="proof"
  if [[ "${source_bin}" == *.exe ]]; then
    staged_name="proof.exe"
  fi

  cp "${source_bin}" "${stage_dir}/${staged_name}"

  local archive="${release_dir}/proof-local.tar.gz"
  tar -czf "${archive}" -C "${stage_dir}" "${staged_name}"
  printf '%s' "${archive}"
}

extract_release_binary() {
  local release_dir="$1"
  local extraction_dir="$2"
  mkdir -p "${extraction_dir}"

  local archive
  archive="$(find "${release_dir}" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) | head -n1 || true)"
  if [[ -z "${archive}" ]]; then
    return 1
  fi

  case "${archive}" in
    *.tar.gz) tar -xzf "${archive}" -C "${extraction_dir}" ;;
    *.zip) unzip -o "${archive}" -d "${extraction_dir}" >/dev/null ;;
    *) return 1 ;;
  esac

  local candidate
  candidate="$(find "${extraction_dir}" -type f \( -name 'proof' -o -name 'proof.exe' \) | head -n1 || true)"
  if [[ -z "${candidate}" ]]; then
    return 1
  fi
  chmod +x "${candidate}" || true
  printf '%s' "${candidate}"
  return 0
}

require_cmd go
require_cmd python3

log "UAT output dir: ${OUTPUT_DIR}"

run_step "quality_prepush_full" make -C "${REPO_ROOT}" prepush-full
run_step "security_gosec" bash -lc "cd \"${REPO_ROOT}\" && if command -v gosec >/dev/null 2>&1; then gosec ./...; else go run github.com/securego/gosec/v2/cmd/gosec@latest ./...; fi"
run_step "security_govulncheck" bash -lc "cd \"${REPO_ROOT}\" && if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; else go run golang.org/x/vuln/cmd/govulncheck@latest ./...; fi"

ARTIFACTS_DIR="${OUTPUT_DIR}/artifacts"
generate_sample_artifacts "${ARTIFACTS_DIR}"

SOURCE_BIN="${OUTPUT_DIR}/source/proof"
mkdir -p "$(dirname "${SOURCE_BIN}")"
run_step "build_source_binary" bash -lc "cd \"${REPO_ROOT}\" && go build -o \"${SOURCE_BIN}\" ./cmd/proof"
SOURCE_BIN_RESOLVED="$(resolve_binary_path "${SOURCE_BIN}" || true)"
if [[ -z "${SOURCE_BIN_RESOLVED}" ]]; then
  log "FAIL source_binary_resolve (${SOURCE_BIN} or ${SOURCE_BIN}.exe not found)"
  exit 1
fi
run_binary_contract_suite "source" "${SOURCE_BIN_RESOLVED}" "${ARTIFACTS_DIR}"

GO_INSTALL_DIR="${OUTPUT_DIR}/go_install/bin"
mkdir -p "${GO_INSTALL_DIR}"
run_step "install_go_binary" bash -lc "cd \"${REPO_ROOT}\" && GOBIN=\"${GO_INSTALL_DIR}\" go install ./cmd/proof"
GO_INSTALL_BIN_RESOLVED="$(resolve_binary_path "${GO_INSTALL_DIR}/proof" || true)"
if [[ -z "${GO_INSTALL_BIN_RESOLVED}" ]]; then
  log "FAIL go_install_binary_resolve (${GO_INSTALL_DIR}/proof or ${GO_INSTALL_DIR}/proof.exe not found)"
  exit 1
fi
run_binary_contract_suite "go_install" "${GO_INSTALL_BIN_RESOLVED}" "${ARTIFACTS_DIR}"

log "==> local_release_archive"
LOCAL_RELEASE_DIR="${OUTPUT_DIR}/local_release"
mkdir -p "${LOCAL_RELEASE_DIR}"
LOCAL_RELEASE_ARCHIVE="$(create_local_release_archive "${SOURCE_BIN_RESOLVED}" "${LOCAL_RELEASE_DIR}" 2>"${OUTPUT_DIR}/logs/local_release_archive.log" || true)"
if [[ -z "${LOCAL_RELEASE_ARCHIVE}" ]]; then
  log "FAIL local_release_archive (see ${OUTPUT_DIR}/logs/local_release_archive.log)"
  tail -n 80 "${OUTPUT_DIR}/logs/local_release_archive.log" || true
  exit 1
fi
log "PASS local_release_archive"

LOCAL_RELEASE_EXTRACT_DIR="${OUTPUT_DIR}/local_release_extract"
LOCAL_RELEASE_BIN="$(extract_release_binary "${LOCAL_RELEASE_DIR}" "${LOCAL_RELEASE_EXTRACT_DIR}" || true)"
if [[ -z "${LOCAL_RELEASE_BIN}" ]]; then
  log "FAIL local_release_extract (no proof binary found in local archive)"
  exit 1
fi
run_binary_contract_suite "local_release" "${LOCAL_RELEASE_BIN}" "${ARTIFACTS_DIR}"

if [[ -n "${RELEASE_VERSION}" ]]; then
  require_cmd gh
  RELEASE_DIR="${OUTPUT_DIR}/release"
  mkdir -p "${RELEASE_DIR}"
  run_step "release_download" gh release download "${RELEASE_VERSION}" -R Clyra-AI/proof -D "${RELEASE_DIR}"

  RELEASE_EXTRACT_DIR="${OUTPUT_DIR}/release_extract"
  RELEASE_BIN="$(extract_release_binary "${RELEASE_DIR}" "${RELEASE_EXTRACT_DIR}" || true)"
  if [[ -z "${RELEASE_BIN}" ]]; then
    log "FAIL release_binary_extract (no proof binary found in downloaded release assets)"
    exit 1
  fi
  run_binary_contract_suite "release" "${RELEASE_BIN}" "${ARTIFACTS_DIR}"
else
  log "SKIP release path checks (set --release-version to enable)"
fi

log "UAT COMPLETE: PASS"
