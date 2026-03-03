#!/usr/bin/env bash
set -euo pipefail

REPO="Clyra-AI/proof"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION=""

usage() {
	cat <<'USAGE'
Usage: install.sh [--version <tag>] [--install-dir <path>]

Options:
  --version, -v      Install a specific release tag (for example: v1.2.3)
  --install-dir      Target directory for the proof binary (default: $HOME/.local/bin)
USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--version|-v)
			[[ $# -ge 2 ]] || { echo "error: --version requires a value" >&2; exit 2; }
			VERSION="$2"
			shift 2
			;;
		--install-dir)
			[[ $# -ge 2 ]] || { echo "error: --install-dir requires a value" >&2; exit 2; }
			INSTALL_DIR="$2"
			shift 2
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			echo "error: unknown argument: $1" >&2
			usage
			exit 2
			;;
	esac
done

uname_s="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "${uname_s}" in
	darwin) os="darwin" ;;
	linux) os="linux" ;;
	*)
		echo "error: unsupported OS: ${uname_s}" >&2
		exit 1
		;;
esac

uname_m="$(uname -m)"
case "${uname_m}" in
	x86_64|amd64) arch="amd64" ;;
	arm64|aarch64) arch="arm64" ;;
	*)
		echo "error: unsupported architecture: ${uname_m}" >&2
		exit 1
		;;
esac

if [[ -z "${VERSION}" ]]; then
	VERSION="$(
		curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
			| sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
			| head -n1
	)"
	if [[ -z "${VERSION}" ]]; then
		echo "error: unable to determine latest release tag" >&2
		exit 1
	fi
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

base_url="https://github.com/${REPO}/releases/download/${VERSION}"
checksums_path="${workdir}/checksums.txt"
sig_path="${workdir}/checksums.txt.sig"
cert_path="${workdir}/checksums.txt.pem"

curl -fsSL "${base_url}/checksums.txt" -o "${checksums_path}"

if curl -fsSL "${base_url}/checksums.txt.sig" -o "${sig_path}" && \
	curl -fsSL "${base_url}/checksums.txt.pem" -o "${cert_path}"; then
	if command -v cosign >/dev/null 2>&1; then
		cosign verify-blob \
			--certificate "${cert_path}" \
			--signature "${sig_path}" \
			"${checksums_path}" >/dev/null
		echo "verified: checksums.txt signature"
	else
		echo "note: cosign not found; skipped signature verification for checksums.txt"
	fi
fi

asset_name="$(
	awk '{print $2}' "${checksums_path}" \
		| grep -E "_${os}_${arch}\\.(tar\\.gz|zip)$" \
		| head -n1 || true
)"

if [[ -z "${asset_name}" ]]; then
	echo "error: no release asset found for ${os}/${arch} in ${VERSION}" >&2
	exit 1
fi

asset_path="${workdir}/${asset_name}"
curl -fsSL "${base_url}/${asset_name}" -o "${asset_path}"

expected_line="$(grep -E "[[:space:]]${asset_name}\$" "${checksums_path}" || true)"
if [[ -z "${expected_line}" ]]; then
	echo "error: missing checksum line for ${asset_name}" >&2
	exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
	( cd "${workdir}" && printf '%s\n' "${expected_line}" | sha256sum -c - )
elif command -v shasum >/dev/null 2>&1; then
	expected_sum="$(printf '%s\n' "${expected_line}" | awk '{print $1}')"
	actual_sum="$(shasum -a 256 "${asset_path}" | awk '{print $1}')"
	if [[ "${expected_sum}" != "${actual_sum}" ]]; then
		echo "error: checksum verification failed for ${asset_name}" >&2
		exit 1
	fi
else
	echo "error: neither sha256sum nor shasum is available for checksum verification" >&2
	exit 1
fi

if [[ "${asset_name}" == *.zip ]]; then
	unzip -q "${asset_path}" -d "${workdir}/extract"
else
	mkdir -p "${workdir}/extract"
	tar -xzf "${asset_path}" -C "${workdir}/extract"
fi

binary_path="$(
	find "${workdir}/extract" -type f -name proof -perm -u+x | head -n1 || true
)"
if [[ -z "${binary_path}" ]]; then
	echo "error: proof binary not found in extracted archive" >&2
	exit 1
fi

mkdir -p "${INSTALL_DIR}"
install -m 0755 "${binary_path}" "${INSTALL_DIR}/proof"

echo "installed: ${INSTALL_DIR}/proof (${VERSION}, ${os}/${arch})"
case ":${PATH}:" in
	*:"${INSTALL_DIR}":*) ;;
	*) echo "note: add ${INSTALL_DIR} to PATH to run 'proof' directly" ;;
esac
