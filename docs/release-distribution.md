# Release Distribution

This document describes release artifact verification and Homebrew publication for `proof`.

## Release Artifacts

Each release is expected to include:

- Cross-platform archives (`linux`, `darwin`, `windows`; `amd64`, `arm64`)
- `checksums.txt`
- `checksums.txt.sig` and `checksums.txt.pem` (cosign signature + certificate)
- SBOM and provenance artifacts (from CI release workflow)

## Verify Downloaded Artifacts

```bash
PROOF_VERSION="vX.Y.Z"
gh release download "${PROOF_VERSION}" -R Clyra-AI/proof -D /tmp/proof-release
cd /tmp/proof-release
sha256sum -c checksums.txt
```

If `cosign` is installed and checksum signature assets are present:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

## Homebrew Publication Path

GoReleaser is configured to publish a formula to `Clyra-AI/homebrew-tap`.

Required secret for release automation:

- `HOMEBREW_TAP_GITHUB_TOKEN` with permission to push to the tap repository.

Configured in `.goreleaser.yaml` under `brews`:

- formula name: `proof`
- tap repository: `Clyra-AI/homebrew-tap`
- formula directory: `Formula`

End-user install path:

```bash
brew tap Clyra-AI/homebrew-tap
brew install proof
```
