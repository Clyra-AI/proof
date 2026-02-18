# Proof — Tamper-Evident Governance Primitive for AI Systems

## Overview

Use Proof when you need deterministic, offline-verifiable records for AI system actions.

Proof is not an agent runtime, not a policy engine, and not a dashboard. It is a Go library + CLI for canonicalization, signing, chain verification, schema validation, and artifact integrity checks.

Core capabilities:

- Deterministic record creation and hashing
- Hash-chain append and integrity verification
- Ed25519 signing and verification
- Cosign/Sigstore-backed signature verification support
- Offline CLI verification and inspection
- Versioned schemas for proof record types
- Gait pack/runpack compatibility verification

## When To Use Proof

- You need portable proof artifacts that can be verified offline.
- You need stable exit-code behavior for CI gates.
- You want a shared primitive that multiple products (including Gait) can reuse.
- You need deterministic canonicalization and repeatable digests.

## When Not To Use Proof

- You need policy authoring/enforcement logic (use your policy layer above Proof).
- You need orchestration of agent workflows or tools.
- You only need live telemetry/observability and no artifact verification contract.

## Try It (Offline, <60s)

```bash
# Install CLI
GO111MODULE=on go install github.com/Clyra-AI/proof/cmd/proof@latest

# Explore built-in surfaces
proof --version
proof types list
proof frameworks list
```

If you already have an artifact:

```bash
proof verify ./artifact.json
```

## Install

Current stable install path:

```bash
go install github.com/Clyra-AI/proof/cmd/proof@latest
```

Binary location:

- `$(go env GOBIN)/proof` when `GOBIN` is set
- otherwise `$(go env GOPATH)/bin/proof` (typically `~/go/bin/proof`)

Release artifact path (enabled on `v*.*.*` tags via `.github/workflows/release.yml`):

```bash
# GitHub CLI
gh release download vX.Y.Z -R Clyra-AI/proof -D /tmp/proof-release

# Direct download example
curl -fL -o /tmp/proof-release/proof.tar.gz \
  https://github.com/Clyra-AI/proof/releases/download/vX.Y.Z/proof_X.Y.Z_<os>_<arch>.tar.gz
curl -fL -o /tmp/proof-release/checksums.txt \
  https://github.com/Clyra-AI/proof/releases/download/vX.Y.Z/checksums.txt
```

Verify release artifacts:

```bash
cd /tmp/proof-release
sha256sum -c checksums.txt

# Optional (if release includes signature + cert and cosign is installed)
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

## What You Get

- **Deterministic canonicalization**: JSON/SQL/URL/text domains with stable digests.
- **Tamper evidence**: record hashes + chain head continuity checks.
- **Signature options**: Ed25519 and cosign verification support.
- **Schema contracts**: built-in proof record schemas and custom schema validation.
- **Cross-product compatibility**: Gait pack/runpack verification and migration-friendly compatibility packages.

## CLI Surface

```text
proof verify <path>                               Verify record, chain, bundle, gait pack/runpack/signed JSON
proof verify --signatures --public-key <key> <path>
proof verify --signatures --cosign-key <pubkey-path> <path>
proof verify --revocation-list <path> --revocation-key <pubkey> <path>
proof chain verify <path> [--from RFC3339] [--to RFC3339]
proof inspect <path> [--record <record_id>]
proof types list
proof types validate <schema-path>
proof frameworks list
proof frameworks show <id>
proof completion <shell>
```

Global flags:

- `--json`
- `--quiet`
- `--explain`

## Gait Compatibility

Proof can verify Gait artifacts directly:

```bash
proof verify ./gait-pack.zip
proof verify ./gait-runpack.zip
proof verify --signatures --public-key <hex-or-base64-ed25519-pub> ./gait-pack.zip
```

For Gait extraction/migration support, Proof exposes compatibility packages:

- `github.com/Clyra-AI/proof/signing`
- `github.com/Clyra-AI/proof/canon`
- `github.com/Clyra-AI/proof/schema`
- `github.com/Clyra-AI/proof/exitcode`

## Library Usage

Primary API:

```go
import "github.com/Clyra-AI/proof"
```

Quick example:

```go
record, _ := proof.NewRecord(proof.RecordOpts{
  Source:        "example",
  SourceProduct: "example",
  Type:          "tool_invocation",
  Event:         map[string]any{"tool": "postgres_query"},
})

chain := proof.NewChain("default")
_ = proof.AppendToChain(chain, record)

key, _ := proof.GenerateSigningKey()
_, _ = proof.Sign(&chain.Records[0], key)
_, _ = proof.VerifyChain(chain)
```

## Contract Commitments

- Deterministic canonicalization and hashing for supported domains
- Offline-first verification workflows
- Stable exit-code contract
- Versioned schema assets under `schemas/v1`

Exit codes:

- `0` success
- `1` internal/runtime failure
- `2` verification failure
- `3` policy/schema violation
- `4` approval required
- `5` regression drift detected
- `6` invalid input
- `7` dependency missing
- `8` unsafe operation blocked

## Developer Workflow

![Main](https://github.com/Clyra-AI/proof/actions/workflows/main.yml/badge.svg)
![CodeQL](https://github.com/Clyra-AI/proof/actions/workflows/codeql.yml/badge.svg)

```bash
make fmt
make lint
make test
make prepush-full
make test-uat-local
```

Key automation:

- Main CI: `.github/workflows/main.yml`
- PR CI: `.github/workflows/pr.yml`
- Nightly hardening/perf: `.github/workflows/nightly.yml`
- Release: `.github/workflows/release.yml`

## Repository Map

- CLI: `cmd/proof`
- Core packages: `core/*`
- Compatibility packages: `signing`, `canon`, `schema`, `exitcode`
- Schemas: `schemas/v1`
- Framework definitions: `frameworks/`
- Scripts: `scripts/`
- Performance budgets: `perf/`

## Notes

- Current Go baseline: `1.25.7`
- Implementation checklist: `IMPLEMENTATION_CHECK.md`
- Product PRD/source of scope: `product/proof.md`
