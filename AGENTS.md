# AGENTS.md

## Purpose

This repository builds `Clyra-AI/proof`: the shared proof primitive for Clyra AI products.

Use this file as the execution contract for all engineering work in this repo.

## Product Boundary (Proof Only)

Proof is a primitive, not an application policy engine.

In scope:
- Create deterministic proof records
- Append and verify tamper-evident hash chains
- Sign and verify records/chains/bundles (Ed25519, optional Sigstore/cosign parity)
- Canonicalize inputs deterministically (RFC 8785 JSON + domain helpers)
- Validate against schemas
- Load/list framework definition files
- Provide verification/inspection CLI

Out of scope:
- Compliance mapping logic or gap scoring (Axym domain)
- Runtime policy enforcement (Gait domain)
- Discovery/scanning logic (Wrkr domain)
- SaaS/cloud dependency for core operations

## Core Invariants

These are non-negotiable:

1. Determinism
- Same inputs must produce bit-identical outputs across supported platforms.
- Record IDs, hashes, signatures, and canonicalized bytes must be stable.

2. Offline-first
- Core library and CLI verification paths must run without network access.
- No telemetry or call-home behavior in core operations.

3. Cryptographic conservatism
- Ed25519 for signatures.
- SHA-256 for digests.
- RFC 8785 (JCS) for canonical JSON in signed/hashed payloads.

4. Zero compliance opinions
- Proof defines structure and integrity only, not control satisfaction.

5. Backward compatibility
- Preserve compatibility expectations for shared artifact semantics and key ID handling.

## Exit Code Contract (Stable API)

All CLI behavior must preserve this shared contract:

- `0`: success
- `1`: internal/runtime error
- `2`: verification failure
- `3`: policy/schema violation
- `4`: approval required
- `5`: regression drift detected
- `6`: invalid input
- `7`: dependency missing
- `8`: unsafe operation blocked

Do not repurpose codes `0-8`. Any additional code must be `>8`.

## CLI Requirements

- CLI is library-first and thin.
- Support machine-readable output via `--json`.
- Support human diagnostics via `--explain` where applicable.
- Keep commands verification/inspection centric for Proof.

## Schemas and Contracts

- Treat schemas as normative contract.
- Keep schema changes backward compatible within major version.
- Breaking schema/API changes require major version bump.
- Maintain deterministic fixture coverage:
  - valid/invalid schema fixtures
  - contract tests for exit codes and JSON shape
  - golden files for stable outputs

## Toolchain Standards

### Go
- Pin version in `go.mod`.
- Single module repo.
- Entry points in `cmd/<binary>/`.
- Shared library code in `core/`.
- Non-exported code in `internal/`.
- Build command: `go build ./cmd/<binary>`.

### Lint/Format/Security
- `gofmt -w .`
- `go vet ./...`
- `golangci-lint run ./...`
- `gosec ./...`
- `govulncheck -mode=binary ./<binary>`

### Pre-commit / Pre-push
- Use pre-commit hooks for formatting and secret detection.
- Pre-push must run fast lint + test gates.

## Testing Strategy (Tiered)

Apply Clyra tier model with Proof focus:

- Tier 1 Unit: record/chain/sign/canon/schema units
- Tier 2 Integration: cross-package deterministic behavior
- Tier 3 E2E: CLI invocation, JSON output, exit code checks
- Tier 4 Acceptance: blessed workflows (`verify`, `chain verify`, bundle checks)
- Tier 5+ nightly/release: hardening, chaos, performance, contract stability

Mandatory before merge:
- Unit + integration + e2e green
- Determinism/contract tests green
- No exit-code regressions

## Coverage Gates

Use Clyra baseline gates:
- Core Go packages: `>=85%`
- All Go packages: `>=75%` per package

Coverage is a gate, not a dashboard metric.

## Performance Budgets

- Benchmarks run with `GOMAXPROCS=1`, multiple samples, median comparison.
- Maintain baseline files and block regressions above configured factor.
- Track command latency budgets (p50/p95/p99), resource, and context budgets.

## Release Integrity

Release pipeline must include:
- Cross-platform builds (linux/darwin/windows; amd64/arm64)
- Checksums
- SBOM (SPDX)
- Vulnerability scan
- cosign signing
- provenance attestation
- checksum/signature verification steps

## Security and Data Handling

- Never store raw secrets in records.
- Prefer hashes/digests over sensitive payload retention.
- Ensure keys are never logged.
- Keep CLI read-only for verification paths.

## Repo Hygiene

Do not commit generated artifacts:
- build output directories
- coverage outputs
- built binaries
- transient performance reports

Local planning docs under `product/` may be ignored in this repo and are used as implementation reference inputs.

## Working Rules for Agents

Before coding:
- Confirm requested change is inside Proof boundary.
- Identify affected contracts (schema, API, CLI, exit codes, determinism).

While coding:
- Prefer minimal, targeted changes.
- Keep behavior deterministic and testable.
- Add/adjust tests with each behavior change.

Before finishing:
- Run format/lint/tests.
- Verify contract and deterministic outputs where relevant.
- Document any deliberate contract change and required migration path.

## Decision Priority

When rules conflict, apply this order:
1. Determinism and integrity invariants
2. Exit-code/schema/API compatibility
3. Security and offline guarantees
4. Performance budgets
5. Ergonomics and implementation convenience
