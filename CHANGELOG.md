# Changelog

All notable changes to this project are documented in this file.

The format is inspired by Keep a Changelog and this project follows semantic versioning.

## [Unreleased]

### Added

- Added an explicit offline final cross-product fixture import contract and staging command for exact Wrkr, Gait, and Axym producer bytes, manifests, portable schemas, and provenance.
- Added fail-closed importer coverage for producer identity, relationship, signature, schema, synthetic-artifact, identifier-only integrity, symlink, and atomic-staging cases.

### Changed

- Deprecated framework coverage compatibility aliases and evaluator documentation while preserving deterministic evidence-path behavior.
- Fixture import validation now supports unsigned Wrkr manifest/tagged-tree integrity and inline Ed25519 Gait/Axym artifacts, including released schema-version declaration variants.

### Security

- Final fixture checks reject missing Axym register/packet artifacts, synthetic substitutions, stale self-provenance, digest/signature mutations, and path traversal or symlink escapes.

## [0.6.2] - 2026-08-25

### Added

- Added a quarantined, fixture-only Action Contract lifecycle compatibility scenario with 16 pinned Gait lifecycle cases, including synthetic control extensions. The checked-in three-record cross-product projection is legacy test data, not released Axym producer evidence.
- Added a signed 16-artifact Gait approval/delegation gate corpus covering exact, expired, tightened-delegation, expansion, wrong-parent/origin, and revoked-ancestor cases.
- Added offline deterministic fixture generators and drift tests for source bytes, public keys, normalized records, provenance manifests, and orphan detection.

### Changed

- Fixture generators now verify source artifact and public-key digests before normalization or copying, and recompute every normalized projection during `--check`.

## [0.6.1] - 2026-08-19

### Added

- API contract documentation (`docs/api-contract.md`) and Python integration guide (`docs/python-integration.md`).
- Structured library errors (`core/errors`) with machine-readable kind/code metadata.
- Dedicated bundle domain package (`core/bundle`) with explicit pure and file-mutating signing APIs.
- New built-in framework definition files for AIUC-1 and OWASP Agentic Top 10.
- OSS hygiene docs: `CONTRIBUTING.md`, `SECURITY.md`.
- Digest-bound relationship references with optional schema and source-product identity fields.
- Validated namespaced relationship entity/edge kinds and stable typed validation reason codes.
- Opt-in strict structural verification for bundles, chains, and Gait packs/runpacks, with stable typed errors for
  ambiguous/duplicate paths, unlisted files, symlinks, and inconsistent chain metadata.
- Scoped portable custom record-type registries with versioned `record-types.json` manifests, SHA-256 schema
  membership, safe paths, conflict checks, and strict bundle auto-loading without process-global state leakage.
- Added the product-neutral Control, Containment, and Telemetry Correlation Profile with OpenTelemetry identifier
  validation, optional redaction/digest binding, deterministic canonicalization, and explicit identifier-only limits.

### Changed

- Go toolchain baseline raised to Go 1.26.6 for current standard-library security fixes.
- Normal release publication now reuses and verifies existing checksum signatures and rejects draft or prerelease targets.
- Public `proof` package now aliases bundle types from `core/bundle`.
- Added `ReadAndValidateRecord` to make validated read behavior explicit.
- `SignBundle` and `SignBundleCosign` kept as deprecated wrappers over explicit file-mutating variants.
- README examples updated to use explicit error handling and JSON-native artifact examples.
- Relationship normalization, sorting, and deduplication now include digest/schema/source identity while preserving
  legacy record hashes and unknown additive fields.
