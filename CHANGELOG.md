# Changelog

All notable changes to this project are documented in this file.

The format is inspired by Keep a Changelog and this project follows semantic versioning.

## [Unreleased]

### Added

- Added an exact, fixture-only Action Contract lifecycle conformance scenario pinned to Wrkr v1.15.1, Gait v1.5.0, and Axym commit `7fa4244`, with strict digest-bound lineage, tamper, authority-quarantine, and evidence-set determinism coverage.
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
