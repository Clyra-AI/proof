# Changelog

All notable changes to this project are documented in this file.

The format is inspired by Keep a Changelog and this project follows semantic versioning.

## [Unreleased]

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

### Changed

- Public `proof` package now aliases bundle types from `core/bundle`.
- Added `ReadAndValidateRecord` to make validated read behavior explicit.
- `SignBundle` and `SignBundleCosign` kept as deprecated wrappers over explicit file-mutating variants.
- README examples updated to use explicit error handling and JSON-native artifact examples.
- Relationship normalization, sorting, and deduplication now include digest/schema/source identity while preserving
  legacy record hashes and unknown additive fields.
