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

### Changed

- Public `proof` package now aliases bundle types from `core/bundle`.
- Added `ReadAndValidateRecord` to make validated read behavior explicit.
- `SignBundle` and `SignBundleCosign` kept as deprecated wrappers over explicit file-mutating variants.
- README examples updated to use explicit error handling and JSON-native artifact examples.
