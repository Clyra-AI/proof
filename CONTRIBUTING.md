# Contributing

Thanks for contributing to `Clyra-AI/proof`.

## Ground Rules

- Keep changes inside Proof product boundaries (record/chain/sign/canon/schema/framework/verify).
- Preserve deterministic behavior and offline-first verification.
- Keep exit code semantics stable (`0-8` are reserved).
- Add or update tests with every behavior change.

## Development Setup

1. Install Go version from `go.mod`.
2. Clone the repo and install hooks:

```bash
git config core.hooksPath .githooks
```

## Local Validation

Run these before opening a PR:

```bash
make fmt
make lint
make test
make contract
```

For full gates (coverage + integration/e2e/acceptance/hardening/perf):

```bash
make prepush-full
```

## Pull Requests

1. Create a focused branch (`codex/*` or your own feature branch naming convention).
2. Keep commits small and reviewable.
3. Include:
   - behavior summary,
   - compatibility impact (API/schema/exit code),
   - tests added/updated.
4. Ensure CI is green before requesting merge.

## Compatibility Expectations

- Schema/API breaking changes require a major version bump.
- Keep `github.com/Clyra-AI/proof` and `core/*` exports backward compatible within the current major.
- Compatibility shims (`/signing`, `/schema`, `/canon`, `/exitcode`) should continue working in v1.

## Release Notes

- Update [CHANGELOG.md](CHANGELOG.md) for user-facing changes.
- Call out any migration guidance for deprecated APIs.
