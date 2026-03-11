# API Contract

This document defines the import-path stability contract for `github.com/Clyra-AI/proof`.
Use this contract before refactors to avoid accidental breakage for downstream users.

## Stability Matrix

| Import Path | Scope | Status | Compatibility Commitment |
|---|---|---|---|
| `github.com/Clyra-AI/proof` | Primary public library API | Supported (stable) | Backward compatible within major version. Preferred path for all new integrations. |
| `github.com/Clyra-AI/proof/core/record` | Low-level record primitives | Supported (stable) | Backward compatible within major version for exported symbols. |
| `github.com/Clyra-AI/proof/core/chain` | Low-level chain primitives | Supported (stable) | Backward compatible within major version for exported symbols. |
| `github.com/Clyra-AI/proof/core/signing` | Low-level signing primitives | Supported (stable) | Backward compatible within major version for exported symbols. |
| `github.com/Clyra-AI/proof/core/canon` | Low-level canonicalization primitives | Supported (stable) | Backward compatible within major version for exported symbols. |
| `github.com/Clyra-AI/proof/core/schema` | Low-level schema/type primitives | Supported (stable) | Backward compatible within major version for exported symbols. |
| `github.com/Clyra-AI/proof/core/framework` | Framework definitions and evidence coverage evaluation | Supported (stable) | Backward compatible within major version for exported symbols. |
| `github.com/Clyra-AI/proof/core/bundle` | Bundle manifest/sign/verify primitives | Supported (stable) | Backward compatible within major version for exported symbols. |
| `github.com/Clyra-AI/proof/core/exitcode` | Exit-code constants | Supported (stable) | Exit code values `0-8` are contractually stable. |
| `github.com/Clyra-AI/proof/signing` | Compatibility shim | Supported (compatibility) | Kept for migration compatibility. New code should prefer `github.com/Clyra-AI/proof` or `.../core/signing`. |
| `github.com/Clyra-AI/proof/schema` | Compatibility shim | Supported (compatibility) | Kept for migration compatibility. New code should prefer `github.com/Clyra-AI/proof` or `.../core/schema`. |
| `github.com/Clyra-AI/proof/canon` | Compatibility shim | Supported (compatibility) | Kept for migration compatibility. New code should prefer `github.com/Clyra-AI/proof` or `.../core/canon`. |
| `github.com/Clyra-AI/proof/exitcode` | Compatibility shim | Supported (compatibility) | Kept for migration compatibility. New code should prefer `.../core/exitcode`. |

## Deprecation Policy

- Compatibility shims are not scheduled for removal in major version `1`.
- Any removal or incompatible change requires a major version bump and migration notes.
- Deprecated APIs remain behavior-compatible while their replacements are available.
