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

## Relationship Reference Contract

`RelationshipRef` keeps `kind` and `id` as its required compatibility core. The optional `digest`, `schema_id`,
`schema_version`, and `source_product` fields bind the reference to immutable content and its producing schema without
changing `record_version`. A digest is a 64-character SHA-256 value with an optional `sha256:` prefix. Constructors
normalize valid digest hex and the prefix to lowercase; read and verification paths do not rewrite already-hashed
artifacts.

Built-in relationship kinds remain stable. Extension kinds must be lowercase dot-separated names, for example
`vendor.model-card` for an entity or `vendor.describes` for an edge. Invalid names and digests return structured
validation errors with stable `record.relationship_ref.*` or `record.relationship_edge.*` codes. Unknown additive
fields remain preserved, hash-covered, and signature-covered.

## Strict Structural Verification

Strict verification is opt-in so existing verification calls remain source- and behavior-compatible. Set
`BundleVerifyOpts.Strict`, use `VerifyChainWithOptions` with `ChainVerifyOpts{Strict: true}`, or set
`core/gait.VerifyOpts.Strict` for Gait packs and runpacks. Strict mode rejects non-canonical and duplicate normalized
paths, unlisted files, symbolic-link ambiguity, and inconsistent chain counts or head hashes. These failures use stable
`structure.*` and `chain.*` structured error codes.

## Deprecation Policy

- Compatibility shims are not scheduled for removal in major version `1`.
- Any removal or incompatible change requires a major version bump and migration notes.
- Deprecated APIs remain behavior-compatible while their replacements are available.
