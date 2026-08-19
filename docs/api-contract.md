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

## Portable Custom Type Registries

`core/schema.Registry` (also available as `proof.SchemaRegistry`) is the scoped custom record-type API. Register a
`RecordTypeDefinition` with its schema bytes, or use `RegisterCustomType(recordType, schemaID, schemaVersion,
schemaPath, data)`. Definitions are additive: built-in names cannot be replaced and conflicting definitions are
rejected. Schema paths are relative, canonical, and validated with the same strict path primitives used by bundle
verification. The versioned `record-types.json` manifest uses `version: "1"` and requires a SHA-256 digest for each
schema. `record-types.json` and every referenced schema must be members of a strict bundle manifest; strict verification
loads them into a call-local registry and does not mutate the legacy `RegisterCustomType` registry.

Portable custom schemas must declare `$id` equal to `schema_id` and
`x-proof-schema-version` equal to `schema_version`. Relative `$ref` values
must target another schema listed in the same strict bundle; file, HTTP, and
escaping references are rejected.

The legacy `RegisterCustomType`, `RegisterCustomTypeSchema`, and `ResetCustomTypes` functions remain supported for
source compatibility. New code that may verify concurrent or untrusted bundles should use scoped registries.

`EvaluateFrameworkCoverage` is retained for compatibility and is deprecated as a compliance interpretation boundary:
it reports deterministic evidence-path coverage only. Regulatory applicability, scope, gap scoring, and compliance
decisions belong to product-owned consumers and are not inferred by Proof.

## Control, Containment, and Telemetry Correlation Profile

`ControlContainmentTelemetryProfile` is a versioned, product-neutral structure whose refs cover event, action, contract,
run, session, policy, decision, proof, causal, containment, boundary, revocation, and acknowledgement relationships.
It validates OpenTelemetry identifier shapes, optional SHA-256 content/reference digests, redaction metadata, and the
`identifier_only`/`digest_bound` binding mode. Identifier-only references establish only that identifiers were recorded;
they do not establish enforcement, containment, telemetry authenticity, or product meaning. The normative public and
embedded schema is `schemas/v1/control-containment-telemetry-v1.schema.json`; use
`ValidateControlContainmentTelemetryProfile` and `CanonicalizeControlContainmentTelemetry` for deterministic API
validation and RFC 8785 JSON canonicalization.
The compatibility schema name `v1/control-containment-telemetry-profile-v1.schema.json` is kept in parity with the
canonical telemetry schema, including binding, identifier, and redaction constraints.

## Deprecation Policy

- Compatibility shims are not scheduled for removal in major version `1`.
- Any removal or incompatible change requires a major version bump and migration notes.
- Deprecated APIs remain behavior-compatible while their replacements are available.
