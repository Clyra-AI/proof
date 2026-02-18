# Proof

The universal record format for AI governance.

[![Main](https://github.com/Clyra-AI/proof/actions/workflows/main.yml/badge.svg)](https://github.com/Clyra-AI/proof/actions/workflows/main.yml)
[![CodeQL](https://github.com/Clyra-AI/proof/actions/workflows/codeql.yml/badge.svg)](https://github.com/Clyra-AI/proof/actions/workflows/codeql.yml)
[![Determinism](https://github.com/Clyra-AI/proof/actions/workflows/determinism.yml/badge.svg)](https://github.com/Clyra-AI/proof/actions/workflows/determinism.yml)

---

## Why Proof Exists

AI agents are moving from pilot to production. Regulators are catching up — the EU AI Act, SOC 2 AI controls, state-level AI laws — and every one of them requires evidence: what did the agent do, what controls were in place, can you prove it?

Today that evidence is scattered across CloudWatch JSON, LangSmith exports, CSV dumps, screenshots, and PDF summaries. Every tool invents its own format. Auditors get a pile of incompatible files. Verification is manual. Tamper evidence is nonexistent.

Proof solves this by defining one record format that any tool can produce and any auditor can verify. One binary, one schema, one chain. Offline, signed, deterministic.

The primitive is separate from the products built on top of it. Discovery tools, compliance engines, and policy enforcers all import Proof as their shared record and signing layer. Third parties — agent frameworks, MCP servers, CI pipelines — can adopt the format independently by importing the Go module or implementing the JSON Schema spec. The format earns standard status through adoption, not announcement.

## What Proof Is

An open-source Go module and verification CLI. Four operations:

- **Create** — Structured, schema-validated proof records with deterministic hashing
- **Chain** — Append records to tamper-evident hash chains (same mechanism as certificate transparency logs)
- **Sign** — Ed25519 or cosign (Sigstore) signatures on records, chains, and bundles
- **Verify** — Offline verification of any proof artifact with a single binary

## What Proof Is Not

- Not a policy engine. Proof does not make allow/block decisions.
- Not a scanner or collector. Proof does not discover tools or capture agent activity.
- Not a compliance engine. Proof does not evaluate whether evidence satisfies controls — it defines what records look like and what controls require.
- Not AI-powered. Zero LLMs, zero ML, zero probabilistic components. Deterministic canonicalization, cryptographic hashing, schema validation. Same inputs, same outputs, always.

## Quick Start

```bash
go install github.com/Clyra-AI/proof/cmd/proof@latest

proof types list          # 15 built-in record types
proof frameworks list     # 8 compliance framework definitions
proof verify ./artifact   # Verify any proof artifact offline
```

### Library Usage (4 lines)

```go
import "github.com/Clyra-AI/proof"

record, _ := proof.NewRecord(proof.RecordOpts{
    Source:        "my-mcp-server",
    SourceProduct: "my-product",
    Type:          "tool_invocation",
    Event:         map[string]any{"tool": "postgres_query", "action": "SELECT"},
})

chain := proof.NewChain("default")
_ = proof.AppendToChain(chain, record)

key, _ := proof.GenerateSigningKey()
_, _ = proof.Sign(&chain.Records[0], key)
```

Every tool invocation now produces a signed, chainable, verifiable proof record. No configuration files, no account, no network access.

### Custom Record Types

```go
_ = proof.RegisterCustomTypeSchema("vendor.custom_event", "./custom.schema.json")
```

Custom types validate against the base proof record schema plus your type-specific schema. They chain and sign identically to built-in types.

### Bundle Signing and Verification

```go
manifest, _ := proof.SignBundle("./bundle", key)

result, _ := proof.VerifyBundle("./bundle", proof.BundleVerifyOpts{
    VerifySignatures: true,
    PublicKey:        proof.PublicKey{Public: key.Public},
})
```

## Record Format

The atomic unit is the proof record — a structured, signed artifact that captures what happened, what controls were in place, and the cryptographic integrity needed to prove it wasn't tampered with.

```yaml
record_id: "prf-2026-09-15T10:30:00Z-a7f3b2c1"
record_version: "1.0"
timestamp: "2026-09-15T10:30:00Z"
source: "my-mcp-server"
source_product: "my-product"
record_type: "tool_invocation"

event:
  tool: "postgres_query"
  action: "SELECT"
  parameters:
    query_hash: "sha256:abc123..."    # digest, not the query itself
    target: "payments.transactions"

controls:
  permissions_enforced: true
  approved_scope: "read-only on payments.*"
  within_scope: true

integrity:
  record_hash: "sha256:def456..."
  previous_record_hash: "sha256:ghi789..."   # chain link
  signing_key_id: "a1b2c3..."
  signature: "base64:..."
```

Records are immutable, deterministic, and JSON-native — readable by any language, any tool, any text editor.

## Built-in Record Types

15 types covering the full AI governance surface, each with its own JSON Schema:

| Type | Description |
|---|---|
| `tool_invocation` | An AI agent invoked a tool |
| `decision` | An AI agent made a decision |
| `guardrail_activation` | A guardrail triggered or passed |
| `permission_check` | A permission was enforced |
| `human_oversight` | A human reviewed or approved |
| `policy_enforcement` | A policy rule was evaluated |
| `scan_finding` | An AI tool or risk was discovered |
| `risk_assessment` | A risk was identified and scored |
| `deployment` | An AI system was deployed or changed |
| `model_change` | A model version or config changed |
| `test_result` | A test or evaluation was run |
| `incident` | An AI-related incident occurred |
| `data_pipeline_run` | A data pipeline executed |
| `replay_certification` | A replay was run and certified |
| `approval` | An approval or delegation was issued |

Record types are extensible. Define a custom type by providing a JSON Schema that extends the base record schema.

## Hash Chains

Records are chained — each record's hash includes the previous record's hash, creating a tamper-evident sequence. Modify or delete a record and the chain breaks. `proof chain verify` identifies the exact break point.

```
Record 1 → hash(record_1)                      →┐
Record 2 → hash(record_2 + prev_hash)           →┐
Record 3 → hash(record_3 + prev_hash)           →┐
...
$ proof chain verify ./records/
Chain intact. 1,427 records. No gaps.
```

This is not blockchain. It is the same mechanism used in certificate transparency logs. Simple, proven, auditable.

## Signing

Two backends, one verification surface:

- **Ed25519** (default) — Fast, offline, no external dependencies
- **Cosign / Sigstore** — Supply chain ecosystem alignment, OIDC keyless signing

Both backends produce records that pass chain verification. The signing backend is transparent to the verifier. Key management supports customer-managed keys, ephemeral keys for development, and key revocation with signed revocation lists.

## Canonicalization

Deterministic serialization is essential for hash stability. Proof implements canonicalization across four domains:

| Domain | Method |
|---|---|
| JSON | RFC 8785 (JCS) — deterministic field ordering, number normalization |
| SQL | UTF-8, trim, collapse whitespace, lowercase keywords, strip trailing semicolons |
| URL | Lowercase scheme + host, normalize path, sort query params |
| Text/Prompt | UTF-8, trim, collapse whitespace, normalize line endings |

All digests carry `algo_id` (sha256 or hmac-sha256) and optional `salt_id` metadata.

## Compliance Framework Definitions

YAML files that declare what regulatory controls require — which record types, what fields, what frequency. Zero evaluation logic. Configuration data consumed by downstream compliance tools.

8 frameworks ship with v1:

| Framework | Scope |
|---|---|
| EU AI Act | Articles 9, 12, 13, 14, 15, 26 |
| SOC 2 | CC6, CC7, CC8 (AI-specific sub-controls) |
| SOX | Change management, SoD, access controls |
| PCI-DSS | Requirement 10 (logging and monitoring) |
| Texas TRAIGA | State AI regulation |
| Colorado AI Act | State AI regulation |
| ISO 42001 | AI Management System |
| NIST AI 600-1 | Agent security guidance |

Adding a new framework is a YAML file and a PR — no code changes required.

## CLI Reference

```
proof verify <path>                    Verify record, chain, bundle, or Gait artifact
  --chain                              Verify chain integrity
  --signatures                         Verify signatures
  --public-key <hex|base64>            Ed25519 public key
  --cosign-key <path>                  Cosign public key
  --cosign-cert <path>                 Cosign certificate
  --cosign-cert-identity <id>          Expected certificate identity
  --cosign-cert-issuer <issuer>        Expected OIDC issuer
  --custom-type-schema <type>=<path>   Custom type schema (repeatable)
  --revocation-list <path>             Signed key revocation list
  --revocation-key <hex>               Revocation list signer public key

proof inspect <path>                   Human-readable artifact display
  --record <record_id>                 Inspect specific record by ID

proof chain verify <path>              Verify chain integrity
  --from <RFC3339>                     Start of time range
  --to <RFC3339>                       End of time range

proof types list                       List all registered record types
proof types validate <schema-path>     Validate a custom record type schema

proof frameworks list                  List available compliance frameworks
proof frameworks show <id>             Display framework controls

proof completion <shell>               Shell completion generation
```

Global flags: `--json`, `--quiet`, `--explain`

## Exit Codes

Stable contract. CI pipelines can rely on consistent semantics across all tools that adopt this vocabulary.

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Internal / runtime failure |
| 2 | Verification failure |
| 3 | Policy / schema violation |
| 4 | Approval required |
| 5 | Regression drift detected |
| 6 | Invalid input |
| 7 | Dependency missing |
| 8 | Unsafe operation blocked |

## Gait Compatibility

Proof verifies Gait artifacts directly — packs, runpacks, and signed JSON — without any Gait dependency:

```bash
proof verify ./gait-pack.zip
proof verify ./gait-runpack.zip
proof verify --signatures --public-key <key> ./gait-pack.zip
```

The signing and canonicalization code in Proof was extracted from Gait's production codebase. `KeyID()`, `Signature{}`, and JCS digest functions produce byte-identical output, so artifacts signed by Gait before the extraction verify correctly with Proof.

Compatibility packages for migration:

- `github.com/Clyra-AI/proof/signing` — Ed25519 key management with dev/prod modes
- `github.com/Clyra-AI/proof/canon` — `CanonicalizeJSON()` and `DigestJCS()` aliases
- `github.com/Clyra-AI/proof/schema` — `ValidateJSON()` and `ValidateJSONL()` helpers
- `github.com/Clyra-AI/proof/exitcode` — Exit code constants with legacy aliases

## Design Principles

1. **The spec is the product.** JSON Schema files are the normative specification. The Go module is the reference implementation. If they disagree, the spec wins.
2. **Zero opinions.** Proof does not know what compliance means. It creates, chains, signs, and verifies. What records mean is someone else's problem.
3. **Boring cryptography.** Ed25519 (RFC 8032), SHA-256, RFC 8785. No novel constructions, no experimental algorithms.
4. **Library-first, CLI-second.** The Go module is the primary artifact. The CLI is a thin wrapper. Every command maps to a module function.
5. **Extracted, not greenfield.** Built by extracting production-proven code from Gait, not by writing from scratch. Same pattern as Sigstore (extracted from cosign), OCI (extracted from Docker), HCL (extracted from Terraform).
6. **Offline-first.** All core operations — create, chain, sign, verify — work without network access. Air-gapped environments are first-class.

## Repository Layout

```
cmd/proof/           CLI (Cobra-based)
core/
  record/            Record creation, validation, hashing
  chain/             Hash chain append and verification
  signing/           Ed25519 + cosign signing
  canon/             Canonicalization (JSON, SQL, URL, text)
  schema/            JSON Schema validation + type registry
  framework/         YAML framework definition loading
  gait/              Gait pack/runpack compatibility verification
  exitcode/          Exit code constants
signing/             Compatibility package (Gait migration)
canon/               Compatibility package (Gait migration)
schema/              Compatibility package (Gait migration)
exitcode/            Compatibility package (Gait migration)
schemas/v1/          JSON Schema spec files (language-agnostic contract)
  types/             15 record type schemas
frameworks/          8 compliance framework YAML definitions
testdata/            Golden vectors and test fixtures
scripts/             Test and validation scripts
perf/                Performance budgets
```

## Development

```bash
make fmt             # Format
make lint            # Vet + golangci-lint
make test            # Unit tests
make prepush-full    # Full gate: lint + test + coverage + contract + integration + e2e + acceptance
make test-uat-local  # Local UAT across install paths
```

CI pipelines: main, PR, determinism (cross-platform), CodeQL, nightly (hardening + chaos + performance + soak), release (GoReleaser + checksums + SBOM + cosign + SLSA provenance).

## Install

```bash
# From source
go install github.com/Clyra-AI/proof/cmd/proof@latest

# From release
gh release download vX.Y.Z -R Clyra-AI/proof -D /tmp/proof-release
cd /tmp/proof-release && sha256sum -c checksums.txt
```

Go module:

```bash
go get github.com/Clyra-AI/proof
```

## License

See [LICENSE](LICENSE).
