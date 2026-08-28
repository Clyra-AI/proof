# Final cross-product fixture import

Proof keeps released producer fixtures separate from compatibility smoke data.
The import contract is owned by the release coordinator and must be supplied
alongside the externally released bytes; Proof does not infer versions, tags,
commits, or digests from a local checkout.

## Contract

The JSON contract uses `format: "proof.cross_product_fixture_import/v1"` and
contains exactly three `sources`, one each for `wrkr`, `gait`, and `axym`. Every
source declares:

- exact release `version`, `commit`, and `tag` values in the contract (the
  producer manifest's commit/tag fields are optional because some released
  manifests carry only `source_commit` or no tree metadata);
- annotated tags may additionally record `tag_object` and `peeled_commit`
  object IDs so the imported bytes can be traced to an immutable tag object
  and its resolved commit;
- authoritative release bundles may pin detached `release_assets` by role
  (`bundle`, `checksums`, `checksums_signature`, `checksums_certificate`,
  `checksums_attestation`, and `provenance`) in addition to extracted files;
- an `integrity_mode`: `manifest_digest` for unsigned Wrkr exports,
  `tagged_tree` when the release tag is also verified by the caller, or
  `inline_ed25519` for signed Gait/Axym artifacts;
- a relative `manifest_path` and its `manifest_sha256`;
- a relative `public_key_path` and its `public_key_sha256`;
- one or more portable `schemas`, each with path, digest, schema ID, and schema
  version. Schema versions may be declared by `x-proof-schema-version` or by a
  `schema_version.const`/`version.const` property in the schema itself;
- one or more `artifacts`, each with raw-byte digest, schema identity, and
  `producer_artifact: true`. Inline Ed25519 signatures (including nested
  lifecycle records) are verified against the pinned public key when present;
  contracts can require them with `signature_required`, and detached signature
  bytes are digest-pinned with `signature_path`/`signature_sha256`.

Each artifact may pin full relationship references (`kind`, `id`, `digest`,
`schema_id`, `schema_version`, and `source_product`). Axym additionally must
list producer artifacts whose kinds include both `register` and `packet`.
Synthetic, fixture-only, or otherwise substituted Axym assessments are
rejected.

The current staging command is:

```bash
go run ./scripts/import_cross_product_fixture.go --update \
  --source /path/to/external/released-fixture-root \
  --contract /path/to/external/released-fixture-root/proof-import-contract.json \
  --dest scenarios/proof/action-contract-final-conformance
```

It verifies source manifests, public keys, schemas, artifact bytes, producer
identity, relationships, and integrity-binding claims before writing anything.
Authoritative Gait/Axym manifests must declare their release tag and peeled
commit, set `authoritative: true`, keep quarantine/development flags false, and
match the contract’s complete artifact and schema digest sets. Detached
release assets are copied and digest-pinned but are never trusted without
their checksum signature and release provenance validation.
The offline check is:

```bash
go run ./scripts/import_cross_product_fixture.go --check \
  --dest scenarios/proof/action-contract-final-conformance
```

The repository’s final conformance fixture is imported from immutable release
tag trees; its contract records the annotated tag object and peeled commit for
Wrkr `v1.15.1`, Gait `v1.7.0`, and Axym `v0.2.0` alongside the exact source
digests and cross-product relationship references.

No developer-absolute default path is accepted. The importer never guesses
tags or commit SHAs and never generates an Axym assessment; all final fixture
bytes must remain traceable to the release-owner contract and its pinned tag
trees.
