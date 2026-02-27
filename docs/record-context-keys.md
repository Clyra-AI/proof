# Record Context Keys

Proof records allow optional `metadata` for context enrichment. These are conventions for cross-product interoperability, not schema-required fields.

## Relationship Envelope

For graph-ready linkage, prefer the first-class `relationship` object on records:

- `parent_ref` (object): parent node with `kind` and `id`
- `entity_refs` ([]object): related nodes with `kind` and `id`
- `policy_ref` (object): optional `policy_id`, `policy_version`, `policy_digest`, and `matched_rule_ids`
- `agent_chain` ([]object): ordered hops with `identity` and `role`
- `edges` ([]object): relation edges with `kind`, `from`, and `to`

Legacy `relations` is still accepted for backward compatibility.

## Determinism Rules

- Digest values are normalized to lowercase when they are valid SHA-256 references.
- `entity_refs`, `edges`, and string ID arrays are deduplicated and sorted deterministically.
- Record timestamps remain RFC3339 UTC in canonical hashing/signing paths.

## Recommended keys

- `data_class` (string): `public` | `internal` | `confidential` | `pii` | `credentials`
- `endpoint_class` (string): `read` | `write` | `exec` | `admin`
- `risk_level` (string): `minimal` | `limited` | `high` | `unacceptable`
- `discovery_method` (string): `static` | `webmcp` | `a2a` | `dynamic_mcp`
- `business_process` (string): workflow identifier or business process id
- `affected_entities` ([]string): entity identifiers affected by the action

## Compatibility

- Records with these keys are valid.
- Records without these keys are valid.
- Downstream products may use these keys for filtering and control matching, but Proof itself remains policy-neutral.
