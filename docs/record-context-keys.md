# Record Context Keys

Proof records allow optional `metadata` for context enrichment. These are conventions for cross-product interoperability, not schema-required fields.

## Relation envelope

For graph-ready linkage, prefer the first-class `relations` object on records:

- `parent_record_id` (string): immediate upstream proof record
- `related_record_ids` ([]string): additional linked proof records
- `related_entity_ids` ([]string): linked entities (agent/tool/resource IDs)
- `policy_ref.policy_id` (string): policy identifier
- `policy_ref.policy_version` (string): policy version label
- `policy_ref.policy_digest` (string): `sha256:<hex>` or legacy bare `<hex>` policy content digest
- `agent_lineage` ([]object): delegation path with `agent_id`, optional `delegated_by`, optional `delegation_record_id`

This keeps relationship semantics explicit while preserving policy neutrality.

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
