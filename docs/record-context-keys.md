# Record Context Keys

Proof records allow optional `metadata` for context enrichment. These are conventions for cross-product interoperability, not schema-required fields.

## Recommended keys

- `data_class` (string): `public` | `internal` | `confidential` | `pii` | `credentials`
- `endpoint_class` (string): `read` | `write` | `exec` | `admin`
- `risk_level` (string): `minimal` | `limited` | `high` | `unacceptable`
- `business_process` (string): workflow identifier or business process id
- `affected_entities` ([]string): entity identifiers affected by the action

## Compatibility

- Records with these keys are valid.
- Records without these keys are valid.
- Downstream products may use these keys for filtering and control matching, but Proof itself remains policy-neutral.
