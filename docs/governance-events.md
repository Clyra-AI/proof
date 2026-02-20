# Governance Events

Governance events are lightweight, unsigned JSON objects for real-time telemetry. They are intentionally simple to emit from any runtime (for example JSONL to stdout), then later promoted into signed proof records.

## Two-tier model

1. Emit `GovernanceEvent` JSON (`event_id`, `timestamp`, `event_type`, optional context/detail).
2. Validate against `schemas/v1/governance-event-v1.schema.json`.
3. Promote to a signed proof record with `proof.NewRecordFromEvent(...)`.

Events are not proof records. They are input artifacts for promotion.

## Event type vocabulary

- `tool_gate`
- `permission_check`
- `approval_request`
- `policy_evaluation`
- `guardrail_activation`
- `script_evaluation`

## Emission examples

```python
import json, datetime
print(json.dumps({"event_id":"evt-1","timestamp":datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00","Z"),"event_type":"tool_gate"}))
```

```ts
console.log(JSON.stringify({ event_id: "evt-1", timestamp: new Date().toISOString(), event_type: "tool_gate" }));
```

```go
_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"event_id": "evt-1", "timestamp": time.Now().UTC().Format(time.RFC3339), "event_type": "tool_gate"})
```

## Promotion mapping

`proof.NewRecordFromEvent` maps governance event types to proof record types:

- `tool_gate` -> `policy_enforcement`
- `permission_check` -> `permission_check`
- `approval_request` -> `guardrail_activation`
- `policy_evaluation` -> `policy_enforcement`
- `guardrail_activation` -> `guardrail_activation`
- `script_evaluation` -> `compiled_action`
