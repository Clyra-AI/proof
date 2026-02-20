package proof

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Clyra-AI/proof/core/schema"
)

// GovernanceEvent is a lightweight, unsigned governance signal that can be
// promoted into a signed proof record.
type GovernanceEvent struct {
	EventID   string         `json:"event_id"`
	Timestamp string         `json:"timestamp"`
	EventType string         `json:"event_type"`
	AgentID   string         `json:"agent_id,omitempty"`
	ToolName  string         `json:"tool_name,omitempty"`
	Verdict   string         `json:"verdict,omitempty"`
	Context   map[string]any `json:"context,omitempty"`
	Detail    map[string]any `json:"detail,omitempty"`
}

// ValidateGovernanceEvent validates a governance event against the embedded
// governance event schema.
func ValidateGovernanceEvent(event GovernanceEvent) error {
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err := schema.ValidateAgainstSchema(raw, "v1/governance-event-v1.schema.json"); err != nil {
		return fmt.Errorf("governance event validation failed: %w", err)
	}
	if _, err := parseGovernanceTimestamp(event.Timestamp); err != nil {
		return fmt.Errorf("governance event validation failed: %w", err)
	}
	return nil
}

// NewRecordFromEvent creates a proof.Record from a validated governance event.
// The caller is responsible for signing and chain-appending the returned record.
func NewRecordFromEvent(event GovernanceEvent, source string) (*Record, error) {
	if err := ValidateGovernanceEvent(event); err != nil {
		return nil, err
	}
	ts, err := parseGovernanceTimestamp(event.Timestamp)
	if err != nil {
		return nil, err
	}
	recordType, err := governanceEventRecordType(event.EventType)
	if err != nil {
		return nil, err
	}

	eventPayload := cloneAnyMap(event.Detail)
	if eventPayload == nil {
		eventPayload = map[string]any{}
	}
	if _, ok := eventPayload["event_id"]; !ok {
		eventPayload["event_id"] = strings.TrimSpace(event.EventID)
	}
	if _, ok := eventPayload["event_type"]; !ok {
		eventPayload["event_type"] = strings.TrimSpace(event.EventType)
	}
	if strings.TrimSpace(event.ToolName) != "" {
		if _, ok := eventPayload["tool_name"]; !ok {
			eventPayload["tool_name"] = strings.TrimSpace(event.ToolName)
		}
	}
	if strings.TrimSpace(event.Verdict) != "" {
		if recordType == "compiled_action" {
			if _, ok := eventPayload["gate_verdict"]; !ok {
				eventPayload["gate_verdict"] = strings.TrimSpace(event.Verdict)
			}
		} else if _, ok := eventPayload["verdict"]; !ok {
			eventPayload["verdict"] = strings.TrimSpace(event.Verdict)
		}
	}

	return NewRecord(RecordOpts{
		Timestamp:     ts,
		Source:        strings.TrimSpace(source),
		SourceProduct: strings.TrimSpace(source),
		AgentID:       strings.TrimSpace(event.AgentID),
		Type:          recordType,
		Event:         eventPayload,
		Metadata:      cloneAnyMap(event.Context),
	})
}

func governanceEventRecordType(eventType string) (string, error) {
	switch strings.TrimSpace(eventType) {
	case "tool_gate":
		return "policy_enforcement", nil
	case "permission_check":
		return "permission_check", nil
	case "approval_request":
		return "guardrail_activation", nil
	case "policy_evaluation":
		return "policy_enforcement", nil
	case "guardrail_activation":
		return "guardrail_activation", nil
	case "script_evaluation":
		return "compiled_action", nil
	default:
		return "", fmt.Errorf("unsupported governance event_type: %s", eventType)
	}
}

func parseGovernanceTimestamp(raw string) (time.Time, error) {
	ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp %q: %w", raw, err)
	}
	return ts.UTC(), nil
}

func cloneAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
