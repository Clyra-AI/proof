package proof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateGovernanceEventFixtures(t *testing.T) {
	fixtures := []string{
		"tool_gate.json",
		"permission_check.json",
		"approval_request.json",
		"policy_evaluation.json",
		"guardrail_activation.json",
		"script_evaluation.json",
	}
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			event := loadGovernanceEventFixture(t, name)
			require.NoError(t, ValidateGovernanceEvent(event))
		})
	}
}

func TestValidateGovernanceEventMinimalAndRejectMissingRequired(t *testing.T) {
	require.NoError(t, ValidateGovernanceEvent(loadGovernanceEventFixture(t, "minimal.json")))
	require.Error(t, ValidateGovernanceEvent(loadGovernanceEventFixture(t, "invalid-missing-required.json")))
}

func TestNewRecordFromEventMappings(t *testing.T) {
	cases := []struct {
		name       string
		event      GovernanceEvent
		expectType string
	}{
		{
			name: "tool_gate",
			event: GovernanceEvent{
				EventID:   "evt-1",
				Timestamp: "2026-02-20T14:00:00Z",
				EventType: "tool_gate",
				AgentID:   "agent-a",
				ToolName:  "shell.exec",
				Verdict:   "allow",
				Context: map[string]any{
					"risk_level": "limited",
				},
				Detail: map[string]any{
					"rule_id": "policy-1",
				},
			},
			expectType: "policy_enforcement",
		},
		{
			name: "permission_check",
			event: GovernanceEvent{
				EventID:   "evt-2",
				Timestamp: "2026-02-20T14:01:00Z",
				EventType: "permission_check",
				Verdict:   "allow",
				Detail: map[string]any{
					"permission": "repo.write",
				},
			},
			expectType: "permission_check",
		},
		{
			name: "approval_request",
			event: GovernanceEvent{
				EventID:   "evt-3",
				Timestamp: "2026-02-20T14:02:00Z",
				EventType: "approval_request",
				Verdict:   "require_approval",
				Detail: map[string]any{
					"reason": "high-risk-op",
				},
			},
			expectType: "guardrail_activation",
		},
		{
			name: "policy_evaluation",
			event: GovernanceEvent{
				EventID:   "evt-4",
				Timestamp: "2026-02-20T14:03:00Z",
				EventType: "policy_evaluation",
				Verdict:   "allow",
				Detail: map[string]any{
					"policy_set": "default",
				},
			},
			expectType: "policy_enforcement",
		},
		{
			name: "guardrail_activation",
			event: GovernanceEvent{
				EventID:   "evt-5",
				Timestamp: "2026-02-20T14:04:00Z",
				EventType: "guardrail_activation",
				Verdict:   "block",
				Detail: map[string]any{
					"guardrail": "secret-redaction",
				},
			},
			expectType: "guardrail_activation",
		},
		{
			name: "script_evaluation",
			event: GovernanceEvent{
				EventID:   "evt-6",
				Timestamp: "2026-02-20T14:05:00Z",
				EventType: "script_evaluation",
				Verdict:   "dry_run",
				Detail: map[string]any{
					"script_hash":          "sha256:3333333333333333333333333333333333333333333333333333333333333333",
					"tool_sequence":        []string{"shell.exec", "http.request", "db.query", "fs.write", "notify.send"},
					"step_count":           5,
					"has_conditionals":     true,
					"has_loops":            false,
					"composite_risk_class": "high",
					"script_source":        "ptc",
				},
			},
			expectType: "compiled_action",
		},
	}

	chain := NewChain("promoted")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRecordFromEvent(tc.event, "axym")
			require.NoError(t, err)
			require.Equal(t, tc.expectType, r.RecordType)
			require.NoError(t, ValidateRecord(r))
			require.Equal(t, "axym", r.Source)
			require.Equal(t, "axym", r.SourceProduct)
			require.Equal(t, tc.event.EventID, r.Event["event_id"])
			require.Equal(t, tc.event.EventType, r.Event["event_type"])
			if tc.event.Context != nil {
				require.NotNil(t, r.Metadata)
			}
			require.NoError(t, AppendToChain(chain, r))
		})
	}

	verification, err := VerifyChain(chain)
	require.NoError(t, err)
	require.True(t, verification.Intact)
	require.Equal(t, len(cases), verification.Count)

	key, err := GenerateSigningKey()
	require.NoError(t, err)
	for i := range chain.Records {
		_, err := Sign(&chain.Records[i], key)
		require.NoError(t, err)
		require.NoError(t, Verify(&chain.Records[i], PublicKey{Public: key.Public}))
	}
}

func TestNewRecordFromEventErrors(t *testing.T) {
	_, err := NewRecordFromEvent(GovernanceEvent{}, "axym")
	require.Error(t, err)

	_, err = NewRecordFromEvent(GovernanceEvent{
		EventID:   "evt-bad-type",
		Timestamp: "2026-02-20T15:00:00Z",
		EventType: "not-real",
	}, "axym")
	require.Error(t, err)

	_, err = NewRecordFromEvent(GovernanceEvent{
		EventID:   "evt-script-missing",
		Timestamp: "2026-02-20T15:01:00Z",
		EventType: "script_evaluation",
	}, "axym")
	require.Error(t, err)

	_, err = NewRecordFromEvent(GovernanceEvent{
		EventID:   "evt-empty-source",
		Timestamp: "2026-02-20T15:02:00Z",
		EventType: "tool_gate",
	}, "")
	require.Error(t, err)
}

func loadGovernanceEventFixture(t *testing.T, name string) GovernanceEvent {
	t.Helper()
	path := filepath.Join("testdata", "governance_events", name)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var event GovernanceEvent
	require.NoError(t, json.Unmarshal(raw, &event))
	return event
}

func TestGovernanceTimestampIsNormalizedToUTC(t *testing.T) {
	event := GovernanceEvent{
		EventID:   "evt-tz",
		Timestamp: "2026-02-20T11:00:00-05:00",
		EventType: "tool_gate",
	}
	r, err := NewRecordFromEvent(event, "axym")
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 2, 20, 16, 0, 0, 0, time.UTC), r.Timestamp)
}
