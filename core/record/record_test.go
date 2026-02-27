package record

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewAndHash(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, r.RecordID)
	require.Contains(t, r.Integrity.RecordHash, "sha256:")

	h, err := ComputeHash(r)
	require.NoError(t, err)
	require.Equal(t, h, r.Integrity.RecordHash)
}

func TestValidateRequiredFields(t *testing.T) {
	err := Validate(&Record{})
	require.Error(t, err)
}

func TestValidateDetailedErrors(t *testing.T) {
	err := Validate(nil)
	require.ErrorContains(t, err, "record is nil")

	base := &Record{
		RecordVersion: SchemaVersion,
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		RecordType:    "decision",
		Event:         map[string]any{"action": "allow"},
	}

	r := *base
	r.RecordVersion = ""
	require.ErrorContains(t, Validate(&r), "record_version is required")

	r = *base
	r.Timestamp = time.Time{}
	require.ErrorContains(t, Validate(&r), "timestamp is required")

	r = *base
	r.Source = ""
	require.ErrorContains(t, Validate(&r), "source is required")

	r = *base
	r.SourceProduct = ""
	require.ErrorContains(t, Validate(&r), "source_product is required")

	r = *base
	r.RecordType = ""
	require.ErrorContains(t, Validate(&r), "record_type is required")

	r = *base
	r.Event = nil
	require.ErrorContains(t, Validate(&r), "event is required")
}

func TestComputeHashNil(t *testing.T) {
	_, err := ComputeHash(nil)
	require.ErrorContains(t, err, "record is nil")
}

func TestNewDefaultsAndTrim(t *testing.T) {
	r, err := New(RecordOpts{
		Source:        "  axym  ",
		SourceProduct: "  axym  ",
		Type:          "  decision  ",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	require.Equal(t, SchemaVersion, r.RecordVersion)
	require.Equal(t, "axym", r.Source)
	require.Equal(t, "axym", r.SourceProduct)
	require.Equal(t, "decision", r.RecordType)
	require.True(t, strings.HasPrefix(r.RecordID, "prf-"))
}

func TestNewMarshalErrorFromEvent(t *testing.T) {
	_, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"bad": make(chan int)},
	})
	require.Error(t, err)
}

func TestClone(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "scan_finding",
		Event:         map[string]any{"id": "f1"},
		Metadata:      map[string]any{"env": "prod"},
	})
	require.NoError(t, err)
	c := Clone(r)
	c.Event["id"] = "f2"
	require.Equal(t, "f1", r.Event["id"])
}

func TestNewWithRelationshipAffectsHash(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
		Relationship: &Relationship{
			ParentRef:  &RelationshipRef{Kind: "trace", ID: "trace-1"},
			EntityRefs: []RelationshipRef{{Kind: "agent", ID: "agent:a"}, {Kind: "tool", ID: "tool:t"}},
			PolicyRef: &PolicyRef{
				PolicyID:      "prod.policy",
				PolicyVersion: "v3",
				PolicyDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	})
	require.NoError(t, err)

	originalHash := r.Integrity.RecordHash
	clone := Clone(r)
	clone.Relationship.PolicyRef.PolicyVersion = "v4"

	changedHash, err := ComputeHash(clone)
	require.NoError(t, err)
	require.NotEqual(t, originalHash, changedHash)
}

func TestCloneDeepCopiesRelationship(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "scan_finding",
		Event:         map[string]any{"id": "f1"},
		Relationship: &Relationship{
			ParentRef:  &RelationshipRef{Kind: "trace", ID: "trace-1"},
			EntityRefs: []RelationshipRef{{Kind: "agent", ID: "agent:a"}},
			PolicyRef: &PolicyRef{
				PolicyID:       "security.policy",
				PolicyVersion:  "v1",
				PolicyDigest:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				MatchedRuleIDs: []string{"rule-1"},
			},
			AgentChain: []AgentChainHop{
				{Identity: "agent:a", Role: "requester"},
			},
		},
	})
	require.NoError(t, err)

	c := Clone(r)
	c.Relationship.EntityRefs[0].ID = "agent:other"
	c.Relationship.PolicyRef.PolicyVersion = "v2"
	c.Relationship.AgentChain[0].Role = "delegate"

	require.Equal(t, "agent:a", r.Relationship.EntityRefs[0].ID)
	require.Equal(t, "v1", r.Relationship.PolicyRef.PolicyVersion)
	require.Equal(t, "requester", r.Relationship.AgentChain[0].Role)
}

func TestNewNormalizesRelationshipDeterministically(t *testing.T) {
	base := RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
	}
	first := base
	first.Relationship = &Relationship{
		EntityRefs: []RelationshipRef{
			{Kind: "Tool", ID: " tool:b "},
			{Kind: "agent", ID: "agent:a"},
			{Kind: "tool", ID: "tool:b"},
		},
		PolicyRef: &PolicyRef{
			PolicyDigest:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			MatchedRuleIDs: []string{"rule-b", "rule-a", "rule-b"},
		},
		Edges: []RelationshipEdge{
			{Kind: "Calls", From: RelationshipRef{Kind: "agent", ID: "agent:a"}, To: RelationshipRef{Kind: "tool", ID: "tool:b"}},
			{Kind: "calls", From: RelationshipRef{Kind: "agent", ID: "agent:a"}, To: RelationshipRef{Kind: "tool", ID: "tool:b"}},
		},
	}
	second := base
	second.Relationship = &Relationship{
		EntityRefs: []RelationshipRef{
			{Kind: "tool", ID: "tool:b"},
			{Kind: "agent", ID: "agent:a"},
		},
		PolicyRef: &PolicyRef{
			PolicyDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			MatchedRuleIDs: []string{"rule-a", "rule-b"},
		},
		Edges: []RelationshipEdge{
			{Kind: "calls", From: RelationshipRef{Kind: "agent", ID: "agent:a"}, To: RelationshipRef{Kind: "tool", ID: "tool:b"}},
		},
	}

	r1, err := New(first)
	require.NoError(t, err)
	r2, err := New(second)
	require.NoError(t, err)

	require.Equal(t, r1.RecordID, r2.RecordID)
	require.Equal(t, r1.Integrity.RecordHash, r2.Integrity.RecordHash)
	require.Equal(t, []string{"rule-a", "rule-b"}, r1.Relationship.PolicyRef.MatchedRuleIDs)
}
