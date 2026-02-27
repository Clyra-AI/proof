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

func TestNewWithRelationsAffectsHash(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
		Relations: &Relations{
			ParentRecordID:   "prf-parent",
			RelatedRecordIDs: []string{"prf-related-1"},
			RelatedEntityIDs: []string{"agent:a", "tool:t"},
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
	clone.Relations.PolicyRef.PolicyVersion = "v4"

	changedHash, err := ComputeHash(clone)
	require.NoError(t, err)
	require.NotEqual(t, originalHash, changedHash)
}

func TestCloneDeepCopiesRelations(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "scan_finding",
		Event:         map[string]any{"id": "f1"},
		Relations: &Relations{
			ParentRecordID:   "prf-parent",
			RelatedRecordIDs: []string{"prf-related-1"},
			RelatedEntityIDs: []string{"agent:a"},
			PolicyRef: &PolicyRef{
				PolicyID:      "security.policy",
				PolicyVersion: "v1",
				PolicyDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
			AgentLineage: []AgentLineageHop{
				{AgentID: "agent:a", DelegatedBy: "agent:root", DelegationRecordID: "prf-del-1"},
			},
		},
	})
	require.NoError(t, err)

	c := Clone(r)
	c.Relations.RelatedRecordIDs[0] = "prf-related-2"
	c.Relations.PolicyRef.PolicyVersion = "v2"
	c.Relations.AgentLineage[0].DelegatedBy = "agent:other"

	require.Equal(t, "prf-related-1", r.Relations.RelatedRecordIDs[0])
	require.Equal(t, "v1", r.Relations.PolicyRef.PolicyVersion)
	require.Equal(t, "agent:root", r.Relations.AgentLineage[0].DelegatedBy)
}
