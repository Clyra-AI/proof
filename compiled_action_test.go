package proof

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCompiledActionGoldenRecordsValidate(t *testing.T) {
	paths := []string{
		filepath.Join("testdata", "records", "compiled_action_full.json"),
		filepath.Join("testdata", "records", "compiled_action_minimal.json"),
	}
	for _, p := range paths {
		r, err := ReadRecord(p)
		require.NoError(t, err)
		require.Equal(t, "compiled_action", r.RecordType)
		require.NoError(t, ValidateRecord(r))
		h, err := ComputeRecordHash(r)
		require.NoError(t, err)
		require.Equal(t, r.Integrity.RecordHash, h)
	}
}

func TestCompiledActionSchemaRejectsInvalidFields(t *testing.T) {
	_, err := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 20, 16, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "compiled_action",
		Event: map[string]any{
			"script_hash":          "sha256:4444444444444444444444444444444444444444444444444444444444444444",
			"tool_sequence":        []string{},
			"step_count":           1,
			"has_conditionals":     false,
			"has_loops":            false,
			"composite_risk_class": "high",
		},
	})
	require.Error(t, err)

	_, err = NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 20, 16, 1, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "compiled_action",
		Event: map[string]any{
			"script_hash":          "sha256:5555555555555555555555555555555555555555555555555555555555555555",
			"tool_sequence":        []string{"shell.exec"},
			"step_count":           1,
			"has_conditionals":     false,
			"has_loops":            false,
			"composite_risk_class": "critical",
		},
	})
	require.Error(t, err)
}

func TestCompiledActionChainRoundTrip(t *testing.T) {
	r, err := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 20, 16, 2, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "compiled_action",
		Event: map[string]any{
			"script_hash":          "sha256:6666666666666666666666666666666666666666666666666666666666666666",
			"tool_sequence":        []string{"shell.exec", "http.request", "db.query", "fs.write", "notify.send"},
			"step_count":           5,
			"has_conditionals":     true,
			"has_loops":            false,
			"composite_risk_class": "high",
			"script_source":        "ptc",
		},
	})
	require.NoError(t, err)

	chain := NewChain("compiled-action")
	require.NoError(t, AppendToChain(chain, r))
	v, err := VerifyChain(chain)
	require.NoError(t, err)
	require.True(t, v.Intact)
	require.Equal(t, 1, v.Count)
}

func TestRecordContextMetadataKeysCompatibility(t *testing.T) {
	withContext, err := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 20, 16, 3, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
		Metadata: map[string]any{
			"data_class":        "pii",
			"endpoint_class":    "write",
			"risk_level":        "high",
			"business_process":  "customer-support",
			"affected_entities": []string{"ticket:10", "customer:42"},
		},
	})
	require.NoError(t, err)
	require.NoError(t, ValidateRecord(withContext))

	withoutContext, err := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 20, 16, 4, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	require.NoError(t, ValidateRecord(withoutContext))
}
