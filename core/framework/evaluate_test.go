package framework

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Clyra-AI/proof/core/record"
	"github.com/stretchr/testify/require"
)

func TestEvaluateCoverageAlternativeEvidencePaths(t *testing.T) {
	f := &Framework{}
	f.Framework.ID = "starter"
	f.Framework.Version = "1"
	f.Framework.Title = "Starter"
	f.Controls = []Control{{
		ID:    "cc7.1",
		Title: "Monitoring",
		EvidenceSets: []EvidenceSet{
			{
				ID:                  "wrkr-discovery",
				SourceProducts:      []string{"wrkr"},
				RequiredRecordTypes: []string{"scan_finding"},
				RequiredFields:      []string{"record_id", "source_product", "event.entity_id"},
				MinimumFrequency:    "continuous",
			},
			{
				ID:                  "runtime-control",
				SourceProducts:      []string{"gait"},
				RequiredRecordTypes: []string{"permission_check", "policy_enforcement"},
				RequiredFields:      []string{"record_id", "source_product", "event"},
				MinimumFrequency:    "continuous",
			},
			{
				ID:                  "combined",
				SourceProducts:      []string{"wrkr", "gait"},
				RequiredRecordTypes: []string{"scan_finding", "permission_check"},
				RequiredFields:      []string{"record_id", "source_product"},
				MinimumFrequency:    "continuous",
			},
		},
	}}

	wrkrRecord := mustRecord(t, "wrkr", "scan_finding", map[string]any{"entity_id": "tool:filesystem.write"})
	gaitPermission := mustRecord(t, "gait", "permission_check", map[string]any{"verdict": "allow"})
	gaitPolicy := mustRecord(t, "gait", "policy_enforcement", map[string]any{"policy_id": "policy-a"})
	wrkrMissingField := mustRecord(t, "wrkr", "scan_finding", map[string]any{"severity": "medium"})

	t.Run("wrkr only", func(t *testing.T) {
		coverage, err := EvaluateCoverage(f, []record.Record{*wrkrRecord})
		require.NoError(t, err)
		require.Equal(t, 1, coverage.CoveredControls)
		require.Equal(t, []string{"wrkr-discovery"}, coverage.Controls[0].MatchedEvidenceSetIDs)
	})

	t.Run("gait only", func(t *testing.T) {
		coverage, err := EvaluateCoverage(f, []record.Record{*gaitPermission, *gaitPolicy})
		require.NoError(t, err)
		require.Equal(t, []string{"runtime-control"}, coverage.Controls[0].MatchedEvidenceSetIDs)
	})

	t.Run("combined", func(t *testing.T) {
		coverage, err := EvaluateCoverage(f, []record.Record{*wrkrRecord, *gaitPermission})
		require.NoError(t, err)
		require.Equal(t, []string{"wrkr-discovery", "combined"}, coverage.Controls[0].MatchedEvidenceSetIDs)
	})

	t.Run("missing field blocks coverage", func(t *testing.T) {
		coverage, err := EvaluateCoverage(f, []record.Record{*wrkrMissingField})
		require.NoError(t, err)
		require.False(t, coverage.Controls[0].Covered)
		require.Equal(t, []string{"scan_finding"}, coverage.Controls[0].EvidenceSets[0].MissingRecordTypes)
	})
}

func TestEvaluateCoverageLegacyControl(t *testing.T) {
	f := &Framework{}
	f.Framework.ID = "legacy"
	f.Framework.Version = "1"
	f.Controls = []Control{{
		ID:                  "legacy-control",
		Title:               "Legacy Control",
		RequiredRecordTypes: []string{"decision"},
		RequiredFields:      []string{"record_id", "integrity.record_hash"},
		MinimumFrequency:    "continuous",
	}}

	decision := mustRecord(t, "axym", "decision", map[string]any{"action": "allow"})

	coverage, err := EvaluateCoverage(f, []record.Record{*decision})
	require.NoError(t, err)
	require.True(t, coverage.Controls[0].Covered)
	require.Equal(t, []string{"legacy"}, coverage.Controls[0].MatchedEvidenceSetIDs)
}

func TestEvaluateCoverageDeterministic(t *testing.T) {
	f := &Framework{}
	f.Framework.ID = "deterministic"
	f.Framework.Version = "1"
	f.Controls = []Control{{
		ID:    "control-1",
		Title: "Control 1",
		EvidenceSets: []EvidenceSet{{
			ID:                  "set-1",
			RequiredRecordTypes: []string{"scan_finding"},
			RequiredFields:      []string{"record_id"},
			MinimumFrequency:    "continuous",
		}},
	}}

	rec := mustRecord(t, "wrkr", "scan_finding", map[string]any{"entity_id": "tool:x"})

	first, err := EvaluateCoverage(f, []record.Record{*rec})
	require.NoError(t, err)
	second, err := EvaluateCoverage(f, []record.Record{*rec})
	require.NoError(t, err)

	firstRaw, err := json.Marshal(first)
	require.NoError(t, err)
	secondRaw, err := json.Marshal(second)
	require.NoError(t, err)
	require.Equal(t, string(firstRaw), string(secondRaw))
}

func TestEvaluateCoverageDeterministicAcrossRecordOrder(t *testing.T) {
	f := &Framework{}
	f.Framework.ID = "deterministic-order"
	f.Framework.Version = "1"
	f.Controls = []Control{{
		ID:    "control-1",
		Title: "Control 1",
		EvidenceSets: []EvidenceSet{{
			ID:                  "set-1",
			SourceProducts:      []string{"wrkr"},
			RequiredRecordTypes: []string{"scan_finding"},
			RequiredFields:      []string{"record_id", "event.entity_id"},
			MinimumFrequency:    "continuous",
		}},
	}}

	recA := mustRecordAt(t, "wrkr", "scan_finding", time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC), map[string]any{"entity_id": "tool:b"})
	recB := mustRecordAt(t, "wrkr", "scan_finding", time.Date(2026, 3, 10, 12, 1, 0, 0, time.UTC), map[string]any{"entity_id": "tool:a"})

	first, err := EvaluateCoverage(f, []record.Record{*recA, *recB})
	require.NoError(t, err)
	second, err := EvaluateCoverage(f, []record.Record{*recB, *recA})
	require.NoError(t, err)

	firstRaw, err := json.Marshal(first)
	require.NoError(t, err)
	secondRaw, err := json.Marshal(second)
	require.NoError(t, err)
	require.Equal(t, string(firstRaw), string(secondRaw))

	expected := recA.RecordID
	if recB.RecordID < expected {
		expected = recB.RecordID
	}
	require.Equal(t, []string{expected}, first.Controls[0].EvidenceSets[0].MatchingRecordIDs)
}

func TestEvaluateCoverageRejectsInvalidControls(t *testing.T) {
	f := &Framework{}
	f.Framework.ID = "invalid"
	f.Framework.Version = "1"
	f.Controls = []Control{{
		ID:    "control-1",
		Title: "Control 1",
	}}

	_, err := EvaluateCoverage(f, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "missing evidence definition")
}

func mustRecord(t *testing.T, sourceProduct, recordType string, event map[string]any) *record.Record {
	t.Helper()
	return mustRecordAt(t, sourceProduct, recordType, time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC), event)
}

func mustRecordAt(t *testing.T, sourceProduct, recordType string, ts time.Time, event map[string]any) *record.Record {
	t.Helper()
	r, err := record.New(record.RecordOpts{
		Timestamp:     ts,
		Source:        sourceProduct,
		SourceProduct: sourceProduct,
		Type:          recordType,
		Event:         event,
	})
	require.NoError(t, err)
	return r
}
