package chain

import (
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/proof/core/record"
	"github.com/Clyra-AI/proof/core/signing"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultsCreatedAt(t *testing.T) {
	c := New("chain-new", time.Time{})
	require.Equal(t, "chain-new", c.ChainID)
	require.False(t, c.CreatedAt.IsZero())
	require.NotNil(t, c.Records)
}

func TestAppendAndVerify(t *testing.T) {
	c := New("chain-1", time.Now().UTC())
	r, _ := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, Append(c, r))
	v, err := Verify(c)
	require.NoError(t, err)
	require.True(t, v.Intact)
}

func TestAppendSignedRecordWithCorrectLink(t *testing.T) {
	c := New("chain-1", time.Now().UTC())
	r1, _ := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "scan_finding",
		Event:         map[string]any{"id": "f1"},
	})
	require.NoError(t, Append(c, r1))

	r2, _ := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 1, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
	})
	r2.Integrity.PreviousRecordHash = c.HeadHash
	h, _ := record.ComputeHash(r2)
	r2.Integrity.RecordHash = h
	key, _ := signing.GenerateKey()
	_, err := signing.Sign(r2, key)
	require.NoError(t, err)
	require.NoError(t, Append(c, r2))

	v, err := Verify(c)
	require.NoError(t, err)
	require.True(t, v.Intact)
}

func TestVerifyRangeUsesFullChainIntegrity(t *testing.T) {
	c := New("chain-1", time.Now().UTC())
	for i := 0; i < 3; i++ {
		r, _ := record.New(record.RecordOpts{
			Timestamp:     time.Date(2026, 2, 17, 12, i, 0, 0, time.UTC),
			Source:        "axym",
			SourceProduct: "axym",
			Type:          "decision",
			Event:         map[string]any{"n": i},
		})
		require.NoError(t, Append(c, r))
	}
	c.Records[1].Integrity.RecordHash = "sha256:bad"
	v, err := VerifyRange(c, time.Date(2026, 2, 17, 12, 1, 0, 0, time.UTC), time.Date(2026, 2, 17, 12, 2, 0, 0, time.UTC))
	require.NoError(t, err)
	require.False(t, v.Intact)
}

func TestAppendErrors(t *testing.T) {
	r, _ := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.Error(t, Append(nil, r))
	require.Error(t, Append(New("x", time.Now().UTC()), nil))
}

func TestAppendValidationAndPreviousHashMismatch(t *testing.T) {
	c := New("chain-1", time.Now().UTC())
	invalid := &record.Record{}
	require.Error(t, Append(c, invalid))

	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	r.Integrity.PreviousRecordHash = "sha256:not-head"
	err = Append(c, r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "previous_record_hash mismatch")
}

func TestAppendSignedMismatchedHashFails(t *testing.T) {
	c := New("chain-1", time.Now().UTC())
	r, _ := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	r.Integrity.PreviousRecordHash = c.HeadHash
	r.Integrity.RecordHash = "sha256:bad"
	r.Integrity.Signature = "base64:abc"
	require.Error(t, Append(c, r))
}

func TestVerifyNilAndHeadMismatch(t *testing.T) {
	_, err := Verify(nil)
	require.Error(t, err)

	c := New("chain-1", time.Now().UTC())
	r, _ := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, Append(c, r))
	c.HeadHash = "sha256:deadbeef"
	v, err := Verify(c)
	require.NoError(t, err)
	require.False(t, v.Intact)
}

func TestVerifyBreakOnPreviousHashMismatch(t *testing.T) {
	c := New("chain-break", time.Now().UTC())
	r1, _ := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	r2, _ := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 1, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "block"},
	})
	require.NoError(t, Append(c, r1))
	require.NoError(t, Append(c, r2))

	c.Records[1].Integrity.PreviousRecordHash = "sha256:tampered"
	v, err := Verify(c)
	require.NoError(t, err)
	require.False(t, v.Intact)
	require.Equal(t, 1, v.BreakIndex)
	require.True(t, strings.HasPrefix(v.BreakPoint, "prf-"))
}

func TestVerifyRangeScenarios(t *testing.T) {
	_, err := VerifyRange(nil, time.Now(), time.Now())
	require.Error(t, err)

	c := New("chain-range", time.Now().UTC())
	r, _ := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, Append(c, r))

	// No matching records in range should still be intact.
	v, err := VerifyRange(c, time.Date(2026, 2, 18, 0, 0, 0, 0, time.UTC), time.Date(2026, 2, 19, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.True(t, v.Intact)
	require.Equal(t, 0, v.Count)
}
