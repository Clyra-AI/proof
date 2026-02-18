package chain

import (
	"testing"
	"time"

	"github.com/Clyra-AI/proof/core/record"
	"github.com/Clyra-AI/proof/core/signing"
	"github.com/stretchr/testify/require"
)

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
