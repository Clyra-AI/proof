package proof

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewRecordDeterministicID(t *testing.T) {
	ts := time.Date(2026, 2, 17, 12, 30, 0, 0, time.UTC)
	opts := RecordOpts{
		Timestamp:     ts,
		Source:        "axym-mcp-collector",
		SourceProduct: "axym",
		Type:          "tool_invocation",
		Event:         map[string]any{"tool": "postgres_query", "action": "SELECT"},
	}
	r1, err := NewRecord(opts)
	require.NoError(t, err)
	r2, err := NewRecord(opts)
	require.NoError(t, err)
	require.Equal(t, r1.RecordID, r2.RecordID)
}

func TestChainTamperDetection(t *testing.T) {
	c := NewChain("test")
	r1, _ := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 10, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "scan_finding",
		Event:         map[string]any{"id": "f1"},
	})
	r2, _ := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 10, 1, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"id": "d1"},
	})
	require.NoError(t, AppendToChain(c, r1))
	require.NoError(t, AppendToChain(c, r2))

	c.Records[1].Event["id"] = "tampered"
	v, err := VerifyChain(c)
	require.NoError(t, err)
	require.False(t, v.Intact)
	require.Equal(t, 1, v.BreakIndex)
}

func TestSignAndVerify(t *testing.T) {
	c := NewChain("test")
	r, _ := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 10, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
	})
	require.NoError(t, AppendToChain(c, r))

	key, err := GenerateSigningKey()
	require.NoError(t, err)
	signed, err := Sign(&c.Records[0], key)
	require.NoError(t, err)
	err = Verify(signed, PublicKey{Public: key.Public})
	require.NoError(t, err)
}
