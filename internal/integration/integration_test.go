package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/proof"
	"github.com/stretchr/testify/require"
)

func TestCrossComponentFlow(t *testing.T) {
	chain := proof.NewChain("integration")
	for i := 0; i < 5; i++ {
		r, err := proof.NewRecord(proof.RecordOpts{
			Timestamp:     time.Date(2026, 2, 17, 12, i, 0, 0, time.UTC),
			Source:        "axym",
			SourceProduct: "axym",
			Type:          "decision",
			Event:         map[string]any{"n": i},
		})
		require.NoError(t, err)
		require.NoError(t, proof.AppendToChain(chain, r))
	}

	v, err := proof.VerifyChain(chain)
	require.NoError(t, err)
	require.True(t, v.Intact)
	require.Equal(t, 5, v.Count)

	key, err := proof.GenerateSigningKey()
	require.NoError(t, err)
	for i := range chain.Records {
		_, err := proof.Sign(&chain.Records[i], key)
		require.NoError(t, err)
		require.NoError(t, proof.Verify(&chain.Records[i], proof.PublicKey{Public: key.Public}))
	}

	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.json")
	raw, _ := json.MarshalIndent(chain, "", "  ")
	require.NoError(t, os.WriteFile(chainPath, raw, 0o644))
}
