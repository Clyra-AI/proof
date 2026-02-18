package signing

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Clyra-AI/proof/core/record"
	"github.com/stretchr/testify/require"
)

func TestDeterministicEd25519Signature(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	key := SigningKey{Private: priv, Public: pub}

	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "test",
		SourceProduct: "test",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)

	r1 := record.Clone(r)
	r2 := record.Clone(r)
	_, err = Sign(r1, key)
	require.NoError(t, err)
	_, err = Sign(r2, key)
	require.NoError(t, err)
	require.Equal(t, r1.Integrity.Signature, r2.Integrity.Signature)
}
