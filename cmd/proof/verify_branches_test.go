package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/signing"
	"github.com/Clyra-AI/proof/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestVerifyWithSignaturesAndRevocationBranches(t *testing.T) {
	key, err := proof.GenerateSigningKey()
	require.NoError(t, err)

	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 16, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	_, err = proof.Sign(r, key)
	require.NoError(t, err)

	dir := t.TempDir()
	recordPath := filepath.Join(dir, "record.json")
	require.NoError(t, proof.WriteRecord(recordPath, r))

	// Signature verify success.
	out, err := runCLIForTest(t, []string{"verify", "--signatures", "--public-key", hex.EncodeToString(key.Public), recordPath})
	require.NoError(t, err)
	require.Contains(t, out, "Record verified")

	// Revocation list branch (verified with separate revocation signer).
	revKey, err := proof.GenerateSigningKey()
	require.NoError(t, err)
	rlist, err := proof.SignRevocationList(proof.RevocationList{
		Version:   "1.0",
		CreatedAt: "2026-02-17T16:05:00Z",
		Revoked: []proof.RevocationEntry{
			{KeyID: r.Integrity.SigningKeyID, RevokedAt: "2026-02-17T15:50:00Z", Reason: "retired"},
		},
	}, revKey)
	require.NoError(t, err)
	raw, _ := json.Marshal(rlist)
	rlPath := filepath.Join(dir, "revocations.json")
	testutil.WriteFile(t, rlPath, raw)

	_, err = runCLIForTest(t, []string{"verify", "--revocation-list", rlPath, "--revocation-key", hex.EncodeToString(revKey.Public), recordPath})
	require.Error(t, err)
}

func TestVerifyChainWithSignaturesBranch(t *testing.T) {
	key, err := proof.GenerateSigningKey()
	require.NoError(t, err)
	c := proof.NewChain("verify-chain")
	for i := 0; i < 2; i++ {
		r, err := proof.NewRecord(proof.RecordOpts{
			Timestamp:     time.Date(2026, 2, 17, 16, i, 0, 0, time.UTC),
			Source:        "axym",
			SourceProduct: "axym",
			Type:          "decision",
			Event:         map[string]any{"i": i},
		})
		require.NoError(t, err)
		require.NoError(t, proof.AppendToChain(c, r))
		_, err = proof.Sign(&c.Records[i], key)
		require.NoError(t, err)
	}
	raw, _ := json.Marshal(c)
	p := filepath.Join(t.TempDir(), "chain.json")
	testutil.WriteFile(t, p, raw)

	out, err := runCLIForTest(t, []string{"verify", "--signatures", "--public-key", hex.EncodeToString(key.Public), p})
	require.NoError(t, err)
	require.Contains(t, out, "Chain intact")
}

func TestVerifyGaitSignedJSONBranch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	payload := map[string]any{"verdict": "allow"}
	digest := mustDigestJSON(t, payload)
	payload["signature"] = map[string]any{
		"alg":           "ed25519",
		"key_id":        signing.KeyID(pub),
		"sig":           signDigestHex(t, priv, digest),
		"signed_digest": digest,
	}
	raw, _ := json.Marshal(payload)
	p := filepath.Join(t.TempDir(), "trace.json")
	testutil.WriteFile(t, p, raw)

	out, err := runCLIForTest(t, []string{"verify", "--signatures", "--public-key", hex.EncodeToString(pub), p})
	require.NoError(t, err)
	require.Contains(t, out, "verified")
}
