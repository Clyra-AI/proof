package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	coresigning "github.com/Clyra-AI/proof/core/signing"
	"github.com/Clyra-AI/proof/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestGaitCompatibilitySignedJSONFixtures(t *testing.T) {
	root := testutil.RepoRoot(t)
	fixtureDir := filepath.Join(root, "testdata", "gait_compat")

	pubHexRaw, err := os.ReadFile(filepath.Join(fixtureDir, "public_key.hex"))
	require.NoError(t, err)
	pubHex := string(pubHexRaw)

	for _, name := range []string{
		"trace_signed.json",
		"approval_token_signed.json",
		"delegation_token_signed.json",
	} {
		p := filepath.Join(fixtureDir, name)
		out, err := runCLIForTest(t, []string{"verify", "--signatures", "--public-key", pubHex, p})
		require.NoError(t, err)
		require.Contains(t, out, "verified")
	}
}

func TestGaitCompatibilityPackFixture(t *testing.T) {
	root := testutil.RepoRoot(t)
	fixtureDir := filepath.Join(root, "testdata", "gait_compat")

	traceRaw, err := os.ReadFile(filepath.Join(fixtureDir, "trace_signed.json"))
	require.NoError(t, err)

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pub)
	keyID := coresigning.KeyID(pub)

	manifest := map[string]any{
		"schema_id":      "gait.pack.manifest",
		"schema_version": "1",
		"created_at":     "2026-02-17T12:00:00Z",
		"pack_id":        "pack-gait-compat-fixture",
		"pack_type":      "run",
		"contents": []map[string]any{
			{"path": "trace.json", "sha256": sha256Hex(traceRaw), "type": "gait.gate.trace"},
		},
	}
	manifestDigest := mustDigestJSON(t, manifest)
	manifest["signatures"] = []map[string]any{{
		"alg":           "ed25519",
		"key_id":        keyID,
		"sig":           signDigestHex(t, priv, manifestDigest),
		"signed_digest": manifestDigest,
	}}
	manifestRaw, err := json.Marshal(manifest)
	require.NoError(t, err)

	zipPath := filepath.Join(t.TempDir(), "gait-compat-pack.zip")
	writeZip(t, zipPath, map[string][]byte{
		"pack_manifest.json": manifestRaw,
		"trace.json":         traceRaw,
	})

	out, err := runCLIForTest(t, []string{"verify", "--signatures", "--public-key", pubHex, zipPath})
	require.NoError(t, err)
	require.Contains(t, out, "Gait pack verified")
}
