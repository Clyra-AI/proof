package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/proof/core/signing"
	"github.com/stretchr/testify/require"
)

func TestSignManifestIsPure(t *testing.T) {
	key, err := signing.GenerateKey()
	require.NoError(t, err)

	input := Manifest{
		Files: []ManifestEntry{
			{
				Path:   "records.jsonl",
				SHA256: "sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
			},
		},
	}

	signed, err := SignManifest(input, key)
	require.NoError(t, err)
	require.Empty(t, input.Signatures)
	require.Len(t, signed.Signatures, 1)
	require.Equal(t, "sha256", signed.AlgoID)
}

func TestSignFileAndVerify(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "records.jsonl"), []byte("{}\n"), 0o644))

	manifest := Manifest{
		Files: []ManifestEntry{
			{
				Path:   "records.jsonl",
				SHA256: "sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
			},
		},
	}
	raw, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644))

	key, err := signing.GenerateKey()
	require.NoError(t, err)

	_, err = SignFile(dir, key)
	require.NoError(t, err)

	verified, err := Verify(dir, VerifyOpts{
		VerifySignatures: true,
		PublicKey:        signing.PublicKey{Public: key.Public},
	})
	require.NoError(t, err)
	require.Len(t, verified.Signatures, 1)
}

func TestVerifyUnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "records.jsonl"), []byte("{}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"algo_id":"sha512","files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}]}`), 0o644))

	_, err := Verify(dir, VerifyOpts{})
	require.ErrorContains(t, err, "unsupported bundle digest algorithm")
}

func TestSignManifestCosignRequiresKeyPath(t *testing.T) {
	_, err := SignManifestCosign(Manifest{Files: []ManifestEntry{}}, "")
	require.ErrorContains(t, err, "cosign key path is required")
}
