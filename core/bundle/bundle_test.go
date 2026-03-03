package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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

func TestReadManifestBranches(t *testing.T) {
	_, err := ReadManifest(t.TempDir())
	require.Error(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{"), 0o644))
	_, err = ReadManifest(dir)
	require.Error(t, err)
}

func TestWriteManifestError(t *testing.T) {
	err := WriteManifest(filepath.Join(t.TempDir(), "missing"), Manifest{})
	require.Error(t, err)
}

func TestVerifyHashMismatchAndSignatureBranches(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "records.jsonl"), []byte("{}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"files":[{"path":"records.jsonl","sha256":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}]}`), 0o644))
	_, err := Verify(dir, VerifyOpts{})
	require.ErrorContains(t, err, "bundle hash mismatch")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}]}`), 0o644))
	_, err = Verify(dir, VerifyOpts{VerifySignatures: true})
	require.ErrorContains(t, err, "has no signatures")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{
	  "files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}],
	  "signatures":[{"alg":"ed25519","key_id":"k","sig":"x","signed_digest":"d"}]
	}`), 0o644))
	_, err = Verify(dir, VerifyOpts{VerifySignatures: true})
	require.ErrorContains(t, err, "public key is required")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{
	  "files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}],
	  "signatures":[{"alg":"rsa","key_id":"k","sig":"x","signed_digest":"d"}]
	}`), 0o644))
	_, err = Verify(dir, VerifyOpts{VerifySignatures: true})
	require.ErrorContains(t, err, "unsupported bundle signature algorithm")
}

func TestVerifyAdditionalBranches(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"files":[{"path":"missing.jsonl","sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`), 0o644))
	_, err := Verify(dir, VerifyOpts{})
	require.Error(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"files":[{"path":"missing.jsonl"}]}`), 0o644))
	_, err = Verify(dir, VerifyOpts{})
	require.Error(t, err)

	recordsDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(recordsDir, "records.jsonl"), []byte("{}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(recordsDir, "manifest.json"), []byte(`{"files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}]}`), 0o644))
	key1, err := signing.GenerateKey()
	require.NoError(t, err)
	_, err = SignFile(recordsDir, key1)
	require.NoError(t, err)
	key2, err := signing.GenerateKey()
	require.NoError(t, err)
	_, err = Verify(recordsDir, VerifyOpts{
		VerifySignatures: true,
		PublicKey:        signing.PublicKey{Public: key2.Public},
	})
	require.Error(t, err)
}

func TestSignManifestAndSignFileErrorBranches(t *testing.T) {
	_, err := SignManifest(Manifest{Files: []ManifestEntry{}}, signing.SigningKey{})
	require.ErrorContains(t, err, "private key is required")

	_, err = SignFile(t.TempDir(), signing.SigningKey{})
	require.Error(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"files":[]}`), 0o644))
	_, err = SignFileCosign(dir, "")
	require.ErrorContains(t, err, "cosign key path is required")

	if runtime.GOOS != "windows" {
		key, genErr := signing.GenerateKey()
		require.NoError(t, genErr)

		readonly := t.TempDir()
		manifestPath := filepath.Join(readonly, "manifest.json")
		require.NoError(t, os.WriteFile(manifestPath, []byte(`{"files":[]}`), 0o644))
		require.NoError(t, os.Chmod(manifestPath, 0o444))
		defer func() { _ = os.Chmod(manifestPath, 0o644) }()

		_, err = SignFile(readonly, key)
		require.Error(t, err)
	}
}

func TestVerifyCosignSignatureMissingMaterial(t *testing.T) {
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
	digest, err := ManifestDigest(manifest)
	require.NoError(t, err)
	manifest.Signatures = []signing.Signature{
		{
			Alg:          "cosign",
			KeyID:        "cosign:test",
			Sig:          "ZmFrZS1zaWduYXR1cmU=",
			SignedDigest: digest,
		},
	}
	raw, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644))

	_, err = Verify(dir, VerifyOpts{VerifySignatures: true})
	require.ErrorContains(t, err, "requires --cosign-key or --cosign-cert")
}

func TestSignManifestCosignAndSignFileCosignSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake cosign shell helper is unix-only")
	}
	fakeBinDir := writeFakeCosign(t)
	t.Setenv("PATH", fakeBinDir+":"+os.Getenv("PATH"))

	signed, err := SignManifestCosign(Manifest{Files: []ManifestEntry{}}, "fake.key")
	require.NoError(t, err)
	require.Len(t, signed.Signatures, 1)
	require.Equal(t, "cosign", signed.Signatures[0].Alg)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"files":[]}`), 0o644))
	out, err := SignFileCosign(dir, "fake.key")
	require.NoError(t, err)
	require.Len(t, out.Signatures, 1)

	persisted, err := ReadManifest(dir)
	require.NoError(t, err)
	require.Len(t, persisted.Signatures, 1)
}

func TestVerifyCosignSignaturePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake cosign shell helper is unix-only")
	}
	fakeBinDir := writeFakeCosign(t)
	t.Setenv("PATH", fakeBinDir+":"+os.Getenv("PATH"))

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "records.jsonl"), []byte("{}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{
	  "files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}]
	}`), 0o644))
	signed, err := SignFileCosign(dir, "fake.key")
	require.NoError(t, err)
	require.Len(t, signed.Signatures, 1)

	_, err = Verify(dir, VerifyOpts{
		VerifySignatures: true,
		Cosign: signing.CosignVerifyOpts{
			KeyPath: "fake.key",
		},
	})
	require.NoError(t, err)
}

func writeFakeCosign(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cosign")
	script := `#!/usr/bin/env sh
set -eu
mode="$1"
shift
if [ "$mode" = "sign-blob" ]; then
  out=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--output-signature" ]; then
      out="$2"
      shift 2
      continue
    fi
    shift
  done
  printf "ZmFrZS1zaWduYXR1cmU=\n" > "$out"
  exit 0
fi
if [ "$mode" = "verify-blob" ]; then
  exit 0
fi
exit 0
`
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return dir
}
