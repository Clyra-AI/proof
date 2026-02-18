package gait

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/proof/core/signing"
	"github.com/stretchr/testify/require"
)

func TestVerifyPackWithManifestAndEmbeddedSignatures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keyID := signing.KeyID(pub)

	trace := map[string]any{
		"verdict": "allow",
	}
	traceDigest, err := canonicalDigestHex(trace)
	require.NoError(t, err)
	traceSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(traceDigest)))
	trace["signature"] = map[string]any{
		"alg":           "ed25519",
		"key_id":        keyID,
		"sig":           traceSig,
		"signed_digest": traceDigest,
	}
	traceRaw, _ := json.Marshal(trace)

	sumDigest := sha256Hex(traceRaw)
	manifest := PackManifest{
		SchemaID:      "gait.pack.manifest",
		SchemaVersion: "1",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		PackID:        "pack-1",
		PackType:      "run",
		Contents: []PackEntry{{
			Path:   "trace.json",
			SHA256: sumDigest,
			Type:   "gait.gate.trace",
		}},
	}
	manifestDigest, err := canonicalDigestHex(PackManifest{
		SchemaID:      manifest.SchemaID,
		SchemaVersion: manifest.SchemaVersion,
		CreatedAt:     manifest.CreatedAt,
		PackID:        manifest.PackID,
		PackType:      manifest.PackType,
		Contents:      manifest.Contents,
	})
	require.NoError(t, err)
	manifest.Signatures = []Signature{{
		Alg:          "ed25519",
		KeyID:        keyID,
		Sig:          base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifestDigest))),
		SignedDigest: manifestDigest,
	}}
	manifestRaw, _ := json.Marshal(manifest)

	zipPath := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, zipPath, map[string][]byte{
		"pack_manifest.json": manifestRaw,
		"trace.json":         traceRaw,
	})

	res, err := VerifyPack(zipPath, true, pub)
	require.NoError(t, err)
	require.Equal(t, 1, res.FilesVerified)
	require.Equal(t, 1, res.SignaturesVerified)
}

func TestVerifyEmbeddedSignedJSONMissingPubFails(t *testing.T) {
	err := VerifyEmbeddedSignedJSON([]byte(`{"signature":{}}`), nil)
	require.Error(t, err)
}

func TestVerifyPackErrors(t *testing.T) {
	_, err := VerifyPack(filepath.Join(t.TempDir(), "missing.zip"), false, nil)
	require.Error(t, err)

	zipPath := filepath.Join(t.TempDir(), "badpack.zip")
	writeZip(t, zipPath, map[string][]byte{
		"pack_manifest.json": []byte(`{"pack_id":"x","pack_type":"run","contents":[{"path":"trace.json","sha256":"bad","type":"gait.gate.trace"}]}`),
		"trace.json":         []byte(`{}`),
	})
	_, err = VerifyPack(zipPath, false, nil)
	require.Error(t, err)
}

func TestVerifyPackSignatureRequirementBranches(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	zipPath := filepath.Join(t.TempDir(), "nosig.zip")
	writeZip(t, zipPath, map[string][]byte{
		"pack_manifest.json": []byte(`{"pack_id":"x","pack_type":"run","contents":[{"path":"trace.json","sha256":"` + sha256Hex([]byte(`{}`)) + `","type":"gait.gate.trace"}]}`),
		"trace.json":         []byte(`{}`),
	})

	_, err = VerifyPack(zipPath, true, nil)
	require.ErrorContains(t, err, "public key is required")

	_, err = VerifyPack(zipPath, true, pub)
	require.ErrorContains(t, err, "manifest has no signatures")
}

func TestInternalHelpersAndSignatureErrors(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	require.True(t, isLikelySignedJSON("gait.gate.trace", "trace.json"))
	require.True(t, isLikelySignedJSON("", "trace.json"))
	require.False(t, isLikelySignedJSON("", "trace.txt"))

	_, err = signatureFromMap(map[string]any{"alg": "ed25519"})
	require.Error(t, err)

	err = verifySignature(Signature{Alg: "rsa"}, pub)
	require.Error(t, err)

	_, err = readZipFile(nil, "missing")
	require.Error(t, err)
}

func TestEmbeddedSignatureAndManifestMismatchErrors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keyID := signing.KeyID(pub)

	payload := map[string]any{"ok": true}
	digest, err := canonicalDigestHex(payload)
	require.NoError(t, err)
	payload["signature"] = map[string]any{
		"alg":           "ed25519",
		"key_id":        keyID,
		"sig":           base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(digest))),
		"signed_digest": "bad",
	}
	raw, _ := json.Marshal(payload)
	err = VerifyEmbeddedSignedJSON(raw, pub)
	require.ErrorContains(t, err, "signed digest mismatch")

	err = VerifyEmbeddedSignedJSON([]byte(`{"signature":"bad"}`), pub)
	require.ErrorContains(t, err, "malformed")

	err = verifyManifestSignature(PackManifest{PackID: "x"}, Signature{
		Alg:          "ed25519",
		KeyID:        keyID,
		Sig:          base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("abcd"))),
		SignedDigest: "different",
	}, pub)
	require.ErrorContains(t, err, "manifest signed_digest mismatch")
}

func TestVerifySignatureAndDigestHelperBranches(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keyID := signing.KeyID(pub)

	err = verifySignature(Signature{
		Alg:          "ed25519",
		KeyID:        "wrong",
		Sig:          base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("abcd"))),
		SignedDigest: "abcd",
	}, pub)
	require.ErrorContains(t, err, "key_id mismatch")

	err = verifySignature(Signature{
		Alg:          "ed25519",
		KeyID:        keyID,
		Sig:          "%%%bad",
		SignedDigest: "abcd",
	}, pub)
	require.ErrorContains(t, err, "decode signature")

	err = verifySignature(Signature{
		Alg:          "ed25519",
		KeyID:        keyID,
		Sig:          base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("abcd"))),
		SignedDigest: "different",
	}, pub)
	require.ErrorContains(t, err, "verification failed")

	_, err = canonicalDigestHex(map[string]any{"bad": make(chan int)})
	require.Error(t, err)

	err = VerifyEmbeddedSignedJSON([]byte(`{"ok":true}`), pub)
	require.NoError(t, err)
}

func writeZip(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	w := zip.NewWriter(f)
	for name, data := range files {
		fw, err := w.Create(name)
		require.NoError(t, err)
		_, err = fw.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
}

func sha256Hex(in []byte) string {
	sum := sha256.Sum256(in)
	return hex.EncodeToString(sum[:])
}
