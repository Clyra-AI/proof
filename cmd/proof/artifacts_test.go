package main

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

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/signing"
	"github.com/Clyra-AI/proof/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestLoadChainFromDirectoryAndJSONL(t *testing.T) {
	dir := t.TempDir()

	r1, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	r2, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 1, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "block"},
	})
	require.NoError(t, err)

	c := proof.NewChain("chain-dir")
	require.NoError(t, proof.AppendToChain(c, r1))
	require.NoError(t, proof.AppendToChain(c, r2))

	require.NoError(t, proof.WriteRecord(filepath.Join(dir, "r1.json"), &c.Records[0]))
	line2, _ := json.Marshal(c.Records[1])
	testutil.WriteFile(t, filepath.Join(dir, "records.jsonl"), append(line2, '\n'))

	loaded, err := loadChain(dir)
	require.NoError(t, err)
	require.Len(t, loaded.Records, 2)
}

func TestVerifyBundle(t *testing.T) {
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "records.jsonl")
	content := []byte("{}\n")
	testutil.WriteFile(t, dataPath, content)

	sum, err := proof.Canonicalize(content, proof.DomainText)
	require.NoError(t, err)
	_ = sum

	// Use exact sha256 to satisfy bundle verify.
	manifestJSON := `{"files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}]}`
	testutil.WriteFile(t, filepath.Join(dir, "manifest.json"), []byte(manifestJSON))

	require.NoError(t, verifyBundle(dir))
}

func TestDecodePublicKeyErrors(t *testing.T) {
	_, err := decodePublicKey("bad")
	require.Error(t, err)
}

func TestDetectAndVerifyGaitPack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keyID := signing.KeyID(pub)

	trace := map[string]any{"verdict": "allow"}
	traceDigest := mustDigestJSON(t, trace)
	trace["signature"] = map[string]any{
		"alg":           "ed25519",
		"key_id":        keyID,
		"sig":           base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(traceDigest))),
		"signed_digest": traceDigest,
	}
	traceRaw, _ := json.Marshal(trace)

	manifest := map[string]any{
		"schema_id":      "gait.pack.manifest",
		"schema_version": "1",
		"created_at":     "2026-02-17T12:00:00Z",
		"pack_id":        "pack-1",
		"pack_type":      "run",
		"contents": []map[string]any{
			{"path": "trace.json", "sha256": sha256Hex(traceRaw), "type": "gait.gate.trace"},
		},
	}
	manifestDigest := mustDigestJSON(t, manifest)
	manifest["signatures"] = []map[string]any{
		{
			"alg":           "ed25519",
			"key_id":        keyID,
			"sig":           base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifestDigest))),
			"signed_digest": manifestDigest,
		},
	}
	manifestRaw, _ := json.Marshal(manifest)

	zipPath := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, zipPath, map[string][]byte{
		"pack_manifest.json": manifestRaw,
		"trace.json":         traceRaw,
	})

	kind, err := detectArtifact(zipPath)
	require.NoError(t, err)
	require.Equal(t, artifactGaitPack, kind)

	res, err := verifyGaitPack(zipPath, true, hex.EncodeToString(pub))
	require.NoError(t, err)
	require.Equal(t, 1, res.FilesVerified)
}

func TestVerifyGaitSignedJSON(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keyID := signing.KeyID(pub)
	payload := map[string]any{"verdict": "allow"}
	d := mustDigestJSON(t, payload)
	payload["signature"] = map[string]any{
		"alg":           "ed25519",
		"key_id":        keyID,
		"sig":           base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(d))),
		"signed_digest": d,
	}
	raw, _ := json.Marshal(payload)
	p := filepath.Join(t.TempDir(), "trace.json")
	testutil.WriteFile(t, p, raw)
	require.NoError(t, verifyGaitSignedJSON(p, hex.EncodeToString(pub)))
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

func mustDigestJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	canonical, err := proof.Canonicalize(raw, proof.DomainJSON)
	require.NoError(t, err)
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}
