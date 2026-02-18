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
	"sort"
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

	require.NoError(t, verifyBundle(dir, false, "", proof.CosignVerifyOpts{}))
}

func TestDecodePublicKeyErrors(t *testing.T) {
	_, err := decodePublicKey("bad")
	require.Error(t, err)
}

func TestDecodePublicKeyBase64(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	decoded, err := decodePublicKey(base64.StdEncoding.EncodeToString(pub))
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(pub), hex.EncodeToString(decoded.Public))
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
		"sig":           signDigestHex(t, priv, traceDigest),
		"signed_digest": traceDigest,
	}
	traceRaw, _ := json.Marshal(trace)

	proofRec, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "tool_invocation",
		Event:         map[string]any{"tool": "demo"},
	})
	require.NoError(t, err)
	_, err = proof.Sign(proofRec, proof.SigningKey{Private: priv, Public: pub})
	require.NoError(t, err)
	proofRaw, _ := json.Marshal(proofRec)
	proofJSONL := append(proofRaw, '\n')

	manifest := map[string]any{
		"schema_id":      "gait.pack.manifest",
		"schema_version": "1",
		"created_at":     "2026-02-17T12:00:00Z",
		"pack_id":        "pack-1",
		"pack_type":      "run",
		"contents": []map[string]any{
			{"path": "trace.json", "sha256": sha256Hex(traceRaw), "type": "gait.gate.trace"},
			{"path": "proof_records.jsonl", "sha256": sha256Hex(proofJSONL), "type": "proof.records.v1"},
		},
	}
	manifestDigest := mustDigestJSON(t, manifest)
	manifest["signatures"] = []map[string]any{
		{
			"alg":           "ed25519",
			"key_id":        keyID,
			"sig":           signDigestHex(t, priv, manifestDigest),
			"signed_digest": manifestDigest,
		},
	}
	manifestRaw, _ := json.Marshal(manifest)

	zipPath := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, zipPath, map[string][]byte{
		"pack_manifest.json":  manifestRaw,
		"trace.json":          traceRaw,
		"proof_records.jsonl": proofJSONL,
	})

	kind, err := detectArtifact(zipPath)
	require.NoError(t, err)
	require.Equal(t, artifactGaitPack, kind)

	res, err := verifyGaitPack(zipPath, true, hex.EncodeToString(pub), proof.CosignVerifyOpts{})
	require.NoError(t, err)
	require.Equal(t, 2, res.FilesVerified)
	require.Equal(t, 1, res.ProofRecordsVerified)
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
		"sig":           signDigestHex(t, priv, d),
		"signed_digest": d,
	}
	raw, _ := json.Marshal(payload)
	p := filepath.Join(t.TempDir(), "trace.json")
	testutil.WriteFile(t, p, raw)
	require.NoError(t, verifyGaitSignedJSON(p, hex.EncodeToString(pub)))
}

func TestDetectAndVerifyGaitRunpack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keyID := signing.KeyID(pub)

	run := []byte(`{"schema_id":"gait.runpack.run","run_id":"run-1"}`)
	intents := []byte(`{"schema_id":"gait.runpack.intent"}` + "\n")
	results := []byte(`{"schema_id":"gait.runpack.result"}` + "\n")
	refs := []byte(`{"schema_id":"gait.runpack.refs","receipts":[]}`)

	files := []map[string]any{
		{"path": "run.json", "sha256": sha256Hex(run)},
		{"path": "intents.jsonl", "sha256": sha256Hex(intents)},
		{"path": "results.jsonl", "sha256": sha256Hex(results)},
		{"path": "refs.json", "sha256": sha256Hex(refs)},
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i]["path"].(string) < files[j]["path"].(string)
	})

	signable := map[string]any{
		"schema_id":       "gait.runpack.manifest",
		"schema_version":  "1.0.0",
		"run_id":          "run-1",
		"files":           files,
		"manifest_digest": "",
	}
	manifestDigest := mustDigestJSON(t, signable)
	manifest := map[string]any{
		"schema_id":       "gait.runpack.manifest",
		"schema_version":  "1.0.0",
		"run_id":          "run-1",
		"files":           files,
		"manifest_digest": manifestDigest,
		"signatures": []map[string]any{{
			"alg":           "ed25519",
			"key_id":        keyID,
			"sig":           signDigestHex(t, priv, manifestDigest),
			"signed_digest": manifestDigest,
		}},
	}
	manifestRaw, _ := json.Marshal(manifest)

	zipPath := filepath.Join(t.TempDir(), "runpack.zip")
	writeZip(t, zipPath, map[string][]byte{
		"manifest.json": manifestRaw,
		"run.json":      run,
		"intents.jsonl": intents,
		"results.jsonl": results,
		"refs.json":     refs,
	})

	kind, err := detectArtifact(zipPath)
	require.NoError(t, err)
	require.Equal(t, artifactGaitRunpack, kind)

	res, err := verifyGaitRunpack(zipPath, true, base64.StdEncoding.EncodeToString(pub), proof.CosignVerifyOpts{})
	require.NoError(t, err)
	require.Equal(t, "run-1", res.RunID)
	require.Equal(t, 4, res.FilesVerified)
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

func signDigestHex(t *testing.T, priv ed25519.PrivateKey, digestHex string) string {
	t.Helper()
	digest, err := hex.DecodeString(digestHex)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest))
}
