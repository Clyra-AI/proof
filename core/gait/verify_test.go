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
	"sort"
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
	traceSig := signDigestHex(t, priv, traceDigest)
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
		Sig:          signDigestHex(t, priv, manifestDigest),
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
		"sig":           signDigestHex(t, priv, digest),
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
		Sig:          signDigestHex(t, priv, digest),
		SignedDigest: "different",
	}, pub)
	require.ErrorContains(t, err, "manifest signed_digest mismatch")
}

func TestVerifySignatureAndDigestHelperBranches(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keyID := signing.KeyID(pub)
	okDigest := digestHex(t, "abcd")
	badDigest := digestHex(t, "different")

	err = verifySignature(Signature{
		Alg:          "ed25519",
		KeyID:        "wrong",
		Sig:          signDigestHex(t, priv, okDigest),
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
		Sig:          signDigestHex(t, priv, okDigest),
		SignedDigest: badDigest,
	}, pub)
	require.ErrorContains(t, err, "verification failed")

	err = verifySignature(Signature{
		Alg:          "ed25519",
		KeyID:        keyID,
		Sig:          signDigestHex(t, priv, okDigest),
		SignedDigest: "abcd",
	}, pub)
	require.ErrorContains(t, err, "invalid signed digest length")

	_, err = canonicalDigestHex(map[string]any{"bad": make(chan int)})
	require.Error(t, err)

	err = VerifyEmbeddedSignedJSON([]byte(`{"ok":true}`), pub)
	require.NoError(t, err)
}

func TestVerifyRunpack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	keyID := signing.KeyID(pub)

	run := []byte(`{"schema_id":"gait.runpack.run","run_id":"run-demo"}`)
	intents := []byte(`{"schema_id":"gait.runpack.intent"}` + "\n")
	results := []byte(`{"schema_id":"gait.runpack.result"}` + "\n")
	refs := []byte(`{"schema_id":"gait.runpack.refs","receipts":[]}`)

	files := []RunpackFile{
		{Path: "run.json", SHA256: sha256Hex(run)},
		{Path: "intents.jsonl", SHA256: sha256Hex(intents)},
		{Path: "results.jsonl", SHA256: sha256Hex(results)},
		{Path: "refs.json", SHA256: sha256Hex(refs)},
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	manifest := RunpackManifest{
		SchemaID:      "gait.runpack.manifest",
		SchemaVersion: "1.0.0",
		RunID:         "run-demo",
		Files:         files,
	}
	d, err := runpackManifestDigest(manifest)
	require.NoError(t, err)
	manifest.ManifestDigest = d
	manifest.Signatures = []Signature{{
		Alg:          "ed25519",
		KeyID:        keyID,
		Sig:          signDigestHex(t, priv, d),
		SignedDigest: d,
	}}
	manifestRaw, _ := json.Marshal(manifest)

	zipPath := filepath.Join(t.TempDir(), "runpack.zip")
	writeZip(t, zipPath, map[string][]byte{
		"manifest.json": manifestRaw,
		"run.json":      run,
		"intents.jsonl": intents,
		"results.jsonl": results,
		"refs.json":     refs,
	})

	res, err := VerifyRunpack(zipPath, true, pub)
	require.NoError(t, err)
	require.Equal(t, "run-demo", res.RunID)
	require.Equal(t, 4, res.FilesVerified)
	require.Equal(t, 1, res.SignaturesVerified)
}

func TestVerifyRunpackErrorBranches(t *testing.T) {
	pub, manifest, files := newSignedRunpackFixture(t)

	manifestBadSchema := manifest
	manifestBadSchema.SchemaID = "bad.schema"
	_, err := VerifyRunpack(writeRunpackZip(t, manifestBadSchema, files), false, nil)
	require.ErrorContains(t, err, "schema_id")

	manifestBadVersion := manifest
	manifestBadVersion.SchemaVersion = "2.0.0"
	_, err = VerifyRunpack(writeRunpackZip(t, manifestBadVersion, files), false, nil)
	require.ErrorContains(t, err, "schema_version")

	filesMissing := cloneFileMap(files)
	delete(filesMissing, "refs.json")
	_, err = VerifyRunpack(writeRunpackZip(t, manifest, filesMissing), false, nil)
	require.ErrorContains(t, err, "missing content refs.json")

	manifestBadHash := manifest
	manifestBadHash.Files = append([]RunpackFile(nil), manifest.Files...)
	manifestBadHash.Files[0].SHA256 = "deadbeef"
	_, err = VerifyRunpack(writeRunpackZip(t, manifestBadHash, files), false, nil)
	require.ErrorContains(t, err, "content hash mismatch")

	manifestBadDigest := manifest
	manifestBadDigest.ManifestDigest = digestHex(t, "wrong")
	_, err = VerifyRunpack(writeRunpackZip(t, manifestBadDigest, files), false, nil)
	require.ErrorContains(t, err, "manifest digest mismatch")

	_, err = VerifyRunpack(writeRunpackZip(t, manifest, files), true, nil)
	require.ErrorContains(t, err, "public key is required")

	manifestNoSigs := manifest
	manifestNoSigs.Signatures = nil
	_, err = VerifyRunpack(writeRunpackZip(t, manifestNoSigs, files), true, pub)
	require.ErrorContains(t, err, "manifest has no signatures")

	require.ErrorContains(t, verifyRunpackSignature(digestHex(t, "other"), manifest.Signatures[0], pub), "manifest signed_digest mismatch")
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

func signDigestHex(t *testing.T, priv ed25519.PrivateKey, digestHex string) string {
	t.Helper()
	digest, err := hex.DecodeString(digestHex)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest))
}

func digestHex(t *testing.T, text string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func newSignedRunpackFixture(t *testing.T) (ed25519.PublicKey, RunpackManifest, map[string][]byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	files := map[string][]byte{
		"run.json":      []byte(`{"schema_id":"gait.runpack.run","run_id":"run-demo"}`),
		"intents.jsonl": []byte(`{"schema_id":"gait.runpack.intent"}` + "\n"),
		"results.jsonl": []byte(`{"schema_id":"gait.runpack.result"}` + "\n"),
		"refs.json":     []byte(`{"schema_id":"gait.runpack.refs","receipts":[]}`),
	}

	entries := []RunpackFile{
		{Path: "run.json", SHA256: sha256Hex(files["run.json"])},
		{Path: "intents.jsonl", SHA256: sha256Hex(files["intents.jsonl"])},
		{Path: "results.jsonl", SHA256: sha256Hex(files["results.jsonl"])},
		{Path: "refs.json", SHA256: sha256Hex(files["refs.json"])},
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	manifest := RunpackManifest{
		SchemaID:      "gait.runpack.manifest",
		SchemaVersion: "1.0.0",
		RunID:         "run-demo",
		Files:         entries,
	}
	d, err := runpackManifestDigest(manifest)
	require.NoError(t, err)
	manifest.ManifestDigest = d
	manifest.Signatures = []Signature{{
		Alg:          "ed25519",
		KeyID:        signing.KeyID(pub),
		Sig:          signDigestHex(t, priv, d),
		SignedDigest: d,
	}}
	return pub, manifest, files
}

func writeRunpackZip(t *testing.T, manifest RunpackManifest, files map[string][]byte) string {
	t.Helper()
	manifestRaw, err := json.Marshal(manifest)
	require.NoError(t, err)

	archiveFiles := cloneFileMap(files)
	archiveFiles["manifest.json"] = manifestRaw

	path := filepath.Join(t.TempDir(), "runpack.zip")
	writeZip(t, path, archiveFiles)
	return path
}

func cloneFileMap(in map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[k] = append([]byte(nil), v...)
	}
	return out
}
