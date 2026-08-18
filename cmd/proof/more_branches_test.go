package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestDetectArtifactAndLoadChainBranches(t *testing.T) {
	dir := t.TempDir()
	kind, err := detectArtifact(dir)
	require.NoError(t, err)
	require.Equal(t, artifactChain, kind)

	p := filepath.Join(dir, "unknown.json")
	testutil.WriteFile(t, p, []byte(`{"x":1}`))
	_, err = detectArtifact(p)
	require.Error(t, err)

	chainFile := filepath.Join(dir, "chain.json")
	testutil.WriteFile(t, chainFile, []byte(`{`))
	_, err = loadChain(chainFile)
	require.Error(t, err)
}

func TestLoadChainFallbackAndJSONLError(t *testing.T) {
	dir := t.TempDir()
	c := proof.NewChain("fallback")
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 17, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	require.NoError(t, proof.AppendToChain(c, r))
	raw, _ := json.Marshal(c)
	testutil.WriteFile(t, filepath.Join(dir, "chain.json"), raw)

	loaded, err := loadChain(dir)
	require.NoError(t, err)
	require.Len(t, loaded.Records, 1)

	testutil.WriteFile(t, filepath.Join(dir, "bad.jsonl"), []byte("{not-json}\n"))
	_, err = loadChain(dir)
	require.Error(t, err)
}

func TestLoadChainMalformedJSONRecordFails(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(dir, "bad.json"), []byte("{not-json"))
	_, err := loadChain(dir)
	require.Error(t, err)
}

func TestBundleAndGaitHelperErrors(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(dir, "manifest.json"), []byte(`{"files":[{"path":"a.txt","sha256":"sha256:abcd"}]}`))
	testutil.WriteFile(t, filepath.Join(dir, "a.txt"), []byte("hello"))
	require.Error(t, verifyBundle(dir, false, "", proof.CosignVerifyOpts{}))

	_, err := verifyGaitPack(filepath.Join(dir, "missing.zip"), true, "", proof.CosignVerifyOpts{})
	require.Error(t, err)
	require.ErrorContains(t, verifyGaitSignedJSON(filepath.Join(dir, "x.json"), ""), "--public-key is required")
}

func TestVerifyCommandBranchErrors(t *testing.T) {
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 18, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)

	dir := t.TempDir()
	recordPath := filepath.Join(dir, "record.json")
	require.NoError(t, proof.WriteRecord(recordPath, r))

	testutil.WriteFile(t, filepath.Join(dir, "bad-revocations.json"), []byte(`{bad`))
	_, err = runCLIForTest(t, []string{"verify", "--revocation-list", filepath.Join(dir, "bad-revocations.json"), recordPath})
	require.Error(t, err)

	r.Integrity.RecordHash = "sha256:tampered"
	require.NoError(t, proof.WriteRecord(recordPath, r))
	_, err = runCLIForTest(t, []string{"verify", recordPath})
	require.Error(t, err)
}

func TestVerifyCommandBundleChainAndTypeFrameworkErrors(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(dir, "records.jsonl"), []byte("{}\n"))
	testutil.WriteFile(t, filepath.Join(dir, "manifest.json"), []byte(`{"files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}]}`))
	testutil.WriteFile(t, filepath.Join(dir, "chain.json"), []byte(`{"records":[{"record_id":"x","record_version":"1.0","timestamp":"2026-02-17T00:00:00Z","source":"a","source_product":"a","record_type":"decision","event":{"a":1},"controls":{},"metadata":{},"integrity":{"record_hash":"sha256:bad","previous_record_hash":""}}],"head_hash":"sha256:bad","record_count":1}`))

	_, err := runCLIForTest(t, []string{"verify", "--chain", dir})
	require.Error(t, err)

	_, err = runCLIForTest(t, []string{"types", "validate", filepath.Join(dir, "missing.schema.json")})
	require.Error(t, err)

	badSchema := filepath.Join(dir, "bad.schema.json")
	testutil.WriteFile(t, badSchema, []byte(`{"type":"not-a-valid-schema-root"}`))
	_, err = runCLIForTest(t, []string{"types", "validate", badSchema})
	require.Error(t, err)

	_, err = runCLIForTest(t, []string{"frameworks", "show", "not-a-framework"})
	require.Error(t, err)
}

func TestVerifyStrictRejectsTamperedChainMetadataInDirectory(t *testing.T) {
	dir := t.TempDir()
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 18, 2, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	require.NoError(t, proof.WriteRecord(filepath.Join(dir, "record.json"), r))
	testutil.WriteFile(t, filepath.Join(dir, "chain.json"), []byte(`{"record_count":2}`))

	_, err = runCLIForTest(t, []string{"verify", dir})
	require.NoError(t, err)

	_, err = runCLIForTest(t, []string{"verify", "--strict", dir})
	require.Error(t, err)
	require.ErrorContains(t, err, "record_count mismatch")
}

func TestInspectCommandBranchErrors(t *testing.T) {
	c := proof.NewChain("inspect-branches")
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 18, 1, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	require.NoError(t, proof.AppendToChain(c, r))

	raw, _ := json.Marshal(c)
	chainPath := filepath.Join(t.TempDir(), "chain.json")
	testutil.WriteFile(t, chainPath, raw)
	_, err = runCLIForTest(t, []string{"inspect", "--record", "missing-id", chainPath})
	require.Error(t, err)

	bundleDir := filepath.Join(t.TempDir(), "bundle")
	_, err = runCLIForTest(t, []string{"inspect", bundleDir})
	require.Error(t, err)
}
