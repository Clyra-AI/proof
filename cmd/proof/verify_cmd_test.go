package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestVerifyCommandRecordAndChainAndBundle(t *testing.T) {
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 15, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)

	dir := t.TempDir()
	recordPath := filepath.Join(dir, "record.json")
	require.NoError(t, proof.WriteRecord(recordPath, r))

	out, err := runCLIForTest(t, []string{"verify", recordPath})
	require.NoError(t, err)
	require.Contains(t, out, "Record verified")

	c := proof.NewChain("test")
	require.NoError(t, proof.AppendToChain(c, r))
	chainPath := filepath.Join(dir, "chain.json")
	raw, _ := json.Marshal(c)
	testutil.WriteFile(t, chainPath, raw)
	out, err = runCLIForTest(t, []string{"verify", chainPath})
	require.NoError(t, err)
	require.Contains(t, out, "Chain intact")

	bundleDir := filepath.Join(dir, "bundle")
	testutil.WriteFile(t, filepath.Join(bundleDir, "records.jsonl"), []byte("{}\n"))
	testutil.WriteFile(t, filepath.Join(bundleDir, "manifest.json"), []byte(`{"files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}]}`))
	out, err = runCLIForTest(t, []string{"verify", bundleDir})
	require.NoError(t, err)
	require.Contains(t, out, "Bundle verified")
}

func TestVerifyCommandErrorPaths(t *testing.T) {
	_, err := runCLIForTest(t, []string{"verify", "/missing"})
	require.Error(t, err)

	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 15, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "record.json")
	require.NoError(t, proof.WriteRecord(p, r))
	_, err = runCLIForTest(t, []string{"verify", "--signatures", p})
	require.Error(t, err)

	chainDir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(chainDir, "bad.json"), []byte("{not-json"))
	_, err = runCLIForTest(t, []string{"verify", chainDir})
	require.Error(t, err)
}

func TestVerifyBundleWithManifestSignature(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(dir, "records.jsonl"), []byte("{}\n"))
	testutil.WriteFile(t, filepath.Join(dir, "manifest.json"), []byte(`{"files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}]}`))

	key, err := proof.GenerateSigningKey()
	require.NoError(t, err)
	_, err = proof.SignBundleFile(dir, key)
	require.NoError(t, err)

	out, err := runCLIForTest(t, []string{"verify", "--bundle", "--signatures", "--public-key", hex.EncodeToString(key.Public), dir})
	require.NoError(t, err)
	require.Contains(t, out, "Bundle verified")
}

func TestVerifyCustomTypeSchemaMapping(t *testing.T) {
	proof.ResetCustomTypes()
	t.Cleanup(proof.ResetCustomTypes)

	schemaPath := filepath.Join(t.TempDir(), "custom-type.schema.json")
	require.NoError(t, os.WriteFile(schemaPath, []byte(`{
	  "$schema":"http://json-schema.org/draft-07/schema#",
	  "type":"object",
	  "required":["record_type","event"],
	  "properties":{
	    "record_type":{"const":"vendor.custom_event"},
	    "event":{"type":"object","required":["custom_value"],"properties":{"custom_value":{"type":"string"}}}
	  }
	}`), 0o644))

	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 15, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	r.RecordType = "vendor.custom_event"
	r.Event = map[string]any{"custom_value": "ok"}
	hash, err := proof.ComputeRecordHash(r)
	require.NoError(t, err)
	r.Integrity.RecordHash = hash

	recordPath := filepath.Join(t.TempDir(), "custom-record.json")
	require.NoError(t, proof.WriteRecord(recordPath, r))

	out, err := runCLIForTest(t, []string{"verify", "--custom-type-schema", "vendor.custom_event=" + schemaPath, recordPath})
	require.NoError(t, err)
	require.Contains(t, out, "Record verified")
}

func TestVerifyExplainFlag(t *testing.T) {
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 15, 30, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	recordPath := filepath.Join(t.TempDir(), "record.json")
	require.NoError(t, proof.WriteRecord(recordPath, r))

	out, err := runCLIForTest(t, []string{"verify", "--explain", recordPath})
	require.NoError(t, err)
	require.Contains(t, out, "Record verified")
}
