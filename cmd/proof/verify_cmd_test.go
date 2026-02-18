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
}
