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
