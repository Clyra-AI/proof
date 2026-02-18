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

func TestTypesValidateCommand(t *testing.T) {
	schema := `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`
	p := filepath.Join(t.TempDir(), "custom.schema.json")
	testutil.WriteFile(t, p, []byte(schema))

	out, err := runCLIForTest(t, []string{"types", "validate", p})
	require.NoError(t, err)
	require.Contains(t, out, "Schema is valid")
}

func TestChainVerifyInvalidDate(t *testing.T) {
	c := proof.NewChain("chain-1")
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	require.NoError(t, proof.AppendToChain(c, r))
	raw, _ := json.Marshal(c)
	p := filepath.Join(t.TempDir(), "chain.json")
	testutil.WriteFile(t, p, raw)

	_, err = runCLIForTest(t, []string{"chain", "verify", "--from", "bad-date", p})
	require.Error(t, err)
}

func TestFrameworkShowCommand(t *testing.T) {
	out, err := runCLIForTest(t, []string{"frameworks", "show", "eu-ai-act", "--json"})
	require.NoError(t, err)
	require.Contains(t, out, "eu-ai-act")
}
