package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestCLIVerifyChain(t *testing.T) {
	root := testutil.RepoRoot(t)
	bin := testutil.BuildBinary(t, root)

	c := proof.NewChain("cli-test")
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 10, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "scan_finding",
		Event:         map[string]any{"id": "f1"},
	})
	require.NoError(t, err)
	require.NoError(t, proof.AppendToChain(c, r))

	raw, _ := json.MarshalIndent(c, "", "  ")
	chainPath := filepath.Join(t.TempDir(), "chain.json")
	testutil.WriteFile(t, chainPath, raw)

	cmd := exec.Command(bin, "verify", chainPath)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "Chain intact")
}
