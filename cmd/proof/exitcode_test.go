package main

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/internal/testutil"
	"github.com/stretchr/testify/require"
)

func TestExitCodeInvalidInput(t *testing.T) {
	root := testutil.RepoRoot(t)
	bin := testutil.BuildBinary(t, root)

	cmd := exec.Command(bin, "verify", "/does/not/exist")
	_, err := cmd.CombinedOutput()
	require.Equal(t, 6, testutil.CommandExitCode(t, err))
}

func TestExitCodeVerificationFailure(t *testing.T) {
	root := testutil.RepoRoot(t)
	bin := testutil.BuildBinary(t, root)

	dir := t.TempDir()
	r, err := proof.NewRecord(proof.RecordOpts{
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	// Tamper hash intentionally to force verification failure.
	r.Integrity.RecordHash = "sha256:deadbeef"
	require.NoError(t, proof.WriteRecord(filepath.Join(dir, "record.json"), r))

	cmd := exec.Command(bin, "verify", filepath.Join(dir, "record.json"))
	_, err = cmd.CombinedOutput()
	require.Equal(t, 2, testutil.CommandExitCode(t, err))
}
