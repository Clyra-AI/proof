package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

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

func TestExitCodeRevokedKeyFailure(t *testing.T) {
	root := testutil.RepoRoot(t)
	bin := testutil.BuildBinary(t, root)

	dir := t.TempDir()
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 13, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	key, err := proof.GenerateSigningKey()
	require.NoError(t, err)
	_, err = proof.Sign(r, key)
	require.NoError(t, err)
	recordPath := filepath.Join(dir, "record.json")
	require.NoError(t, proof.WriteRecord(recordPath, r))

	revList, err := proof.SignRevocationList(proof.RevocationList{
		Version:   "1.0",
		CreatedAt: "2026-02-17T13:10:00Z",
		Revoked: []proof.RevocationEntry{
			{KeyID: r.Integrity.SigningKeyID, RevokedAt: "2026-02-17T12:59:00Z", Reason: "retired"},
		},
	}, key)
	require.NoError(t, err)
	rlPath := filepath.Join(dir, "revocations.json")
	raw, _ := json.MarshalIndent(revList, "", "  ")
	testutil.WriteFile(t, rlPath, raw)

	cmd := exec.Command(bin, "verify", "--revocation-list", rlPath, recordPath)
	_, err = cmd.CombinedOutput()
	require.Equal(t, 2, testutil.CommandExitCode(t, err))
}

func TestExitCodeDependencyMissing(t *testing.T) {
	root := testutil.RepoRoot(t)
	bin := testutil.BuildBinary(t, root)

	dir := t.TempDir()
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	r.Integrity.Signature = "cosign:ZmFrZXNpZw=="
	r.Integrity.SigningKeyID = "cosign:test-key"
	recordPath := filepath.Join(dir, "record.json")
	require.NoError(t, proof.WriteRecord(recordPath, r))

	cmd := exec.Command(bin, "verify", "--signatures", "--cosign-key", filepath.Join(dir, "cosign.pub"), recordPath)
	cmd.Env = append(os.Environ(), "PATH="+t.TempDir())
	_, err = cmd.CombinedOutput()
	require.Equal(t, 7, testutil.CommandExitCode(t, err))
}
