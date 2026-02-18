package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/proof"
	"github.com/stretchr/testify/require"
)

func TestTypesListCommand(t *testing.T) {
	out, err := runCLIForTest(t, []string{"types", "list", "--json"})
	require.NoError(t, err)
	require.Contains(t, out, "tool_invocation")
}

func TestFrameworksListCommand(t *testing.T) {
	out, err := runCLIForTest(t, []string{"frameworks", "list"})
	require.NoError(t, err)
	require.Contains(t, out, "eu-ai-act")
}

func TestInspectRecordCommand(t *testing.T) {
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "record.json")
	require.NoError(t, proof.WriteRecord(p, r))

	out, err := runCLIForTest(t, []string{"inspect", p})
	require.NoError(t, err)
	require.Contains(t, out, "record_id")
}

func TestVerifyRecordCommand(t *testing.T) {
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "record.json")
	require.NoError(t, proof.WriteRecord(p, r))

	out, err := runCLIForTest(t, []string{"verify", p})
	require.NoError(t, err)
	require.Contains(t, out, "Record verified")
}

func runCLIForTest(t *testing.T, args []string) (string, error) {
	t.Helper()
	cmd := newRootCmd("test")
	cmd.SetArgs(args)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := cmd.Execute()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String(), err
}
