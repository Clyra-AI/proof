package main

import (
	"bytes"
	"encoding/json"
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
	require.Contains(t, out, "built-in starter frameworks")
}

func TestFrameworksShowByPathCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-framework.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
framework:
  id: custom-framework
  version: "1"
  title: Custom Framework
controls:
  - id: custom-control
    title: Custom Control
    required_record_types: [decision]
    required_fields: [record_id]
    minimum_frequency: continuous
`), 0o644))

	out, err := runCLIForTest(t, []string{"frameworks", "show", path, "--json"})
	require.NoError(t, err)
	require.Contains(t, out, `"id": "custom-framework"`)
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

func TestInspectChainAndBundleCommands(t *testing.T) {
	c := proof.NewChain("inspect-chain")
	r, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	require.NoError(t, proof.AppendToChain(c, r))
	chainPath := filepath.Join(t.TempDir(), "chain.json")
	raw, _ := json.Marshal(c)
	require.NoError(t, os.WriteFile(chainPath, raw, 0o644))

	out, err := runCLIForTest(t, []string{"inspect", chainPath, "--record", c.Records[0].RecordID})
	require.NoError(t, err)
	require.Contains(t, out, c.Records[0].RecordID)

	bundleDir := filepath.Join(t.TempDir(), "bundle")
	require.NoError(t, os.MkdirAll(bundleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bundleDir, "manifest.json"), []byte(`{"files":[]}`), 0o644))
	out, err = runCLIForTest(t, []string{"inspect", bundleDir})
	require.NoError(t, err)
	require.Contains(t, out, "\"files\"")
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
