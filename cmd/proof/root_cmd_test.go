package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/proof"
	"github.com/spf13/cobra"
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

func TestRunCommandForTestDrainsLargeStdout(t *testing.T) {
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprint(os.Stdout, strings.Repeat("x", 1024*1024))
			return err
		},
	}

	out, err := runCommandForTest(t, cmd, nil)
	require.NoError(t, err)
	require.Len(t, out, 1024*1024)
}

func runCLIForTest(t *testing.T, args []string) (string, error) {
	t.Helper()
	cmd := newRootCmd("test")
	return runCommandForTest(t, cmd, args)
}

func runCommandForTest(t *testing.T, cmd *cobra.Command, args []string) (string, error) {
	t.Helper()
	cmd.SetArgs(args)

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	var buf bytes.Buffer
	copyDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(&buf, r)
		copyDone <- copyErr
	}()

	err = cmd.Execute()

	_ = w.Close()
	require.NoError(t, <-copyDone)
	_ = r.Close()
	return buf.String(), err
}
