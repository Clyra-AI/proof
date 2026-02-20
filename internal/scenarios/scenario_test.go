//go:build scenario

package scenarios_test

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/internal/testutil"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type expectedInput struct {
	File     string `yaml:"file"`
	ExitCode int    `yaml:"exit_code"`
}

type expectedScenario struct {
	Verify        string          `yaml:"verify"`
	Count         int             `yaml:"count"`
	Chain         string          `yaml:"chain"`
	BreakPoint    int             `yaml:"break_point"`
	Sign          string          `yaml:"sign"`
	Algorithm     string          `yaml:"algorithm"`
	Total         int             `yaml:"total"`
	Sources       []string        `yaml:"sources"`
	InvalidInputs []expectedInput `yaml:"invalid_inputs"`
}

func TestScenarios(t *testing.T) {
	root := testutil.RepoRoot(t)
	scenarioDir := filepath.Join(root, "scenarios", "proof")

	entries, err := os.ReadDir(scenarioDir)
	if err != nil {
		t.Fatalf("read scenario dir: %v", err)
	}

	binary := testutil.BuildBinary(t, root)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join(scenarioDir, entry.Name())
			runScenario(t, binary, dir)
		})
	}
}

func runScenario(t *testing.T, binary, dir string) {
	t.Helper()
	expected := loadExpected(t, filepath.Join(dir, "expected.yaml"))
	name := filepath.Base(dir)

	switch name {
	case "chain-round-trip":
		require.Equal(t, "pass", expected.Verify)
		require.Equal(t, "intact", expected.Chain)
		out, code := runProof(binary, "verify", dir)
		require.Equal(t, 0, code, out)
		require.Contains(t, out, "Chain intact")
		require.Contains(t, out, strconv.Itoa(expected.Count)+" records")

	case "compiled-action-chain-round-trip":
		require.Equal(t, "pass", expected.Verify)
		require.Equal(t, "intact", expected.Chain)
		out, code := runProof(binary, "verify", dir)
		require.Equal(t, 0, code, out)
		require.Contains(t, out, "Chain intact")
		require.Contains(t, out, strconv.Itoa(expected.Count)+" records")

	case "chain-tamper-detection":
		require.Equal(t, "fail", expected.Verify)
		tempDir := t.TempDir()
		copyFile(t, filepath.Join(dir, "tamper-record-5.jsonl"), filepath.Join(tempDir, "records.jsonl"))
		out, code := runProof(binary, "verify", tempDir)
		require.Equal(t, 2, code, out)
		require.Contains(t, out, "chain verification failed at index")
		if expected.BreakPoint > 0 {
			re := regexp.MustCompile(`index ([0-9]+)`)
			match := re.FindStringSubmatch(out)
			require.Len(t, match, 2, "missing break index in output: %s", out)
			index, err := strconv.Atoi(match[1])
			require.NoError(t, err)
			require.Equal(t, expected.BreakPoint, index+1)
		}

	case "signing-verify-round-trip":
		require.Equal(t, "success", expected.Sign)
		require.Equal(t, "pass", expected.Verify)
		require.Equal(t, "ed25519", expected.Algorithm)
		recordPath := filepath.Join(dir, "input-record.json")
		r, err := proof.ReadRecord(recordPath)
		require.NoError(t, err)
		key, err := proof.GenerateSigningKey()
		require.NoError(t, err)
		_, err = proof.Sign(r, key)
		require.NoError(t, err)
		require.NotEmpty(t, r.Integrity.SigningKeyID)
		require.True(t, strings.HasPrefix(r.Integrity.Signature, "base64:"))
		signedPath := filepath.Join(t.TempDir(), "signed-record.json")
		require.NoError(t, proof.WriteRecord(signedPath, r))
		out, code := runProof(binary, "verify", "--signatures", "--public-key", hex.EncodeToString(key.Public), signedPath)
		require.Equal(t, 0, code, out)
		require.Contains(t, out, "Record verified")

	case "schema-validation-reject":
		require.NotEmpty(t, expected.InvalidInputs)
		for _, tc := range expected.InvalidInputs {
			out, code := runProof(binary, "verify", filepath.Join(dir, tc.File))
			require.Equalf(t, tc.ExitCode, code, "file=%s output=%s", tc.File, out)
		}

	case "cross-product-mixed-chain":
		require.Equal(t, "pass", expected.Verify)
		out, code := runProof(binary, "verify", dir)
		require.Equal(t, 0, code, out)
		require.Contains(t, out, "Chain intact")
		require.Contains(t, out, strconv.Itoa(expected.Total)+" records")
		foundSources := readSources(t,
			filepath.Join(dir, "axym-records.jsonl"),
			filepath.Join(dir, "gait-records.jsonl"),
			filepath.Join(dir, "wrkr-records.jsonl"),
		)
		for _, source := range expected.Sources {
			_, ok := foundSources[source]
			require.Truef(t, ok, "expected source %s not present", source)
		}

	default:
		t.Fatalf("unsupported scenario: %s", name)
	}
}

func loadExpected(t *testing.T, path string) expectedScenario {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var expected expectedScenario
	require.NoError(t, yaml.Unmarshal(raw, &expected))
	return expected
}

func runProof(binary string, args ...string) (string, int) {
	cmd := exec.Command(binary, args...) // #nosec G204 -- test harness executes fixed binary with fixture args.
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return string(out), 1
	}
	return string(out), exitErr.ExitCode()
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	require.NoError(t, err)
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()
	_, err = io.Copy(out, in)
	require.NoError(t, err)
}

func readSources(t *testing.T, paths ...string) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	for _, path := range paths {
		f, err := os.Open(path)
		require.NoError(t, err)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var record proof.Record
			require.NoError(t, json.Unmarshal([]byte(line), &record))
			out[record.Source] = struct{}{}
		}
		require.NoError(t, scanner.Err())
		_ = f.Close()
	}
	return out
}
