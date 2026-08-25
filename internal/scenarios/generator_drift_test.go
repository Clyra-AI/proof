//go:build scenario

package scenarios_test

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFixtureGeneratorsRejectSourceAndProjectionDrift(t *testing.T) {
	root := repoRootForGeneratorTest(t)
	checks := []struct {
		name   string
		source string
		dest   string
		script string
		mutate func(string) string
	}{
		{
			name:   "lifecycle source",
			source: filepath.Join(root, "scenarios", "proof", "action-contract-lifecycle-conformance", "source", "gait-v1.5.0"),
			script: "scripts/generate_lifecycle_fixture.go",
			mutate: func(root string) string {
				return filepath.Join(root, "successful-execution-effect-containment", "lifecycle.json")
			},
		},
		{
			name:   "lifecycle projection",
			source: filepath.Join(root, "scenarios", "proof", "action-contract-lifecycle-conformance", "source", "gait-v1.5.0"),
			script: "scripts/generate_lifecycle_fixture.go",
			mutate: func(root string) string {
				return filepath.Join(root, "normalized", "successful-execution-effect-containment", "records.jsonl")
			},
		},
		{
			name:   "gate source",
			source: filepath.Join(root, "scenarios", "proof", "action-contract-gate-conformance", "source", "gait-gate-v1"),
			script: "scripts/generate_gate_fixture.go",
			mutate: func(root string) string { return filepath.Join(root, "source", "approval-exact.json") },
		},
		{
			name:   "gate projection",
			source: filepath.Join(root, "scenarios", "proof", "action-contract-gate-conformance", "source", "gait-gate-v1", "normalized"),
			script: "scripts/generate_gate_fixture.go",
			mutate: func(root string) string { return filepath.Join(root, "approval-exact.json", "records.jsonl") },
		},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "fixture")
			if err := copyTree(tc.source, dest); err != nil {
				t.Fatal(err)
			}
			path := tc.mutate(dest)
			if err := appendFile(path, []byte("\n")); err != nil {
				t.Fatal(err)
			}
			args := []string{"run", tc.script, "--check", "--dest", dest}
			if tc.script == "scripts/generate_gate_fixture.go" {
				args = append(args, "--offline")
			}
			if err := runGenerator(t, root, args...); err == nil {
				t.Fatal("generator accepted drift")
			}
		})
	}
}

func repoRootForGeneratorTest(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func runGenerator(t *testing.T, root string, args ...string) error {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(t.TempDir(), "gocache"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func appendFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(data)
	return err
}

func copyTree(source, dest string) error {
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}
