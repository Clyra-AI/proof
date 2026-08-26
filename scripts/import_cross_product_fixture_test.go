package scripts_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Clyra-AI/proof/internal/fixtureimport"
)

func TestImportCrossProductFixtureExitContract(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	binaryName := "import-cross-product-fixture"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binary := filepath.Join(t.TempDir(), binaryName)
	build := exec.Command("go", "build", "-o", binary, "./scripts/import_cross_product_fixture.go")
	build.Dir = root
	build.Env = append(os.Environ(), "GOCACHE="+filepath.Join(t.TempDir(), "build-cache"))
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build importer: %v: %s", err, output)
	}
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "invalid invocation", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--update"}, want: 6},
		{name: "unexpected positional argument", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--check", "unexpected"}, want: 6},
		{name: "unknown flag with json", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--bogus", "--json"}, want: 6},
		{name: "unknown flag with single dash json", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--bogus", "-json"}, want: 6},
		{name: "unknown flag with true assignment 1", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--bogus", "-json=1"}, want: 6},
		{name: "unknown flag with true assignment t", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--bogus", "--json=t"}, want: 6},
		{name: "unknown flag with true assignment T", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--bogus", "-json=T"}, want: 6},
		{name: "unknown flag with true assignment TRUE", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--bogus", "--json=TRUE"}, want: 6},
		{name: "unknown flag with true assignment true", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--bogus", "-json=true"}, want: 6},
		{name: "unknown flag with true assignment True", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--bogus", "--json=True"}, want: 6},
		{name: "empty destination", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--check", "--dest="}, want: 6},
		{name: "invalid contract", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--update", "--source", t.TempDir(), "--contract", filepath.Join(t.TempDir(), "contract.json")}, want: 6},
		{name: "missing contract runtime failure", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--update", "--source", t.TempDir(), "--contract", filepath.Join(t.TempDir(), "missing-contract.json")}, want: 1},
		{name: "contract nonregular unsafe failure", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--update", "--source", t.TempDir(), "--contract", t.TempDir()}, want: 8},
		{name: "check drift", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--check", "--dest", t.TempDir()}, want: 2},
		{name: "check missing required file", args: []string{"run", "./scripts/import_cross_product_fixture.go", "--check", "--dest", t.TempDir()}, want: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "invalid contract" {
				contractPath := tc.args[len(tc.args)-1]
				if err := os.WriteFile(contractPath, []byte(`{"format":"bad"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "check drift" {
				dest := tc.args[len(tc.args)-1]
				if err := os.MkdirAll(dest, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dest, fixtureimport.ManagedMarker), []byte(fixtureimport.ManagedContent), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(dest, "provenance"), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dest, fixtureimport.ContractPath), []byte(`{"format":"invalid"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "check missing required file" {
				dest := tc.args[len(tc.args)-1]
				if err := os.MkdirAll(dest, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dest, fixtureimport.ManagedMarker), []byte(fixtureimport.ManagedContent), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := tc.args[2:]
			cmdArgs := append([]string{"--json"}, args...)
			if tc.name == "unknown flag with json" || tc.name == "unknown flag with single dash json" || strings.HasPrefix(tc.name, "unknown flag with true assignment") {
				cmdArgs = args
			}
			cmd := exec.Command(binary, cmdArgs...)
			cmd.Dir = root
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("command succeeded, want exit %d", tc.want)
			}
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != tc.want {
				t.Fatalf("exit=%v, want %d", err, tc.want)
			}
			var envelope struct {
				OK      bool           `json:"ok"`
				Command string         `json:"command"`
				Error   map[string]any `json:"error"`
			}
			if decodeErr := json.Unmarshal(output, &envelope); decodeErr != nil || envelope.OK || envelope.Command != "import_cross_product_fixture" || envelope.Error["reason"] == nil {
				t.Fatalf("unstable JSON error shape: %s (%v)", output, decodeErr)
			}
		})
	}
}

func TestLegacyFixtureGeneratorsRequireSourceWithExit6(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"./scripts/generate_gate_fixture.go", "./scripts/generate_lifecycle_fixture.go"} {
		t.Run(source, func(t *testing.T) {
			name := "fixture-generator"
			if runtime.GOOS == "windows" {
				name += ".exe"
			}
			binary := filepath.Join(t.TempDir(), name)
			build := exec.Command("go", "build", "-o", binary, source)
			build.Dir = root
			build.Env = append(os.Environ(), "GOCACHE="+filepath.Join(t.TempDir(), "build-cache"))
			if output, buildErr := build.CombinedOutput(); buildErr != nil {
				t.Fatalf("build generator: %v: %s", buildErr, output)
			}
			cmd := exec.Command(binary, "--update")
			cmd.Dir = root
			if runErr := cmd.Run(); runErr == nil {
				t.Fatal("generator accepted missing source")
			} else if exitErr, ok := runErr.(*exec.ExitError); !ok || exitErr.ExitCode() != 6 {
				t.Fatalf("exit=%v, want 6", runErr)
			}
		})
	}
}
