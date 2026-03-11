package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepoRoot(t *testing.T) {
	root := RepoRoot(t)
	require.NotEmpty(t, root)
	_, err := os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, err)
}

func TestWriteFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a", "b", "c.txt")
	WriteFile(t, p, []byte("ok"))
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, "ok", string(b))
}

func TestBuildBinaryAndExitCode(t *testing.T) {
	root := RepoRoot(t)
	bin := BuildBinary(t, root)
	binAgain := BuildBinary(t, root)
	_, err := os.Stat(bin)
	require.NoError(t, err)
	require.Equal(t, bin, binAgain)

	cmd := exec.Command("sh", "-c", "exit 7")
	err = cmd.Run()
	require.Equal(t, 7, CommandExitCode(t, err))
	require.Equal(t, 0, CommandExitCode(t, nil))
}
