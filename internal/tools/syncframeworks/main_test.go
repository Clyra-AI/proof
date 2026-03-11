package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type exitPanic struct {
	code int
}

func restoreGlobals() {
	repoRootFunc = repoRoot
	syncFrameworksFunc = syncFrameworks
	runFunc = run
	exitFunc = os.Exit
	stderrWriter = os.Stderr
}

func TestRunUsesRepoRoot(t *testing.T) {
	t.Cleanup(restoreGlobals)

	tempRoot := t.TempDir()
	repoRootFunc = func() (string, error) {
		return tempRoot, nil
	}

	called := false
	syncFrameworksFunc = func(srcDir, dstDir string) error {
		called = true
		require.Equal(t, filepath.Join(tempRoot, "core", "framework"), srcDir)
		require.Equal(t, filepath.Join(tempRoot, "frameworks"), dstDir)
		return nil
	}

	require.NoError(t, run())
	require.True(t, called)
}

func TestRunPropagatesRepoRootError(t *testing.T) {
	t.Cleanup(restoreGlobals)

	repoRootFunc = func() (string, error) {
		return "", errors.New("no root")
	}

	err := run()
	require.EqualError(t, err, "no root")
}

func TestMainCallsFailOnRunError(t *testing.T) {
	t.Cleanup(restoreGlobals)

	runFunc = func() error {
		return errors.New("boom")
	}

	var stderr bytes.Buffer
	stderrWriter = &stderr
	exitFunc = func(code int) {
		panic(exitPanic{code: code})
	}

	require.PanicsWithValue(t, exitPanic{code: 1}, func() {
		main()
	})
	require.Equal(t, "sync frameworks: boom\n", stderr.String())
}

func TestRepoRoot(t *testing.T) {
	root, err := repoRoot()
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, err)
	require.False(t, info.IsDir())
}

func TestCopyFile(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "soc2.yaml"), []byte("framework: soc2\n"), 0o644))

	require.NoError(t, copyFile(srcDir, dstDir, "soc2.yaml"))

	raw, err := os.ReadFile(filepath.Join(dstDir, "soc2.yaml"))
	require.NoError(t, err)
	require.Equal(t, "framework: soc2\n", string(raw))
}

func TestSyncFrameworksCopiesAndRemovesYAML(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "soc2.yaml"), []byte("soc2"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "notes.txt"), []byte("ignore"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dstDir, "old.yaml"), []byte("stale"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dstDir, "keep.txt"), []byte("keep"), 0o644))

	require.NoError(t, syncFrameworks(srcDir, dstDir))

	raw, err := os.ReadFile(filepath.Join(dstDir, "soc2.yaml"))
	require.NoError(t, err)
	require.Equal(t, "soc2", string(raw))

	_, err = os.Stat(filepath.Join(dstDir, "old.yaml"))
	require.ErrorIs(t, err, os.ErrNotExist)

	raw, err = os.ReadFile(filepath.Join(dstDir, "keep.txt"))
	require.NoError(t, err)
	require.Equal(t, "keep", string(raw))

	_, err = os.Stat(filepath.Join(dstDir, "notes.txt"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestSyncFrameworksMissingSourceDir(t *testing.T) {
	err := syncFrameworks(filepath.Join(t.TempDir(), "missing"), t.TempDir())
	require.Error(t, err)
}

func TestCopyFileErrors(t *testing.T) {
	t.Run("missing source file", func(t *testing.T) {
		err := copyFile(t.TempDir(), t.TempDir(), "missing.yaml")
		require.Error(t, err)
	})

	t.Run("missing destination dir", func(t *testing.T) {
		srcDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "soc2.yaml"), []byte("soc2"), 0o644))

		err := copyFile(srcDir, filepath.Join(t.TempDir(), "missing"), "soc2.yaml")
		require.Error(t, err)
	})
}
