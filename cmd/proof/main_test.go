package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMainCallsExitWithRunCode(t *testing.T) {
	origArgs := os.Args
	origExitFn := exitFn
	defer func() {
		os.Args = origArgs
		exitFn = origExitFn
	}()

	os.Args = []string{"proof", "--version"}
	got := -1
	exitFn = func(code int) { got = code }

	main()
	require.Equal(t, 0, got)
}

func TestRunVersion(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"proof", "--version"}
	code := run(os.Stderr)
	require.Equal(t, 0, code)
}

func TestRunInvalidArgs(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"proof", "verify"}
	code := run(os.Stderr)
	require.NotEqual(t, 0, code)
}
