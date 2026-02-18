package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCLIErrorExitCode(t *testing.T) {
	err := newCLIError(6, "bad")
	ec, ok := err.(interface{ ExitCode() int })
	require.True(t, ok)
	require.Equal(t, 6, ec.ExitCode())
	require.Equal(t, "bad", err.Error())
}
