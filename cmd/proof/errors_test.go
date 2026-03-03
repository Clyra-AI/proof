package main

import (
	"testing"

	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/Clyra-AI/proof/core/exitcode"
	"github.com/stretchr/testify/require"
)

func TestCLIErrorExitCode(t *testing.T) {
	err := newCLIError(6, "bad")
	ec, ok := err.(interface{ ExitCode() int })
	require.True(t, ok)
	require.Equal(t, 6, ec.ExitCode())
	require.Equal(t, "bad", err.Error())
}

func TestVerificationErrorCodeFromTypedError(t *testing.T) {
	require.Equal(t, exitcode.InvalidInput, verificationErrorCode(coreerr.New(coreerr.KindInvalidInput, "x", "bad input")))
	require.Equal(t, exitcode.PolicyOrSchema, verificationErrorCode(coreerr.New(coreerr.KindValidation, "x", "bad schema")))
	require.Equal(t, exitcode.VerificationErr, verificationErrorCode(coreerr.New(coreerr.KindVerification, "x", "bad signature")))
	require.Equal(t, exitcode.DependencyMiss, verificationErrorCode(coreerr.New(coreerr.KindDependencyMissing, "x", "missing dep")))
}
