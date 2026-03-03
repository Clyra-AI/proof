package main

import (
	"github.com/Clyra-AI/proof"
	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/Clyra-AI/proof/core/exitcode"
)

type cliError struct {
	code int
	msg  string
}

func (e cliError) Error() string { return e.msg }
func (e cliError) ExitCode() int { return e.code }

func newCLIError(code int, msg string) error {
	return cliError{code: code, msg: msg}
}

func verificationErrorCode(err error) int {
	if typed, ok := coreerr.As(err); ok {
		switch typed.Kind {
		case coreerr.KindDependencyMissing:
			return exitcode.DependencyMiss
		case coreerr.KindInvalidInput:
			return exitcode.InvalidInput
		case coreerr.KindValidation:
			return exitcode.PolicyOrSchema
		case coreerr.KindVerification:
			return exitcode.VerificationErr
		}
	}
	if proof.IsDependencyMissing(err) {
		return exitcode.DependencyMiss
	}
	return exitcode.VerificationErr
}
