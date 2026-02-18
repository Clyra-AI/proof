package exitcode

import core "github.com/Clyra-AI/proof/core/exitcode"

const (
	Success         = core.Success
	InternalError   = core.InternalError
	VerificationErr = core.VerificationErr
	PolicyOrSchema  = core.PolicyOrSchema
	ApprovalReq     = core.ApprovalReq
	RegressionDrift = core.RegressionDrift
	InvalidInput    = core.InvalidInput
	DependencyMiss  = core.DependencyMiss
	UnsafeBlocked   = core.UnsafeBlocked
)

// Compatibility aliases for clients migrating from legacy CLI constants.
const (
	OK                  = Success
	InternalFailure     = InternalError
	VerificationFailure = VerificationErr
	PolicyBlocked       = PolicyOrSchema
	ApprovalRequired    = ApprovalReq
	RegressionFailed    = RegressionDrift
	MissingDependency   = DependencyMiss
	UnsafeReplay        = UnsafeBlocked
)
