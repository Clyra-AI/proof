package exitcode

const (
	Success         = 0
	InternalError   = 1
	VerificationErr = 2
	PolicyOrSchema  = 3
	ApprovalReq     = 4
	RegressionDrift = 5
	InvalidInput    = 6
	DependencyMiss  = 7
	UnsafeBlocked   = 8
)
