package proof

import coreerr "github.com/Clyra-AI/proof/core/errors"

type ErrorKind = coreerr.Kind
type LibraryError = coreerr.Error

const (
	ErrorKindInvalidInput      = coreerr.KindInvalidInput
	ErrorKindValidation        = coreerr.KindValidation
	ErrorKindVerification      = coreerr.KindVerification
	ErrorKindDependencyMissing = coreerr.KindDependencyMissing
	ErrorKindInternal          = coreerr.KindInternal
)

func AsLibraryError(err error) (*LibraryError, bool) {
	return coreerr.As(err)
}
