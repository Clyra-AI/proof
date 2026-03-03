package errors

import (
	stdliberrors "errors"
	"fmt"
	"strings"
)

// Kind classifies library errors for machine-readable handling.
type Kind string

const (
	KindInvalidInput      Kind = "invalid_input"
	KindValidation        Kind = "validation"
	KindVerification      Kind = "verification"
	KindDependencyMissing Kind = "dependency_missing"
	KindInternal          Kind = "internal"
)

// Error is a structured library error with optional field/path context.
type Error struct {
	Kind    Kind   `json:"kind"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
	Path    string `json:"path,omitempty"`

	cause error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := strings.TrimSpace(e.Message)
	switch {
	case message == "" && e.cause != nil:
		return e.cause.Error()
	case message == "":
		return string(e.Kind)
	case e.cause != nil:
		return fmt.Sprintf("%s: %v", message, e.cause)
	default:
		return message
	}
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type Option func(*Error)

func WithField(field string) Option {
	return func(e *Error) {
		e.Field = strings.TrimSpace(field)
	}
}

func WithPath(path string) Option {
	return func(e *Error) {
		e.Path = strings.TrimSpace(path)
	}
}

func WithCause(err error) Option {
	return func(e *Error) {
		e.cause = err
	}
}

func New(kind Kind, code, message string, opts ...Option) error {
	e := &Error{
		Kind:    kind,
		Code:    strings.TrimSpace(code),
		Message: strings.TrimSpace(message),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	return e
}

func Wrap(kind Kind, code, message string, cause error, opts ...Option) error {
	opts = append(opts, WithCause(cause))
	return New(kind, code, message, opts...)
}

func As(err error) (*Error, bool) {
	var out *Error
	if stdliberrors.As(err, &out) {
		return out, true
	}
	return nil, false
}
