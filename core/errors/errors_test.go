package errors

import (
	stdliberrors "errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAndOptions(t *testing.T) {
	err := New(
		KindValidation,
		"schema.invalid",
		"schema validation failed",
		WithField("event"),
		WithPath("v1/types/decision.schema.json"),
	)
	require.Error(t, err)

	typed, ok := As(err)
	require.True(t, ok)
	require.Equal(t, KindValidation, typed.Kind)
	require.Equal(t, "schema.invalid", typed.Code)
	require.Equal(t, "schema validation failed", typed.Message)
	require.Equal(t, "event", typed.Field)
	require.Equal(t, "v1/types/decision.schema.json", typed.Path)
	require.Equal(t, "schema validation failed", typed.Error())
}

func TestWrapAndUnwrap(t *testing.T) {
	root := stdliberrors.New("low-level failure")
	err := Wrap(KindInternal, "record.marshal", "marshal payload", root)
	require.Error(t, err)
	require.Equal(t, "marshal payload: low-level failure", err.Error())
	require.True(t, stdliberrors.Is(err, root))
}

func TestAsNotTyped(t *testing.T) {
	typed, ok := As(stdliberrors.New("plain"))
	require.False(t, ok)
	require.Nil(t, typed)
}

func TestNilErrorBehaviors(t *testing.T) {
	var typed *Error
	require.Equal(t, "<nil>", typed.Error())
	require.Nil(t, typed.Unwrap())
}

func TestErrorFallsBackToCauseMessage(t *testing.T) {
	root := stdliberrors.New("fallback")
	err := New(KindInternal, "x", "", WithCause(root))
	require.EqualError(t, err, "fallback")
}
