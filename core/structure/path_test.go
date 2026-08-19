package structure

import (
	"testing"

	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/stretchr/testify/require"
)

func TestValidateListedPaths(t *testing.T) {
	paths, err := ValidateListedPaths([]string{"records/one.json", "records/two.json"})
	require.NoError(t, err)
	require.Contains(t, paths, "records/one.json")
	require.Contains(t, paths, "records/two.json")
}

func TestValidateListedPathsRejectsAmbiguityAndDuplicates(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		code  string
	}{
		{name: "empty", paths: []string{""}, code: ErrorCodePathInvalid},
		{name: "absolute", paths: []string{"/tmp/file"}, code: ErrorCodePathInvalid},
		{name: "windows absolute", paths: []string{"C:/tmp/file"}, code: ErrorCodePathInvalid},
		{name: "escape", paths: []string{"../file"}, code: ErrorCodePathInvalid},
		{name: "dot segment", paths: []string{"./file"}, code: ErrorCodePathAmbiguous},
		{name: "backslash", paths: []string{`dir\file`}, code: ErrorCodePathAmbiguous},
		{name: "uppercase alias", paths: []string{"File.json"}, code: ErrorCodePathAmbiguous},
		{name: "trailing dot alias", paths: []string{"file."}, code: ErrorCodePathAmbiguous},
		{name: "trailing space alias", paths: []string{"file "}, code: ErrorCodePathAmbiguous},
		{name: "duplicate", paths: []string{"file", "file"}, code: ErrorCodePathDuplicate},
		{name: "duplicate normalized", paths: []string{"file", "./file"}, code: ErrorCodePathDuplicate},
		{name: "duplicate portable alias", paths: []string{"file", "FILE"}, code: ErrorCodePathDuplicate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateListedPaths(tt.paths)
			require.Error(t, err)
			typed, ok := coreerr.As(err)
			require.True(t, ok)
			require.Equal(t, tt.code, typed.Code)
		})
	}
}

func TestValidateArchivePathsAcceptsCanonicalDirectoriesAndRejectsCollisions(t *testing.T) {
	paths, err := ValidateArchivePaths([]string{"payload/", "payload/file.json"})
	require.NoError(t, err)
	require.Contains(t, paths, "payload")
	require.Contains(t, paths, "payload/file.json")

	_, err = ValidateArchivePaths([]string{"payload/", "payload"})
	require.Error(t, err)
	typed, ok := coreerr.As(err)
	require.True(t, ok)
	require.Equal(t, ErrorCodePathDuplicate, typed.Code)
}

func TestStructuralErrorsAreTyped(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
	}{
		{err: UnlistedFileError("extra.json"), code: ErrorCodeUnlistedFile},
		{err: SymlinkAmbiguityError("link.json"), code: ErrorCodeSymlinkAmbiguous},
	} {
		typed, ok := coreerr.As(test.err)
		require.True(t, ok)
		require.Equal(t, coreerr.KindVerification, typed.Kind)
		require.Equal(t, test.code, typed.Code)
	}
}

func TestValidateObservedPaths(t *testing.T) {
	key, err := ValidatePath("records/one.json")
	require.NoError(t, err)
	require.Equal(t, "records/one.json", key)
	key, err = ValidateArchivePath("payload/", true)
	require.NoError(t, err)
	require.Equal(t, "payload", key)
	_, err = ValidatePath("./records/one.json")
	require.Error(t, err)
	_, err = ValidateArchivePath("payload", false)
	require.NoError(t, err)
}
