//go:build !windows

package fixtureimport

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadContractFileRejectsNamedPipeBeforeOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contract.pipe")
	require.NoError(t, syscall.Mkfifo(path, 0o600))
	var unsafeErr *UnsafeError
	_, err := ReadContractFile(path)
	require.ErrorAs(t, err, &unsafeErr)
}
