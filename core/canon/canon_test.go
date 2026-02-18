package canon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalizeSQLDeterministic(t *testing.T) {
	inA := []byte(" SELECT  *  FROM payments ; ")
	inB := []byte("select * from payments")
	a, err := Canonicalize(inA, DomainSQL)
	require.NoError(t, err)
	b, err := Canonicalize(inB, DomainSQL)
	require.NoError(t, err)
	require.Equal(t, string(b), string(a))
}

func TestCanonicalizeURLSortsQuery(t *testing.T) {
	in := []byte("HTTPS://Example.com/path?b=2&a=1")
	out, err := Canonicalize(in, DomainURL)
	require.NoError(t, err)
	require.Equal(t, "https://example.com/path?a=1&b=2", string(out))
}
