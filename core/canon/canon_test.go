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

func TestDigestHex(t *testing.T) {
	d, err := DigestHex([]byte("hello"), DomainText)
	require.NoError(t, err)
	require.Len(t, d, 64)
}

func TestDigestInfoAndHMAC(t *testing.T) {
	d, err := DigestInfo([]byte("hello"), DomainText, "rotation-q1")
	require.NoError(t, err)
	require.Equal(t, "sha256", d.AlgoID)
	require.Equal(t, "rotation-q1", d.SaltID)
	require.Len(t, d.Value, 64)

	h, err := DigestHMACInfo([]byte("hello"), DomainText, []byte("secret"), "salt-a")
	require.NoError(t, err)
	require.Equal(t, "hmac-sha256", h.AlgoID)
	require.Equal(t, "salt-a", h.SaltID)
	require.Len(t, h.Value, 64)
}

func TestCanonicalizeErrorAndFallbackBranches(t *testing.T) {
	_, err := Canonicalize([]byte("http://[::1"), DomainURL)
	require.Error(t, err)

	out, err := Canonicalize([]byte("raw"), Domain("unknown"))
	require.NoError(t, err)
	require.Equal(t, "raw", string(out))
}

func TestDigestErrorBranches(t *testing.T) {
	_, err := DigestHex([]byte("http://[::1"), DomainURL)
	require.Error(t, err)

	_, err = DigestInfo([]byte("http://[::1"), DomainURL, "salt")
	require.Error(t, err)

	_, err = DigestHMACHex([]byte("http://[::1"), DomainURL, []byte("secret"))
	require.Error(t, err)

	_, err = DigestHMACInfo([]byte("http://[::1"), DomainURL, []byte("secret"), "salt")
	require.Error(t, err)
}
