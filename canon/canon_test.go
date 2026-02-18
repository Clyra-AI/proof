package canon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalizeJSONAndDigestJCS(t *testing.T) {
	input := []byte(`{"b":2,"a":1}`)

	canonical, err := CanonicalizeJSON(input)
	require.NoError(t, err)
	require.Equal(t, `{"a":1,"b":2}`, string(canonical))

	digest, err := DigestJCS(input)
	require.NoError(t, err)
	require.Len(t, digest, 64)
}
