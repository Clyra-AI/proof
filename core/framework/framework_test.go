package framework

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListAndLoad(t *testing.T) {
	list, err := List()
	require.NoError(t, err)
	require.NotEmpty(t, list)

	f, err := Load("eu-ai-act")
	require.NoError(t, err)
	require.Equal(t, "eu-ai-act", f.Framework.ID)
	require.NotEmpty(t, f.Controls)
}
