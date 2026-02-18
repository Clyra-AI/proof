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

func TestLoadMissingAndCountControls(t *testing.T) {
	_, err := Load("does-not-exist")
	require.Error(t, err)

	total := countControls([]Control{
		{ID: "a"},
		{ID: "b", Children: []Control{{ID: "b1"}, {ID: "b2"}}},
	})
	require.Equal(t, 4, total)
}
