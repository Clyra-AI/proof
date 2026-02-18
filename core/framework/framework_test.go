package framework

import (
	"os"
	"path/filepath"
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

func TestValidateControls(t *testing.T) {
	valid := []Control{
		{
			ID:                  "c1",
			Title:               "Control 1",
			RequiredRecordTypes: []string{"decision"},
			MinimumFrequency:    "continuous",
			RequiredFields:      []string{"record_id", "event"},
		},
	}
	require.NoError(t, validateControls(valid, "controls"))

	missingFields := []Control{
		{
			ID:                  "c2",
			Title:               "Control 2",
			RequiredRecordTypes: []string{"decision"},
			MinimumFrequency:    "continuous",
		},
	}
	require.ErrorContains(t, validateControls(missingFields, "controls"), "missing required_fields")
}

func TestFrameworkCopiesStayInSync(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		corePath := entry.Name()
		repoPath := filepath.Join("..", "..", "frameworks", entry.Name())
		coreRaw, err := os.ReadFile(corePath)
		require.NoError(t, err)
		repoRaw, err := os.ReadFile(repoPath)
		require.NoError(t, err)
		require.Equalf(t, string(repoRaw), string(coreRaw), "framework copy mismatch for %s", entry.Name())
	}
}
