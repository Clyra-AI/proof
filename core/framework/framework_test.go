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

func TestLoadFromFilesystemPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-framework.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
framework:
  id: custom-framework
  version: "1"
  title: Custom Framework
controls:
  - id: custom-control
    title: Custom Control
    required_record_types: [decision]
    required_fields: [record_id]
    minimum_frequency: continuous
`), 0o644))

	f, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "custom-framework", f.Framework.ID)
	require.Len(t, f.Controls, 1)
}

func TestLoadMissingFilesystemPath(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
	require.ErrorContains(t, err, "load framework file")
}

func TestLoadPrefersEmbeddedOverLocalCollision(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.WriteFile("eu-ai-act.yaml", []byte("not: valid: yaml: ["), 0o644))

	f, err := Load("eu-ai-act.yaml")
	require.NoError(t, err)
	require.Equal(t, "eu-ai-act", f.Framework.ID)
	require.Equal(t, "2024-final", f.Framework.Version)

	list, err := List()
	require.NoError(t, err)
	var found bool
	for _, info := range list {
		if info.ID == "eu-ai-act" {
			found = true
			require.Equal(t, 3, info.ControlCount)
		}
	}
	require.True(t, found)
}

func TestLoadFilenameFallbackForCustomFramework(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.WriteFile("custom-framework.yaml", []byte(`
framework:
  id: custom-framework
  version: "1"
  title: Custom Framework
controls:
  - id: custom-control
    title: Custom Control
    required_record_types: [decision]
    required_fields: [record_id]
    minimum_frequency: continuous
`), 0o644))

	f, err := Load("custom-framework.yaml")
	require.NoError(t, err)
	require.Equal(t, "custom-framework", f.Framework.ID)
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

func TestParseFrameworkBranches(t *testing.T) {
	_, err := parseFramework("bad-yaml", []byte("framework: ["))
	require.Error(t, err)

	_, err = parseFramework("missing-id", []byte(`
framework:
  version: "1"
  title: Missing ID
controls:
  - id: c1
    title: Control
    required_record_types: [decision]
    required_fields: [record_id]
    minimum_frequency: continuous
`))
	require.ErrorContains(t, err, "missing id")

	_, err = parseFramework("missing-controls", []byte(`
framework:
  id: test
  version: "1"
  title: Missing Controls
controls: []
`))
	require.ErrorContains(t, err, "has no controls")
}

func TestValidateControlsErrors(t *testing.T) {
	cases := []struct {
		name   string
		in     []Control
		needle string
	}{
		{
			name: "missing id",
			in: []Control{{
				Title:               "Control",
				RequiredRecordTypes: []string{"decision"},
				MinimumFrequency:    "continuous",
				RequiredFields:      []string{"record_id"},
			}},
			needle: "missing id",
		},
		{
			name: "missing title",
			in: []Control{{
				ID:                  "c1",
				RequiredRecordTypes: []string{"decision"},
				MinimumFrequency:    "continuous",
				RequiredFields:      []string{"record_id"},
			}},
			needle: "missing title",
		},
		{
			name: "missing required_record_types",
			in: []Control{{
				ID:               "c1",
				Title:            "Control",
				MinimumFrequency: "continuous",
				RequiredFields:   []string{"record_id"},
			}},
			needle: "missing required_record_types",
		},
		{
			name: "missing minimum_frequency",
			in: []Control{{
				ID:                  "c1",
				Title:               "Control",
				RequiredRecordTypes: []string{"decision"},
				RequiredFields:      []string{"record_id"},
			}},
			needle: "missing minimum_frequency",
		},
		{
			name: "blank required_record_types entry",
			in: []Control{{
				ID:                  "c1",
				Title:               "Control",
				RequiredRecordTypes: []string{"decision", " "},
				MinimumFrequency:    "continuous",
				RequiredFields:      []string{"record_id"},
			}},
			needle: "blank required_record_types entry",
		},
		{
			name: "blank required_fields entry",
			in: []Control{{
				ID:                  "c1",
				Title:               "Control",
				RequiredRecordTypes: []string{"decision"},
				MinimumFrequency:    "continuous",
				RequiredFields:      []string{"record_id", ""},
			}},
			needle: "blank required_fields entry",
		},
		{
			name: "invalid child control",
			in: []Control{{
				ID:                  "c1",
				Title:               "Control",
				RequiredRecordTypes: []string{"decision"},
				MinimumFrequency:    "continuous",
				RequiredFields:      []string{"record_id"},
				Children: []Control{{
					ID:               "child",
					Title:            "Child",
					MinimumFrequency: "continuous",
					RequiredFields:   []string{"record_id"},
				}},
			}},
			needle: "missing required_record_types",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := validateControls(tc.in, "controls")
			require.Error(t, err)
			require.ErrorContains(t, err, tc.needle)
		})
	}
}
