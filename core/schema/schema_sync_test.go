package schema

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchemaTreeCopiesStayInSync(t *testing.T) {
	coreRoot := filepath.Join("v1")
	repoRoot := filepath.Join("..", "..", "schemas", "v1")

	coreFiles, err := collectFiles(coreRoot)
	require.NoError(t, err)
	repoFiles, err := collectFiles(repoRoot)
	require.NoError(t, err)

	coreKeys := sortedKeys(coreFiles)
	repoKeys := sortedKeys(repoFiles)
	require.Equal(t, repoKeys, coreKeys, "schema file lists differ between core/schema/v1 and schemas/v1")

	for _, rel := range coreKeys {
		require.Equalf(t, string(repoFiles[rel]), string(coreFiles[rel]), "schema mismatch at %s", rel)
	}
}

func TestBuiltinsMatchTypeSchemas(t *testing.T) {
	typeDir := filepath.Join("v1", "types")
	entries, err := os.ReadDir(typeDir)
	require.NoError(t, err)

	schemaFiles := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".schema.json") {
			continue
		}
		schemaFiles[name] = struct{}{}
	}

	require.NotEmpty(t, schemaFiles)
	require.Equal(t, len(schemaFiles), len(builtins), "builtins count must match schema file count")

	byFile := make(map[string]RecordType, len(builtins))
	byName := make(map[string]struct{}, len(builtins))
	for _, rt := range builtins {
		require.NotEmpty(t, rt.Name)
		require.NotEmpty(t, rt.SchemaPath)

		_, seenName := byName[rt.Name]
		require.Falsef(t, seenName, "duplicate built-in type name %s", rt.Name)
		byName[rt.Name] = struct{}{}

		base := filepath.Base(rt.SchemaPath)
		_, exists := schemaFiles[base]
		require.Truef(t, exists, "built-in type %s references missing schema file %s", rt.Name, base)
		expected := strings.ReplaceAll(rt.Name, "_", "-") + ".schema.json"
		require.Equalf(t, expected, base, "built-in schema path naming mismatch for %s", rt.Name)

		_, seenFile := byFile[base]
		require.Falsef(t, seenFile, "duplicate built-in schema mapping for %s", base)
		byFile[base] = rt
	}

	for file := range schemaFiles {
		_, exists := byFile[file]
		require.Truef(t, exists, "schema file %s is not mapped in builtins", file)
	}
}

func collectFiles(root string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = raw
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
