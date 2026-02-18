package schema

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateJSONAndJSONL(t *testing.T) {
	dir := t.TempDir()
	schemaPath := filepath.Join(dir, "schema.json")
	jsonPath := filepath.Join(dir, "one.json")
	jsonlPath := filepath.Join(dir, "many.jsonl")

	schemaDoc := `{
  "type": "object",
  "required": ["id"],
  "properties": {"id": {"type": "string"}}
}`
	require.NoError(t, os.WriteFile(schemaPath, []byte(schemaDoc), 0o600))
	require.NoError(t, os.WriteFile(jsonPath, []byte(`{"id":"a"}`), 0o600))
	require.NoError(t, os.WriteFile(jsonlPath, []byte("{\"id\":\"a\"}\n{\"id\":\"b\"}\n"), 0o600))

	require.NoError(t, ValidateJSONFile(schemaPath, jsonPath))
	require.NoError(t, ValidateJSON(schemaPath, []byte(`{"id":"x"}`)))
	require.NoError(t, ValidateJSONLFile(schemaPath, jsonlPath))
	require.NoError(t, ValidateJSONL(schemaPath, []byte("{\"id\":\"x\"}\n\n{\"id\":\"y\"}\n")))
}

func TestValidateJSONErrors(t *testing.T) {
	dir := t.TempDir()
	schemaPath := filepath.Join(dir, "schema.json")
	require.NoError(t, os.WriteFile(schemaPath, []byte(`{"type":"object","required":["id"]}`), 0o600))

	err := ValidateJSON(schemaPath, []byte(`{"name":"missing"}`))
	require.Error(t, err)

	err = ValidateJSONL(schemaPath, []byte("{\"id\":\"ok\"}\n{\"name\":\"bad\"}\n"))
	require.Error(t, err)
}

func TestValidateSchemaAndFileErrorBranches(t *testing.T) {
	dir := t.TempDir()
	schemaPath := filepath.Join(dir, "schema.json")
	jsonPath := filepath.Join(dir, "payload.json")
	require.NoError(t, os.WriteFile(schemaPath, []byte(`{"type":"object","required":["id"]}`), 0o600))
	require.NoError(t, os.WriteFile(jsonPath, []byte(`{"id":"ok"}`), 0o600))

	require.Error(t, ValidateJSONFile(filepath.Join(dir, "missing.json"), jsonPath))
	require.Error(t, ValidateJSONFile(schemaPath, filepath.Join(dir, "missing.json")))
	require.Error(t, ValidateJSONLFile(schemaPath, filepath.Join(dir, "missing.jsonl")))
	require.Error(t, ValidateJSON(schemaPath, []byte(`{not-json`)))
	require.Error(t, ValidateJSONL(schemaPath, []byte("{\"id\":\"ok\"}\n{not-json}\n")))

	invalidSchemaPath := filepath.Join(dir, "invalid-schema.json")
	require.NoError(t, os.WriteFile(invalidSchemaPath, []byte(`{bad`), 0o600))
	require.Error(t, ValidateJSON(invalidSchemaPath, []byte(`{"id":"x"}`)))
}
