package schema

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListRecordTypes(t *testing.T) {
	types := ListRecordTypes()
	require.GreaterOrEqual(t, len(types), 10)
}

func TestValidateRecord(t *testing.T) {
	raw := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-17T12:00:00Z",
	  "source":"axym",
	  "source_product":"axym",
	  "record_type":"decision",
	  "event":{"action":"allow"},
	  "controls":{},
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.NoError(t, ValidateRecord(raw, "decision"))
	require.Error(t, ValidateRecord(raw, "unknown_type"))
}

func TestValidateCustomSchema(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "custom.schema.json")
	raw := []byte(`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`)
	require.NoError(t, os.WriteFile(p, raw, 0o644))
	require.NoError(t, ValidateCustomSchema(p, raw))
}

func TestValidateAgainstSchemaAndErrors(t *testing.T) {
	raw := []byte(`{"chain_id":"c1","created_at":"2026-02-17T12:00:00Z","record_count":0,"records":[]}`)
	require.NoError(t, ValidateAgainstSchema(raw, "v1/chain-v1.schema.json"))
	require.Error(t, ValidateAgainstSchema([]byte("{"), "v1/chain-v1.schema.json"))
	require.Error(t, ValidateAgainstSchema(raw, "v1/missing.schema.json"))
}
