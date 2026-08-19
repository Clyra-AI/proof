package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScopedRegistryConvenienceAPIsAndManifestFile(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "schemas"), 0o755))
	rawSchema := []byte(`{"$id":"urn:test:file","x-proof-schema-version":"1","type":"object","required":["record_type"],"properties":{"record_type":{"const":"vendor.file"}}}`)
	require.NoError(t, os.WriteFile(filepath.Join(root, "schemas", "vendor-file.json"), rawSchema, 0o644))
	rawSchema2 := []byte(`{"$id":"urn:test:file2","x-proof-schema-version":"1","type":"object","required":["record_type"],"properties":{"record_type":{"const":"vendor.file2"}}}`)
	require.NoError(t, os.WriteFile(filepath.Join(root, "schemas", "vendor-file2.json"), rawSchema2, 0o644))
	sum := sha256.Sum256(rawSchema)
	digest := hex.EncodeToString(sum[:])
	def := RecordTypeDefinition{RecordType: "vendor.file", SchemaID: "urn:test:file", SchemaVersion: "1", SchemaPath: "schemas/vendor-file.json", Digest: digest}
	r := NewScopedRegistry()
	require.NoError(t, r.RegisterFile(def))
	require.NoError(t, r.RegisterSchema(def, rawSchema))
	require.NoError(t, r.RegisterCustomTypeSchema("vendor.file2", "urn:test:file2", "1", "schemas/vendor-file2.json"))
	rawSchema3 := []byte(`{"$id":"urn:test:inline","x-proof-schema-version":"1","type":"object","required":["record_type"],"properties":{"record_type":{"const":"vendor.inline"}}}`)
	require.NoError(t, r.RegisterCustomType("vendor.inline", "urn:test:inline", "1", "schemas/vendor-inline.json", rawSchema3))
	require.Len(t, r.Definitions(), 3)
	require.Len(t, r.ListRecordTypes(), len(builtins)+3)
	require.Len(t, r.Manifest().RecordTypes, 3)
	require.NoError(t, ValidateRecordWithRegistry(r, scopedRecord("vendor.file", `{}`), "vendor.file"))

	manifestRaw, err := json.Marshal(RecordTypeManifest{Version: RecordTypeManifestVersion, RecordTypes: []RecordTypeDefinition{def}})
	require.NoError(t, err)
	parsed, err := ParseRecordTypeManifest(manifestRaw)
	require.NoError(t, err)
	require.Len(t, parsed.RecordTypes, 1)
	require.Equal(t, digest, parsed.RecordTypes[0].Digest)
	require.NoError(t, os.WriteFile(filepath.Join(root, RecordTypeManifestPath), manifestRaw, 0o644))
	loaded, err := LoadRecordTypeManifestFile(root, RecordTypeManifestPath)
	require.NoError(t, err)
	require.Len(t, loaded.Definitions(), 1)

	var nilRegistry *Registry
	require.Error(t, nilRegistry.Register(def, rawSchema))
	require.Error(t, nilRegistry.ValidateRecord(scopedRecord("vendor.file", `{}`), "vendor.file"))
}

func TestScopedRegistryValidationErrorBranches(t *testing.T) {
	rawSchema := []byte(`{"$id":"urn:test","x-proof-schema-version":"1","type":"object"}`)
	sum := sha256.Sum256(rawSchema)
	digest := hex.EncodeToString(sum[:])
	base := RecordTypeDefinition{RecordType: "vendor.valid", SchemaID: "urn:test", SchemaVersion: "1", SchemaPath: "schemas/valid.json", SHA256: digest}
	cases := []RecordTypeDefinition{
		{SchemaID: "urn:test", SchemaVersion: "1", SchemaPath: "schemas/valid.json", SHA256: digest},
		{RecordType: "vendor.valid", SchemaVersion: "1", SchemaPath: "schemas/valid.json", SHA256: digest},
		{RecordType: "vendor.valid", SchemaID: "urn:test", SchemaPath: "schemas/valid.json", SHA256: digest},
		{RecordType: "vendor.valid", SchemaID: "urn:test", SchemaVersion: "1", SchemaPath: "../valid.json", SHA256: digest},
		{RecordType: "vendor.valid", SchemaID: "urn:test", SchemaVersion: "1", SchemaPath: "manifest.json", SHA256: digest},
		{RecordType: "vendor.valid", SchemaID: "urn:test", SchemaVersion: "1", SchemaPath: "schemas/valid.json", SHA256: "bad"},
		{RecordType: "Vendor.Valid", SchemaID: "urn:test", SchemaVersion: "1", SchemaPath: "schemas/valid.json", SHA256: digest},
	}
	for _, def := range cases {
		require.Error(t, NewRegistry().Register(def, rawSchema))
	}
	require.Error(t, NewRegistry().Register(base, []byte(`{"type":`)))
	badSchema := []byte(`{"type":"object"}`)
	badSum := sha256.Sum256(badSchema)
	require.Error(t, NewRegistry().Register(RecordTypeDefinition{RecordType: "vendor.valid", SchemaID: "urn:test", SchemaVersion: "1", SchemaPath: "schemas/valid.json", SHA256: hex.EncodeToString(badSum[:])}, []byte(`{"type":`)))
	require.NoError(t, NewRegistry().Register(base, rawSchema))

	_, err := ParseRecordTypeManifest([]byte("{"))
	require.Error(t, err)
	_, err = ParseRecordTypeManifest([]byte(`{"version":"1","record_types":[]}`))
	require.NoError(t, err)
	require.Equal(t, "", normalizeSHA256("sha256:not-hex"))
	require.Equal(t, digest, normalizeSHA256("SHA256:"+digest))
}
