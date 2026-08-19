package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/proof/core/chain"
	"github.com/Clyra-AI/proof/core/record"
	"github.com/Clyra-AI/proof/core/schema"
	"github.com/stretchr/testify/require"
)

func TestValidateStrictRecordFilesChainAndJSONLBranches(t *testing.T) {
	dir := t.TempDir()
	rawSchema := []byte(`{"type":"object","required":["record_type"],"properties":{"record_type":{"const":"vendor.strict"}}}`)
	sum := sha256.Sum256(rawSchema)
	registry := schema.NewRegistry()
	require.NoError(t, registry.Register(schema.RecordTypeDefinition{RecordType: "vendor.strict", SchemaID: "urn:test:strict", SchemaVersion: "1", SchemaPath: "schemas/strict.json", SHA256: hex.EncodeToString(sum[:])}, rawSchema))
	r := record.Record{RecordID: "prf-strict", RecordVersion: "1.0", Timestamp: time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC), Source: "test", SourceProduct: "test", RecordType: "vendor.strict", Event: map[string]any{}, Controls: record.Controls{}, Integrity: record.Integrity{RecordHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	chainRaw, err := json.Marshal(chain.Chain{ChainID: "c1", Records: []record.Record{r}})
	require.NoError(t, err)
	jsonlRaw, err := json.Marshal(r)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "chain.json"), chainRaw, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "records.jsonl"), append(jsonlRaw, '\n'), 0o644))
	manifest := Manifest{Files: []ManifestEntry{{Path: "chain.json"}, {Path: "records.jsonl"}}}
	require.NoError(t, validateStrictRecordFiles(dir, manifest, registry))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "chain.json"), []byte("{"), 0o644))
	require.Error(t, validateStrictRecordFiles(dir, manifest, registry))
	manifest.Files = []ManifestEntry{{Path: "records.jsonl"}}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "records.jsonl"), []byte("{\"record_type\":\"vendor.strict\"}\n"), 0o644))
	require.Error(t, validateStrictRecordFiles(dir, manifest, registry))
	manifest.Files = nil
	require.NoError(t, validateStrictRecordFiles(dir, manifest, registry))
}

func TestLoadStrictRecordTypeRegistryBranches(t *testing.T) {
	dir := t.TempDir()
	_, err := loadStrictRecordTypeRegistry(dir, Manifest{})
	require.NoError(t, err)
	emptyRaw := []byte(`{"version":"1","record_types":[]}`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "record-types.json"), emptyRaw, 0o644))
	hash := sha256.Sum256(emptyRaw)
	manifest := Manifest{Files: []ManifestEntry{{Path: "record-types.json", SHA256: hex.EncodeToString(hash[:])}}}
	registry, err := loadStrictRecordTypeRegistry(dir, manifest)
	require.NoError(t, err)
	require.Empty(t, registry.Definitions())
	require.NoError(t, os.WriteFile(filepath.Join(dir, "record-types.json"), []byte("{"), 0o644))
	_, err = loadStrictRecordTypeRegistry(dir, manifest)
	require.Error(t, err)

	rawSchema := []byte(`{"type":"object"}`)
	schemaSum := sha256.Sum256(rawSchema)
	typesRaw, err := json.Marshal(schema.RecordTypeManifest{Version: schema.RecordTypeManifestVersion, RecordTypes: []schema.RecordTypeDefinition{{RecordType: "vendor.bad", SchemaID: "urn:test", SchemaVersion: "1", SchemaPath: "schemas/bad.json", SHA256: hex.EncodeToString(schemaSum[:])}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "record-types.json"), typesRaw, 0o644))
	manifestHash := sha256.Sum256(typesRaw)
	manifest = Manifest{Files: []ManifestEntry{{Path: "record-types.json", SHA256: hex.EncodeToString(manifestHash[:])}}}
	_, err = loadStrictRecordTypeRegistry(dir, manifest)
	require.ErrorContains(t, err, "not covered by bundle manifest")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "schemas"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "schemas", "bad.json"), rawSchema, 0o644))
	manifest.Files = append(manifest.Files, ManifestEntry{Path: "schemas/bad.json", SHA256: hex.EncodeToString(schemaSum[:])})
	_, err = loadStrictRecordTypeRegistry(dir, manifest)
	require.NoError(t, err)

	wrong := []byte(`{"type":"string"}`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "schemas", "bad.json"), wrong, 0o644))
	_, err = loadStrictRecordTypeRegistry(dir, manifest)
	require.ErrorContains(t, err, "digest mismatch")
}
