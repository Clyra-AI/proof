package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"

	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/stretchr/testify/require"
)

func TestScopedRegistryIsolationAndConflict(t *testing.T) {
	rawSchema := []byte(`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","required":["record_type","event"],"properties":{"record_type":{"const":"vendor.scoped"},"event":{"type":"object","required":["value"]}}}`)
	sum := sha256.Sum256(rawSchema)
	digest := hex.EncodeToString(sum[:])
	first := NewRegistry()
	second := NewRegistry()
	def := RecordTypeDefinition{RecordType: "vendor.scoped", SchemaID: "urn:test:scoped", SchemaVersion: "1.0", SchemaPath: "schemas/vendor-scoped.json", SHA256: digest}
	require.NoError(t, first.Register(def, rawSchema))
	require.Len(t, first.Definitions(), 1)
	require.Empty(t, second.Definitions())
	require.Error(t, second.ValidateRecord(scopedRecord("vendor.scoped", `{"value":1}`), "vendor.scoped"))
	require.NoError(t, first.Register(def, rawSchema), "identical definitions are idempotent")
	conflict := def
	conflict.SchemaVersion = "2.0"
	err := first.Register(conflict, rawSchema)
	require.Error(t, err)
	typed, ok := coreerr.As(err)
	require.True(t, ok)
	require.Equal(t, "schema.custom.conflicting_definition", typed.Code)
	require.Error(t, first.Register(RecordTypeDefinition{RecordType: "decision", SchemaID: "urn:test", SchemaVersion: "1", SchemaPath: "schemas/decision.json", SHA256: digest}, rawSchema))
}

func TestScopedRegistryManifestDigestPathVersionAndMissing(t *testing.T) {
	rawSchema := []byte(`{"type":"object"}`)
	sum := sha256.Sum256(rawSchema)
	digest := hex.EncodeToString(sum[:])
	manifest := RecordTypeManifest{Version: RecordTypeManifestVersion, RecordTypes: []RecordTypeDefinition{{RecordType: "vendor.manifest", SchemaID: "urn:test:manifest", SchemaVersion: "1.0", SchemaPath: "schemas/vendor.json", SHA256: digest}}}
	rawManifest, err := json.Marshal(manifest)
	require.NoError(t, err)
	registry, err := LoadRecordTypeManifest(rawManifest, map[string][]byte{"schemas/vendor.json": rawSchema})
	require.NoError(t, err)
	require.Len(t, registry.Definitions(), 1)

	manifest.Version = "2"
	rawManifest, err = json.Marshal(manifest)
	require.NoError(t, err)
	_, err = LoadRecordTypeManifest(rawManifest, map[string][]byte{"schemas/vendor.json": rawSchema})
	require.Error(t, err)
	manifest.Version = RecordTypeManifestVersion
	manifest.RecordTypes[0].SchemaPath = "../vendor.json"
	rawManifest, err = json.Marshal(manifest)
	require.NoError(t, err)
	_, err = LoadRecordTypeManifest(rawManifest, map[string][]byte{"../vendor.json": rawSchema})
	require.Error(t, err)
	manifest.RecordTypes[0].SchemaPath = "schemas/vendor.json"
	manifest.RecordTypes[0].SHA256 = hex.EncodeToString(make([]byte, sha256.Size))
	rawManifest, err = json.Marshal(manifest)
	require.NoError(t, err)
	_, err = LoadRecordTypeManifest(rawManifest, map[string][]byte{"schemas/vendor.json": rawSchema})
	require.Error(t, err)
	manifest.RecordTypes[0].SHA256 = digest
	rawManifest, err = json.Marshal(manifest)
	require.NoError(t, err)
	_, err = LoadRecordTypeManifest(rawManifest, map[string][]byte{})
	require.ErrorContains(t, err, "schema file is missing")
}

func TestScopedRegistryConcurrentValidation(t *testing.T) {
	rawSchema := []byte(`{"type":"object","required":["record_type"],"properties":{"record_type":{"const":"vendor.concurrent"}}}`)
	sum := sha256.Sum256(rawSchema)
	r := NewRegistry()
	require.NoError(t, r.Register(RecordTypeDefinition{RecordType: "vendor.concurrent", SchemaID: "urn:test:concurrent", SchemaVersion: "1", SchemaPath: "schemas/concurrent.json", SHA256: hex.EncodeToString(sum[:])}, rawSchema))
	raw := scopedRecord("vendor.concurrent", `{}`)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, r.ValidateRecord(raw, "vendor.concurrent"))
		}()
	}
	wg.Wait()
}

func TestLegacyCustomRegistrationRemainsCompatible(t *testing.T) {
	ResetCustomTypes()
	t.Cleanup(ResetCustomTypes)
	rawSchema := []byte(`{"type":"object","required":["record_type"],"properties":{"record_type":{"const":"vendor.legacy"}}}`)
	require.NoError(t, RegisterCustomType("vendor.legacy", "inline", rawSchema))
	require.NotEmpty(t, ListRecordTypes())
	require.NoError(t, ValidateRecord(scopedRecord("vendor.legacy", `{}`), "vendor.legacy"))
	require.NoError(t, RegisterCustomType("vendor.legacy", "inline", rawSchema))
	ResetCustomTypes()
	require.Error(t, ValidateRecord(scopedRecord("vendor.legacy", `{}`), "vendor.legacy"))
}

func scopedRecord(recordType, event string) []byte {
	return []byte(`{"record_id":"prf-scoped","record_version":"1.0","timestamp":"2026-02-17T12:00:00Z","source":"test","source_product":"test","record_type":"` + recordType + `","event":` + event + `,"controls":{},"integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
}
