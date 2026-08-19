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
	rawSchema := []byte(`{"$id":"urn:test:scoped","x-proof-schema-version":"1.0","$schema":"http://json-schema.org/draft-07/schema#","type":"object","required":["record_type","event"],"properties":{"record_type":{"const":"vendor.scoped"},"event":{"type":"object","required":["value"]}}}`)
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
	rawSchema := []byte(`{"$id":"urn:test:manifest","x-proof-schema-version":"1.0","type":"object"}`)
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
	rawSchema := []byte(`{"$id":"urn:test:concurrent","x-proof-schema-version":"1","type":"object","required":["record_type"],"properties":{"record_type":{"const":"vendor.concurrent"}}}`)
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

func TestPortableManifestSchemaIdentityAndLocalRefs(t *testing.T) {
	shared := []byte(`{"$id":"urn:test:shared","x-proof-schema-version":"1","$defs":{"event":{"type":"object","required":["x"]}}}`)
	base := []byte(`{"$id":"urn:test:base","x-proof-schema-version":"1","type":"object","required":["record_type","event"],"properties":{"record_type":{"const":"vendor.ref"},"event":{"$ref":"shared.json#/$defs/event"}}}`)
	hash := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
	manifest := RecordTypeManifest{Version: "1", RecordTypes: []RecordTypeDefinition{
		{RecordType: "vendor.ref", SchemaID: "urn:test:base", SchemaVersion: "1", SchemaPath: "schemas/base.json", SHA256: hash(base)},
		{RecordType: "vendor.shared", SchemaID: "urn:test:shared", SchemaVersion: "1", SchemaPath: "schemas/shared.json", SHA256: hash(shared)},
	}}
	rawManifest, err := json.Marshal(manifest)
	require.NoError(t, err)
	registry, err := LoadRecordTypeManifestWithResources(rawManifest, map[string][]byte{"schemas/base.json": base, "schemas/shared.json": shared})
	require.NoError(t, err)
	require.NoError(t, registry.ValidateRecord(scopedRecord("vendor.ref", `{"x":1}`), "vendor.ref"))

	external := []byte(`{"$id":"urn:test:base","x-proof-schema-version":"1","type":"object","properties":{"event":{"$ref":"https://example.invalid/schema.json"}}}`)
	manifest.RecordTypes[0].SHA256 = hash(external)
	rawManifest, err = json.Marshal(manifest)
	require.NoError(t, err)
	_, err = LoadRecordTypeManifestWithResources(rawManifest, map[string][]byte{"schemas/base.json": external, "schemas/shared.json": shared})
	require.ErrorContains(t, err, "external schema reference")

	escape := []byte(`{"$id":"urn:test:base","x-proof-schema-version":"1","type":"object","properties":{"event":{"$ref":"../../outside.json"}}}`)
	manifest.RecordTypes[0].SHA256 = hash(escape)
	rawManifest, err = json.Marshal(manifest)
	require.NoError(t, err)
	_, err = LoadRecordTypeManifestWithResources(rawManifest, map[string][]byte{"schemas/base.json": escape, "schemas/shared.json": shared})
	require.Error(t, err)

	identityMismatch := []byte(`{"$id":"urn:wrong","x-proof-schema-version":"1","type":"object"}`)
	manifest.RecordTypes[0].SHA256 = hash(identityMismatch)
	rawManifest, err = json.Marshal(manifest)
	require.NoError(t, err)
	_, err = LoadRecordTypeManifestWithResources(rawManifest, map[string][]byte{"schemas/base.json": identityMismatch, "schemas/shared.json": shared})
	require.ErrorContains(t, err, "schema $id mismatch")
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
