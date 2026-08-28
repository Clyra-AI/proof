package fixtureimport

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	prooffcanon "github.com/Clyra-AI/proof/core/canon"
	"github.com/stretchr/testify/require"
)

func TestFinalFixtureImportStagesExactBytesAndChecksOffline(t *testing.T) {
	root, contract, raw := validSource(t)
	dest := filepath.Join(t.TempDir(), "fixture")
	require.NoError(t, Update(root, dest, contract, raw))
	require.NoError(t, Check(dest))
	require.NoError(t, Check(dest), "check must be repeatable and offline")
	manifestRaw, err := os.ReadFile(filepath.Join(dest, ManifestPath))
	require.NoError(t, err)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(manifestRaw, &manifest))
	wantContractDigest, err := canonicalDigest(raw)
	require.NoError(t, err)
	require.Equal(t, wantContractDigest, manifest["contract_sha256"])

	// Source bytes are copied without normalization or producer-owned ref loss.
	want, err := os.ReadFile(filepath.Join(root, "axym", "artifact.json"))
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(dest, "source", "axym", "artifact.json"))
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestFinalFixtureImportPreflightFailureLeavesExistingFixtureUntouched(t *testing.T) {
	root, contract, raw := validSource(t)
	dest := filepath.Join(t.TempDir(), "fixture")
	require.NoError(t, Update(root, dest, contract, raw))
	sentinel := []byte("keep-existing")
	sentinelPath := filepath.Join(dest, "sentinel.txt")
	require.NoError(t, os.WriteFile(sentinelPath, sentinel, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "axym", "public.key"), []byte("changed"), 0o600))
	require.Error(t, Update(root, dest, contract, raw))
	got, err := os.ReadFile(sentinelPath)
	require.NoError(t, err)
	require.Equal(t, sentinel, got)
}

func TestFinalFixtureImportCheckTypesMissingRequiredFileAsRuntimeFailure(t *testing.T) {
	root, contract, raw := validSource(t)
	dest := filepath.Join(t.TempDir(), "fixture")
	require.NoError(t, Update(root, dest, contract, raw))
	require.NoError(t, os.Remove(filepath.Join(dest, "source", "wrkr", "artifact.json")))
	var runtimeErr *RuntimeError
	require.ErrorAs(t, Check(dest), &runtimeErr)
}

func TestFinalFixtureImportRejectsContractStructRawMismatch(t *testing.T) {
	root, contract, raw := validSource(t)
	contract.FixtureID = "different-contract"
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "contract and contractRaw disagree")
}

func TestFinalFixtureImportRefusesExistingUnmanagedDestination(t *testing.T) {
	root, contract, raw := validSource(t)
	dest := filepath.Join(t.TempDir(), "fixture")
	require.NoError(t, os.MkdirAll(dest, 0o750))
	var unsafeErr *UnsafeError
	require.ErrorAs(t, Update(root, dest, contract, raw), &unsafeErr)

	dest = filepath.Join(t.TempDir(), "contract-only")
	require.NoError(t, os.MkdirAll(filepath.Join(dest, "provenance"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dest, ContractPath), raw, 0o600))
	unsafeErr = nil
	require.ErrorAs(t, Update(root, dest, contract, raw), &unsafeErr)
}

func TestFinalFixtureImportRejectsSourceAndStagedSymlinks(t *testing.T) {
	root, contract, raw := validSource(t)
	artifact := filepath.Join(root, "axym", "artifact.json")
	backup := artifact + ".regular"
	require.NoError(t, os.Rename(artifact, backup))
	require.NoError(t, os.Symlink(backup, artifact))
	var unsafeErr *UnsafeError
	require.ErrorAs(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), &unsafeErr)

	root, contract, raw = validSource(t)
	dest := filepath.Join(t.TempDir(), "fixture")
	require.NoError(t, Update(root, dest, contract, raw))
	sourceDir := filepath.Join(dest, "source", "axym")
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.MkdirAll(outside, 0o750))
	backupDir := sourceDir + ".regular"
	require.NoError(t, os.Rename(sourceDir, backupDir))
	outsideSource := filepath.Join(outside, "axym")
	require.NoError(t, os.Rename(backupDir, outsideSource))
	require.NoError(t, os.Symlink(outsideSource, sourceDir))
	require.ErrorContains(t, Check(dest), "symlink path is not allowed")
}

func TestFinalFixtureImportCheckRejectsSharedSourceSymlinkAsUnsafe(t *testing.T) {
	root, contract, raw := validSource(t)
	dest := filepath.Join(t.TempDir(), "fixture")
	require.NoError(t, Update(root, dest, contract, raw))
	sourceRoot := filepath.Join(dest, "source")
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.MkdirAll(outside, 0o750))
	backup := sourceRoot + ".regular"
	require.NoError(t, os.Rename(sourceRoot, backup))
	require.NoError(t, os.Symlink(outside, sourceRoot))
	var unsafeErr *UnsafeError
	require.ErrorAs(t, Check(dest), &unsafeErr)
}

func TestFinalFixtureImportRejectsMissingAxymRegisterOrPacket(t *testing.T) {
	for _, missing := range []string{"register", "packet"} {
		t.Run(missing, func(t *testing.T) {
			_, contract, _ := validSource(t)
			axym := sourceFor(&contract, "axym")
			filtered := axym.Artifacts[:0]
			for _, artifact := range axym.Artifacts {
				if !strings.Contains(artifact.Kind, missing) {
					filtered = append(filtered, artifact)
				}
			}
			axym.Artifacts = filtered
			_, err := LoadContract(mustJSON(contract))
			require.ErrorContains(t, err, "exact register and evidence packet")
		})
	}
}

func TestFinalFixtureImportRejectsAxymRegisterPacketPathAlias(t *testing.T) {
	_, contract, _ := validSource(t)
	axym := sourceFor(&contract, "axym")
	axym.Artifacts[1].Path = axym.Artifacts[0].Path
	_, err := LoadContract(mustJSON(contract))
	require.ErrorContains(t, err, "portable path collision")
}

func TestFinalFixtureImportRejectsAxymRolePayloadSwap(t *testing.T) {
	root, contract, raw := validSource(t)
	axym := sourceFor(&contract, "axym")
	register := axym.Artifacts[0]
	register.Path = "packet-copy.json"
	register.Kind = "evidence_packet"
	axym.Artifacts[1] = register
	require.NoError(t, os.WriteFile(filepath.Join(root, "axym", register.Path), mustRead(t, filepath.Join(root, "axym", "artifact.json")), 0o600))
	contract.Sources[2].Artifacts[1].SHA256 = digest(mustRead(t, filepath.Join(root, "axym", register.Path)))
	raw = mustJSON(contract)
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "normative schema")
}

func TestFinalFixtureImportRejectsWrongProducerIdentity(t *testing.T) {
	for _, field := range []string{"version", "commit", "tag"} {
		t.Run(field, func(t *testing.T) {
			root, contract, raw := validSource(t)
			s := sourceFor(&contract, "gait")
			manifestPath := filepath.Join(root, "gait", "manifest.json")
			manifest := map[string]any{"producer": map[string]any{"name": "gait", "version": s.Version, "commit": s.Commit, "tag": s.Tag}}
			manifest["producer"].(map[string]any)[field] = "wrong"
			manifestRaw, err := json.Marshal(manifest)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(manifestPath, manifestRaw, 0o600))
			s.ManifestSHA256 = digest(manifestRaw)
			require.Error(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw))
		})
	}
}

func TestFinalFixtureImportRejectsConflictingProducerIdentityAliases(t *testing.T) {
	root, contract, raw := validSource(t)
	manifest := []byte(`{"producer":{"name":"gait","version":"v1","commit":"commit-gait"},"product":"wrkr"}`)
	require.NoError(t, os.WriteFile(filepath.Join(root, "gait", "manifest.json"), manifest, 0o600))
	contract.Sources[1].ManifestSHA256 = digest(manifest)
	raw = mustJSON(contract)
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "conflicting producer")
}

func TestFinalFixtureImportAcceptsReleaseManifestWithoutTagField(t *testing.T) {
	root, contract, raw := validSource(t)
	manifestPath := filepath.Join(root, "gait", "manifest.json")
	manifest := []byte(`{"producer":{"name":"gait","version":"v1"},"source_commit":"commit-gait"}`)
	require.NoError(t, os.WriteFile(manifestPath, manifest, 0o600))
	contract.Sources[1].ManifestSHA256 = digest(manifest)
	raw = mustJSON(contract)
	require.NoError(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw))
}

func TestFinalFixtureImportAcceptsGaitV16TagPinnedOutsideManifest(t *testing.T) {
	root, contract, raw := validSource(t)
	source := sourceFor(&contract, "gait")
	source.Version = "v1.5.0"
	source.Tag = "v1.6.0"
	manifest := []byte(`{"fixture_version":"1","foundation_commit":"foundation","source_commit":"commit-gait","producer":{"name":"gait","version":"v1.5.0"},"signing":{"fixture_test_only":true}}`)
	require.NoError(t, os.WriteFile(filepath.Join(root, "gait", "manifest.json"), manifest, 0o600))
	source.ManifestSHA256 = digest(manifest)
	raw = mustJSON(contract)
	require.NoError(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw))
}

func TestFinalFixtureImportRejectsSyntheticAndIntegrityOverclaim(t *testing.T) {
	root, contract, raw := validSource(t)
	contract.Sources[2].Artifacts[0].Synthetic = true
	_, err := LoadContract(mustJSON(contract))
	require.ErrorContains(t, err, "synthetic artifacts")

	root, contract, raw = validSource(t)
	artifactPath := filepath.Join(root, "gait", "artifact.json")
	overclaim := []byte(`{"binding_mode":"identifier_only","content_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	require.NoError(t, os.WriteFile(artifactPath, overclaim, 0o600))
	contract.Sources[1].Artifacts[0].SHA256 = testDigest(overclaim)
	require.Error(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw))

	root, contract, raw = validSource(t)
	artifactPath = filepath.Join(root, "axym", "artifact.json")
	synthetic := []byte(`{"assessment":"synthetic","fixture_only":true}`)
	require.NoError(t, os.WriteFile(artifactPath, synthetic, 0o600))
	contract.Sources[2].Artifacts[0].SHA256 = digest(synthetic)
	require.Error(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw))
}

func TestFinalFixtureImportRejectsSchemaManifestKeyAndRelationshipMutations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(string, *Contract)
	}{
		{"schema", func(root string, c *Contract) {
			p := filepath.Join(root, "wrkr", "schema.json")
			require.NoError(t, os.WriteFile(p, []byte(`{"$id":"urn:wrong","x-proof-schema-version":"1"}`), 0o600))
		}},
		{"manifest", func(root string, c *Contract) {
			p := filepath.Join(root, "gait", "manifest.json")
			require.NoError(t, os.WriteFile(p, []byte(`{"producer":{"name":"gait","version":"v1","commit":"commit-gait","tag":"v1"},"mutated":true}`), 0o600))
		}},
		{"public-key", func(root string, c *Contract) {
			require.NoError(t, os.WriteFile(filepath.Join(root, "axym", "public.key"), []byte("mutated"), 0o600))
		}},
		{"signature", func(root string, c *Contract) {
			require.NoError(t, os.WriteFile(filepath.Join(root, "wrkr", "signature.bin"), []byte("mutated"), 0o600))
		}},
		{"relationship", func(root string, c *Contract) {
			p := filepath.Join(root, "wrkr", "artifact.json")
			require.NoError(t, os.WriteFile(p, []byte(`{"relationship":{"kind":"wrkr.contract","id":"changed","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_id":"urn:contract","schema_version":"1","source_product":"wrkr"}}`), 0o600))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, contract, raw := validSource(t)
			tc.mutate(root, &contract)
			require.Error(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw))
		})
	}
}

func TestFinalFixtureImportRejectsConflictingSchemaVersionMarkers(t *testing.T) {
	root, contract, raw := validSource(t)
	schemaPath := filepath.Join(root, "wrkr", "schema.json")
	schema := []byte(`{"$id":"urn:wrkr-schema","x-proof-schema-version":"1","properties":{"schema_version":{"const":"2"}}}`)
	require.NoError(t, os.WriteFile(schemaPath, schema, 0o600))
	contract.Sources[0].Schemas[0].SHA256 = digest(schema)
	contract.Sources[0].Artifacts[0].SchemaSHA256 = digest(schema)
	raw = mustJSON(contract)
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "schema version schema_version")
}

func TestFinalFixtureImportRejectsMalformedOrSchemaMismatchedArtifactWithMatchingDigest(t *testing.T) {
	root, contract, raw := validSource(t)
	artifactPath := filepath.Join(root, "wrkr", "artifact.json")
	malformed := []byte(`{"schema_id":"urn:wrkr-schema","schema_version":"1",`)
	require.NoError(t, os.WriteFile(artifactPath, malformed, 0o600))
	contract.Sources[0].Artifacts[0].SHA256 = digest(malformed)
	raw = mustJSON(contract)
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "artifact is not valid JSON")

	root, contract, raw = validSource(t)
	artifactPath = filepath.Join(root, "wrkr", "artifact.json")
	var payload map[string]any
	require.NoError(t, json.Unmarshal(mustRead(t, artifactPath), &payload))
	payload["schema_id"] = "urn:wrong-schema"
	mutated, err := json.Marshal(payload)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(artifactPath, mutated, 0o600))
	contract.Sources[0].Artifacts[0].SHA256 = digest(mutated)
	raw = mustJSON(contract)
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "payload schema_id")
}

func TestFinalFixtureImportRejectsTrailingArtifactJSONWithMatchingDigest(t *testing.T) {
	root, contract, raw := validSource(t)
	artifactPath := filepath.Join(root, "wrkr", "artifact.json")
	trailing := append(mustRead(t, artifactPath), []byte("\n{}")...)
	require.NoError(t, os.WriteFile(artifactPath, trailing, 0o600))
	contract.Sources[0].Artifacts[0].SHA256 = digest(trailing)
	raw = mustJSON(contract)
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "trailing JSON")
}

func TestFinalFixtureImportRejectsDuplicateArtifactJSONMembers(t *testing.T) {
	root, contract, raw := validSource(t)
	artifactPath := filepath.Join(root, "wrkr", "artifact.json")
	duplicate := []byte(`{"schema_id":"urn:wrkr-schema","schema_id":"urn:wrkr-schema","schema_version":"1","record_id":"wrkr-artifact","contracts":[]}`)
	require.NoError(t, os.WriteFile(artifactPath, duplicate, 0o600))
	contract.Sources[0].Artifacts[0].SHA256 = digest(duplicate)
	raw = mustJSON(contract)
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "duplicate JSON object member")
}

func TestFinalFixtureImportRejectsDuplicatePinnedSchemaJSONMembers(t *testing.T) {
	root, contract, raw := validSource(t)
	schemaPath := filepath.Join(root, "wrkr", "schema.json")
	duplicate := []byte(`{"$id":"urn:wrkr-schema","$id":"urn:wrkr-schema","x-proof-schema-version":"1"}`)
	require.NoError(t, os.WriteFile(schemaPath, duplicate, 0o600))
	contract.Sources[0].Schemas[0].SHA256 = digest(duplicate)
	contract.Sources[0].Artifacts[0].SchemaSHA256 = digest(duplicate)
	raw = mustJSON(contract)
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "duplicate JSON object member")
}

func TestFinalFixtureImportRejectsDuplicateProducerManifestMembers(t *testing.T) {
	root, contract, raw := validSource(t)
	manifest := []byte(`{"producer":{"name":"gait","name":"gait","version":"v1","commit":"commit-gait","tag":"v1"}}`)
	require.NoError(t, os.WriteFile(filepath.Join(root, "gait", "manifest.json"), manifest, 0o600))
	contract.Sources[1].ManifestSHA256 = digest(manifest)
	raw = mustJSON(contract)
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "duplicate JSON object member")
}

func TestFinalFixtureImportRejectsDuplicateContractMembers(t *testing.T) {
	_, _, raw := validSource(t)
	duplicate := strings.Replace(string(raw), `"fixture_id":"final-fixture-v1"`, `"fixture_id":"first","fixture_id":"final-fixture-v1"`, 1)
	_, err := LoadContract([]byte(duplicate))
	require.ErrorContains(t, err, "duplicate JSON object member")
}

func TestFinalFixtureImportRejectsInvalidUTF8(t *testing.T) {
	_, _, raw := validSource(t)
	invalid := strings.Replace(string(raw), "final-fixture-v1", "final-\xff", 1)
	_, err := LoadContract([]byte(invalid))
	require.ErrorContains(t, err, "UTF-8")
}

func TestFinalFixtureImportRejectsUnpairedSurrogateEscapes(t *testing.T) {
	for _, raw := range []string{`{"x":"\uD800"}`, `{"x":"\uDC00"}`} {
		require.Error(t, rejectUnpairedSurrogates([]byte(raw)))
	}
	require.NoError(t, rejectUnpairedSurrogates([]byte(`{"x":"\uD834\uDD1E"}`)))
}

func TestFinalFixtureImportCompilesEveryPinnedSchema(t *testing.T) {
	schemaID := "urn:compiled-schema"
	unusedID := "urn:unused-schema"
	artifact := Artifact{SchemaPath: "selected.json", SchemaID: schemaID, SchemaVersion: "1"}
	selected := []byte(`{"$id":"urn:compiled-schema","x-proof-schema-version":"1","type":"object","required":["schema_id","schema_version"],"properties":{"schema_id":{"const":"urn:compiled-schema"},"schema_version":{"const":"1"}}}`)
	unused := []byte(`{"$id":"urn:unused-schema","x-proof-schema-version":"1","$ref":"https://example.invalid/unpinned.json"}`)
	raw := []byte(`{"schema_id":"urn:compiled-schema","schema_version":"1"}`)
	err := validateArtifactAgainstSchema(raw, "wrkr", artifact, map[string]File{
		"selected.json": {Path: "selected.json", SchemaID: schemaID, SchemaVersion: "1"},
		"unused.json":   {Path: "unused.json", SchemaID: unusedID, SchemaVersion: "1"},
	}, map[string][]byte{"selected.json": selected, "unused.json": unused})
	require.ErrorContains(t, err, "compile pinned schema unused.json")
}

func TestFinalFixtureImportTypesCommittedFixtureDrift(t *testing.T) {
	root, contract, raw := validSource(t)
	dest := filepath.Join(t.TempDir(), "fixture")
	require.NoError(t, Update(root, dest, contract, raw))
	manifestPath := filepath.Join(dest, ManifestPath)
	require.NoError(t, os.WriteFile(manifestPath, []byte("drift"), 0o600))
	var driftErr *DriftError
	require.ErrorAs(t, Check(dest), &driftErr)
}

func TestFinalFixtureImportCheckRejectsContractSymlinkAsUnsafe(t *testing.T) {
	root, contract, raw := validSource(t)
	dest := filepath.Join(t.TempDir(), "fixture")
	require.NoError(t, Update(root, dest, contract, raw))
	contractPath := filepath.Join(dest, ContractPath)
	backup := contractPath + ".regular"
	require.NoError(t, os.Rename(contractPath, backup))
	require.NoError(t, os.Symlink(backup, contractPath))
	var unsafeErr *UnsafeError
	require.ErrorAs(t, Check(dest), &unsafeErr)
}

func TestFinalFixtureImportCheckRejectsMissingLeafUnderSymlinkAncestorAsUnsafe(t *testing.T) {
	root, contract, raw := validSource(t)
	dest := filepath.Join(t.TempDir(), "fixture")
	require.NoError(t, Update(root, dest, contract, raw))
	sourceDir := filepath.Join(dest, "source", "wrkr")
	artifactPath := filepath.Join(sourceDir, "artifact.json")
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.MkdirAll(outside, 0o750))
	require.NoError(t, os.Remove(artifactPath))
	require.NoError(t, os.RemoveAll(sourceDir))
	require.NoError(t, os.Symlink(outside, sourceDir))
	var unsafeErr *UnsafeError
	require.ErrorAs(t, Check(dest), &unsafeErr)
}

func TestFinalFixtureImportRejectsExplicitSyntheticProvenanceMarkers(t *testing.T) {
	for _, marker := range []string{"assessment", "quarantine", "authoritative", "non_authoritative", "synthetic_extension", "fixture_test_only", "development_signing"} {
		t.Run(marker, func(t *testing.T) {
			root, contract, raw := validSource(t)
			artifactPath := filepath.Join(root, "axym", "artifact.json")
			var artifact map[string]any
			require.NoError(t, json.Unmarshal(mustRead(t, artifactPath), &artifact))
			if marker == "assessment" {
				artifact[marker] = "synthetic"
			} else if marker == "authoritative" {
				artifact[marker] = false
			} else {
				artifact[marker] = true
			}
			mutated, err := json.Marshal(artifact)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(artifactPath, mutated, 0o600))
			contract.Sources[2].Artifacts[0].SHA256 = digest(mutated)
			raw = mustJSON(contract)
			require.Error(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw))
		})
	}
}

func TestFinalFixtureImportRejectsDuplicateSchemaIdentities(t *testing.T) {
	_, contract, _ := validSource(t)
	wrkr := sourceFor(&contract, "wrkr")
	duplicate := wrkr.Schemas[0]
	duplicate.Path = "schema-copy.json"
	wrkr.Schemas = append(wrkr.Schemas, duplicate)
	_, err := LoadContract(mustJSON(contract))
	require.NoError(t, err)
	root, contract, raw := validSource(t)
	wrkr = sourceFor(&contract, "wrkr")
	duplicate = wrkr.Schemas[0]
	duplicate.Path = "schema-copy.json"
	wrkr.Schemas = append(wrkr.Schemas, duplicate)
	require.NoError(t, os.WriteFile(filepath.Join(root, "wrkr", duplicate.Path), mustRead(t, filepath.Join(root, "wrkr", wrkr.Schemas[0].Path)), 0o600))
	raw = mustJSON(contract)
	var schemaErr *SchemaError
	require.ErrorAs(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), &schemaErr)
}

func TestFinalFixtureImportReplacementRejectsChangedDestinationIdentity(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "fixture")
	oldTarget := filepath.Join(parent, "old-fixture")
	newTarget := filepath.Join(parent, "new-fixture")
	require.NoError(t, os.Mkdir(target, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(target, ManagedMarker), []byte(ManagedContent), 0o600))
	info, err := os.Lstat(target)
	require.NoError(t, err)
	identity, err := destinationIdentityFor(target, info)
	require.NoError(t, err)
	require.NoError(t, os.Rename(target, oldTarget))
	require.NoError(t, os.Mkdir(newTarget, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(newTarget, ManagedMarker), []byte(ManagedContent), 0o600))
	distinctTime := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(filepath.Join(newTarget, ManagedMarker), distinctTime, distinctTime))
	require.NoError(t, os.Rename(newTarget, target))
	staging := filepath.Join(parent, "staging")
	require.NoError(t, os.Mkdir(staging, 0o750))
	var unsafeErr *UnsafeError
	require.ErrorAs(t, replaceDirectory(staging, target, identity), &unsafeErr)
}

func TestFinalFixtureImportRejectsCaseFoldedPathCollisions(t *testing.T) {
	_, contract, _ := validSource(t)
	wrkr := sourceFor(&contract, "wrkr")
	wrkr.Schemas[0].Path = "ARTIFACT.JSON"
	_, err := LoadContract(mustJSON(contract))
	require.ErrorContains(t, err, "portable path collision")
}

func TestFinalFixtureImportRejectsUnicodeEquivalentPathCollisions(t *testing.T) {
	_, contract, _ := validSource(t)
	wrkr := sourceFor(&contract, "wrkr")
	wrkr.Schemas[0].Path = "caf\u00e9.json"
	duplicate := wrkr.Schemas[0]
	duplicate.Path = "cafe\u0301.json"
	wrkr.Schemas = append(wrkr.Schemas, duplicate)
	_, err := LoadContract(mustJSON(contract))
	require.ErrorContains(t, err, "portable path collision")
}

func TestFinalFixtureImportRejectsUnicodeCaseFoldPathCollisions(t *testing.T) {
	_, contract, _ := validSource(t)
	wrkr := sourceFor(&contract, "wrkr")
	wrkr.Schemas[0].Path = "\u03a3.json"
	duplicate := wrkr.Schemas[0]
	duplicate.Path = "\u03c2.json"
	wrkr.Schemas = append(wrkr.Schemas, duplicate)
	_, err := LoadContract(mustJSON(contract))
	require.ErrorContains(t, err, "portable path collision")
}

func TestFinalFixtureImportRejectsCaseFoldedFileDirectoryPrefixCollisions(t *testing.T) {
	_, contract, _ := validSource(t)
	wrkr := sourceFor(&contract, "wrkr")
	wrkr.ManifestPath = "DATA"
	wrkr.Schemas[0].Path = "data/schema.json"
	_, err := LoadContract(mustJSON(contract))
	require.ErrorContains(t, err, "portable path collision")
}

func TestFinalFixtureImportDoesNotUnwrapNonGaitRecordContainers(t *testing.T) {
	schemaID := "urn:wrkr-wrapper-test"
	schemaVersion := "1"
	schemaPath := "schema.json"
	schemaRaw := []byte(`{"$id":"urn:wrkr-wrapper-test","x-proof-schema-version":"1","type":"object","required":["schema_id","schema_version"],"properties":{"schema_id":{"const":"urn:wrkr-wrapper-test"},"schema_version":{"const":"1"}}}`)
	artifact := Artifact{SchemaPath: schemaPath, SchemaID: schemaID, SchemaVersion: schemaVersion}
	raw := []byte(`{"records":[{"schema_id":"urn:wrkr-wrapper-test","schema_version":"1"}]}`)
	err := validateArtifactAgainstSchema(raw, "wrkr", artifact, map[string]File{
		schemaPath: {Path: schemaPath, SchemaID: schemaID, SchemaVersion: schemaVersion},
	}, map[string][]byte{schemaPath: schemaRaw})
	require.ErrorContains(t, err, "payload schema_id")
}

func TestFinalFixtureImportPreservesJSONNumberPrecision(t *testing.T) {
	schemaID := "urn:number-test"
	schemaPath := "schema.json"
	schemaRaw := []byte(`{"$id":"urn:number-test","x-proof-schema-version":"1","type":"object","required":["schema_id","schema_version","sequence"],"properties":{"schema_id":{"const":"urn:number-test"},"schema_version":{"const":"1"},"sequence":{"const":9007199254740993}}}`)
	artifact := Artifact{SchemaPath: schemaPath, SchemaID: schemaID, SchemaVersion: "1"}
	raw := []byte(`{"schema_id":"urn:number-test","schema_version":"1","sequence":9007199254740993}`)
	require.NoError(t, validateArtifactAgainstSchema(raw, "wrkr", artifact, map[string]File{
		schemaPath: {Path: schemaPath, SchemaID: schemaID, SchemaVersion: "1"},
	}, map[string][]byte{schemaPath: schemaRaw}))
}

func TestFinalFixtureImportTypesManagedMarkerReadFailureAsRuntime(t *testing.T) {
	root, contract, raw := validSource(t)
	dest := filepath.Join(t.TempDir(), "fixture")
	require.NoError(t, Update(root, dest, contract, raw))
	require.NoError(t, os.Remove(filepath.Join(dest, ManagedMarker)))
	require.NoError(t, os.Mkdir(filepath.Join(dest, ManagedMarker), 0o750))
	var unsafeErr *UnsafeError
	require.ErrorAs(t, Check(dest), &unsafeErr)
}

func TestFinalFixtureImportSafePathRejectsWindowsVolumeFormsPortably(t *testing.T) {
	for _, path := range []string{"C:/fixture.json", "C:\\fixture.json", "C:fixture.json"} {
		t.Run(path, func(t *testing.T) {
			require.Error(t, safePath(path))
		})
	}
}

func TestFinalFixtureImportSafePathRejectsPlatformReservedNamesAndCharacters(t *testing.T) {
	for _, path := range []string{"artifact?.json", "dir/a:b", "CON", "nested/COM1.txt", "trailing.", "trailing "} {
		t.Run(path, func(t *testing.T) {
			require.Error(t, safePath(path))
		})
	}
}

func TestFinalFixtureImportKeepsDigestFailuresAsVerificationErrors(t *testing.T) {
	root, contract, raw := validSource(t)
	contract.Sources[0].Schemas[0].SHA256 = digest([]byte("different schema bytes"))
	raw = mustJSON(contract)
	err := Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw)
	var schemaErr *SchemaError
	require.Error(t, err)
	require.NotErrorAs(t, err, &schemaErr)

	root, contract, raw = validSource(t)
	contract.Sources[0].Artifacts[0].SchemaSHA256 = digest([]byte("different schema bytes"))
	raw = mustJSON(contract)
	err = Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw)
	require.Error(t, err)
	require.NotErrorAs(t, err, &schemaErr)
}

func TestFinalFixtureImportRejectsContractSchemaIdentityMismatch(t *testing.T) {
	root, contract, raw := validSource(t)
	contract.Sources[0].Artifacts[0].SchemaID = "urn:not-the-pinned-schema"
	raw = mustJSON(contract)
	require.ErrorContains(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw), "contract artifact schema identity")
}

func TestFinalFixtureImportRejectsStaleSelfProvenance(t *testing.T) {
	root, contract, raw := validSource(t)
	manifest := []byte(`{"producer":{"name":"axym","version":"v1","commit":"commit-axym","tag":"v1"},"proof_commit":"stale"}`)
	require.NoError(t, os.WriteFile(filepath.Join(root, "axym", "manifest.json"), manifest, 0o600))
	require.Error(t, Update(root, filepath.Join(t.TempDir(), "fixture"), contract, raw))
}

func TestFinalFixtureImportVerifiesRealisticInlineLifecycleSignature(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	unsigned := map[string]any{
		"schema_id": "https://gait.dev/schemas/v1/runtime-lifecycle-record.schema.json", "schema_version": "1",
		"record_id": "", "kind": "execution", "occurred_at": "2026-08-01T12:00:00Z",
		"contract_ref": map[string]any{"kind": "action_contract", "id": "pac-1", "digest": "sha256:" + strings.Repeat("a", 64), "schema_id": "https://wrkr.dev/schema", "schema_version": "3", "source_product": "wrkr"},
		"signature":    map[string]any{"alg": "", "key_id": "", "sig": ""},
	}
	unsignedRaw, err := json.Marshal(unsigned)
	require.NoError(t, err)
	digestHex, err := prooffcanon.DigestHex(unsignedRaw, prooffcanon.DomainJSON)
	require.NoError(t, err)
	digestBytes, err := hex.DecodeString(digestHex)
	require.NoError(t, err)
	record := map[string]any{}
	for key, value := range unsigned {
		record[key] = value
	}
	record["record_id"] = "gait-record-1"
	record["signature"] = map[string]any{"alg": "ed25519", "key_id": testKeyID(public), "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, digestBytes)), "signed_digest": digestHex}
	raw, err := json.Marshal(record)
	require.NoError(t, err)
	require.NoError(t, verifyInlineSignatures(raw, public, true))
	record["signature"].(map[string]any)["sig"] = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	raw, err = json.Marshal(record)
	require.NoError(t, err)
	require.Error(t, verifyInlineSignatures(raw, public, true))
}

func TestFinalFixtureImportVerifiesInlineAxymPacketSignature(t *testing.T) {
	private, encodedPublic := testSigningKey("axym-packet")
	packet := []byte(`{"schema_id":"https://axym.dev/schemas/v1/governance/action-contract-evidence-packet.schema.json","schema_version":"v1","packet_id":"axym-packet-1","producer":"axym","digest":"","register_ref":{"kind":"axym.action_contract_register","id":"register-1","digest":"sha256:` + strings.Repeat("b", 64) + `","schema_id":"https://axym.dev/schemas/v1/governance/action-contract-register.schema.json","schema_version":"v1","source_product":"axym"}}`)
	packet = signTestPacket(t, packet, private)
	public, err := decodePublicKey(encodedPublic)
	require.NoError(t, err)
	require.NoError(t, verifyInlineSignatures(packet, public, true))
	var object map[string]any
	require.NoError(t, json.Unmarshal(packet, &object))
	object["packet_id"] = "mutated"
	mutated, err := json.Marshal(object)
	require.NoError(t, err)
	require.Error(t, verifyInlineSignatures(mutated, public, true))
}

func TestFinalFixtureImportVerifiesReleasedGaitTokenSignatures(t *testing.T) {
	base := filepath.Join("..", "..", "scenarios", "proof", "action-contract-gate-conformance", "source", "gait-gate-v1")
	keyRaw, err := os.ReadFile(filepath.Join(base, "fixture-signing-key.public.b64"))
	require.NoError(t, err)
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyRaw)))
	require.NoError(t, err)
	for _, name := range []string{"approval-exact.json", "delegation-root.json", "delegation-child-tightened.json"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(base, "source", name))
			require.NoError(t, err)
			require.NoError(t, verifyInlineSignatures(raw, ed25519.PublicKey(key), true))
		})
	}
}

func TestFinalFixtureImportVerifiesPresentSignatureWithoutKnownIdentityField(t *testing.T) {
	private, _ := testSigningKey("register")
	raw := []byte(`{"register_id":"register-1","schema_id":"urn:register-schema","schema_version":"1"}`)
	signed := signTestArtifact(t, raw, private)
	require.NoError(t, verifyInlineSignatures(signed, private.Public().(ed25519.PublicKey), true))
}

func TestFinalFixtureImportRejectsInlineSignatureWithoutPinnedPublicKey(t *testing.T) {
	private, _ := testSigningKey("missing-key")
	raw := []byte(`{"register_id":"register-1","schema_id":"urn:register-schema","schema_version":"1"}`)
	signed := signTestArtifact(t, raw, private)
	require.ErrorContains(t, verifyInlineSignatures(signed, nil, true), "valid pinned public key")
	var wrong ed25519.PublicKey = make([]byte, ed25519.PublicKeySize-1)
	require.ErrorContains(t, verifyInlineSignatures(signed, wrong, true), "valid pinned public key")
}

func TestFinalFixtureImportRejectsContractNonregularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contract")
	require.NoError(t, os.Mkdir(path, 0o750))
	var unsafeErr *UnsafeError
	_, err := ReadContractFile(path)
	require.ErrorAs(t, err, &unsafeErr)
}

func validSource(t *testing.T) (string, Contract, []byte) {
	t.Helper()
	root := t.TempDir()
	contract := Contract{Format: ContractFormat, FixtureID: "final-fixture-v1"}
	for _, product := range []string{"wrkr", "gait", "axym"} {
		s := Source{Product: product, Version: "v1", Commit: "commit-" + product, Tag: "v1", ManifestPath: "manifest.json"}
		dir := filepath.Join(root, product)
		require.NoError(t, os.MkdirAll(dir, 0o750))
		manifest := []byte(`{"producer":{"name":"` + product + `","version":"v1","commit":"commit-` + product + `","tag":"v1"}}`)
		var key []byte
		var private ed25519.PrivateKey
		if product == "wrkr" {
			s.IntegrityMode, s.PublicKeyPath = "manifest_digest", ""
			key = nil
		} else {
			s.IntegrityMode, s.PublicKeyPath = "inline_ed25519", "public.key"
			private, key = testSigningKey(product)
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, s.ManifestPath), manifest, 0o600))
		if s.PublicKeyPath != "" {
			require.NoError(t, os.WriteFile(filepath.Join(dir, s.PublicKeyPath), key, 0o600))
			s.PublicKeySHA256 = digest(key)
		}
		s.ManifestSHA256 = digest(manifest)
		schema := []byte(`{"$id":"urn:` + product + `-schema","x-proof-schema-version":"1"}`)
		schemaPath := "schema.json"
		require.NoError(t, os.WriteFile(filepath.Join(dir, schemaPath), schema, 0o600))
		s.Schemas = []File{{Path: schemaPath, SHA256: digest(schema), SchemaID: "urn:" + product + "-schema", SchemaVersion: "1"}}
		artifact := []byte(`{"schema_id":"urn:` + product + `-schema","schema_version":"1","record_id":"` + product + `-artifact","contracts":[],"relationship":{"kind":"` + product + `.contract","id":"` + product + `-1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_id":"urn:` + product + `-schema","schema_version":"1","source_product":"` + product + `"}}`)
		if private != nil {
			artifact = signTestArtifact(t, artifact, private)
		}
		artifactPath := "artifact.json"
		require.NoError(t, os.WriteFile(filepath.Join(dir, artifactPath), artifact, 0o600))
		a := Artifact{Path: artifactPath, SHA256: digest(artifact), Kind: "artifact", SchemaPath: schemaPath, SchemaSHA256: digest(schema), SchemaID: "urn:" + product + "-schema", SchemaVersion: "1", ProducerArtifact: true, RelationshipRefs: []Reference{{Kind: product + ".contract", ID: product + "-1", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SchemaID: "urn:" + product + "-schema", SchemaVersion: "1", SourceProduct: product}}}
		if product == "wrkr" {
			signature := []byte("signature-wrkr")
			a.SignaturePath, a.SignatureSHA256 = "signature.bin", digest(signature)
			require.NoError(t, os.WriteFile(filepath.Join(dir, a.SignaturePath), signature, 0o600))
		} else {
			a.SignatureRequired = true
		}
		if product == "axym" {
			registerSchemaPath := "register-schema.json"
			packetSchemaPath := "packet-schema.json"
			registerSchema := []byte(`{"$id":"` + AxymRegisterSchemaID + `","x-proof-schema-version":"v1"}`)
			packetSchema := []byte(`{"$id":"` + AxymPacketSchemaID + `","x-proof-schema-version":"v1"}`)
			require.NoError(t, os.WriteFile(filepath.Join(dir, registerSchemaPath), registerSchema, 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, packetSchemaPath), packetSchema, 0o600))
			s.Schemas = []File{
				{Path: registerSchemaPath, SHA256: digest(registerSchema), SchemaID: AxymRegisterSchemaID, SchemaVersion: AxymSchemaVersion},
				{Path: packetSchemaPath, SHA256: digest(packetSchema), SchemaID: AxymPacketSchemaID, SchemaVersion: AxymSchemaVersion},
			}
			artifact = []byte(`{"schema_id":"` + AxymRegisterSchemaID + `","schema_version":"` + AxymSchemaVersion + `","record_id":"axym-register","contracts":[]}`)
			artifact = signTestArtifact(t, artifact, private)
			require.NoError(t, os.WriteFile(filepath.Join(dir, artifactPath), artifact, 0o600))
			a = Artifact{Path: artifactPath, SHA256: digest(artifact), Kind: "assessment_register", SchemaPath: registerSchemaPath, SchemaSHA256: digest(registerSchema), SchemaID: AxymRegisterSchemaID, SchemaVersion: AxymSchemaVersion, ProducerArtifact: true, SignatureRequired: true}
			a.Kind = "assessment_register"
			s.Artifacts = append(s.Artifacts, a)
			packet := a
			packet.Path = "packet.json"
			packet.Kind = "evidence_packet"
			packet.SchemaPath = packetSchemaPath
			packet.SchemaSHA256 = digest(packetSchema)
			packet.SchemaID = AxymPacketSchemaID
			packet.SchemaVersion = AxymSchemaVersion
			packet.RelationshipRefs = nil
			packetBytes := []byte(`{"schema_id":"` + AxymPacketSchemaID + `","schema_version":"` + AxymSchemaVersion + `","packet_id":"axym-packet","packet":"axym"}`)
			packetBytes = signTestArtifact(t, packetBytes, private)
			packet.SHA256 = digest(packetBytes)
			require.NoError(t, os.WriteFile(filepath.Join(dir, packet.Path), packetBytes, 0o600))
			s.Artifacts = append(s.Artifacts, packet)
		} else {
			s.Artifacts = []Artifact{a}
		}
		contract.Sources = append(contract.Sources, s)
	}
	raw := mustJSON(contract)
	return root, contract, raw
}

func sourceFor(c *Contract, product string) *Source {
	for i := range c.Sources {
		if c.Sources[i].Product == product {
			return &c.Sources[i]
		}
	}
	panic("missing source")
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return raw
}

func testDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func testKeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:])
}

func testSigningKey(product string) (ed25519.PrivateKey, []byte) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1 + len(product))
	}
	private := ed25519.NewKeyFromSeed(seed)
	return private, []byte(hex.EncodeToString(private.Public().(ed25519.PublicKey)))
}

func signTestArtifact(t *testing.T, raw []byte, private ed25519.PrivateKey) []byte {
	t.Helper()
	var object map[string]any
	require.NoError(t, json.Unmarshal(raw, &object))
	identity, hasIdentity := object["record_id"]
	if hasIdentity {
		object["record_id"] = ""
	}
	object["signature"] = map[string]any{"alg": "", "key_id": "", "sig": ""}
	unsigned, err := json.Marshal(object)
	require.NoError(t, err)
	digestHex, err := prooffcanon.DigestHex(unsigned, prooffcanon.DomainJSON)
	require.NoError(t, err)
	digestBytes, err := hex.DecodeString(digestHex)
	require.NoError(t, err)
	if hasIdentity {
		object["record_id"] = identity
	}
	object["signature"] = map[string]any{"alg": "ed25519", "key_id": testKeyID(private.Public().(ed25519.PublicKey)), "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, digestBytes)), "signed_digest": digestHex}
	signed, err := json.Marshal(object)
	require.NoError(t, err)
	return signed
}

func signTestPacket(t *testing.T, raw []byte, private ed25519.PrivateKey) []byte {
	t.Helper()
	var object map[string]any
	require.NoError(t, json.Unmarshal(raw, &object))
	delete(object, "signature")
	delete(object, "digest")
	unsigned, err := json.Marshal(object)
	require.NoError(t, err)
	digestHex, err := prooffcanon.DigestHex(unsigned, prooffcanon.DomainJSON)
	require.NoError(t, err)
	digestBytes, err := hex.DecodeString(digestHex)
	require.NoError(t, err)
	object["digest"] = "sha256:" + digestHex
	object["signature"] = map[string]any{"alg": "ed25519", "key_id": testKeyID(private.Public().(ed25519.PublicKey)), "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, digestBytes)), "signed_digest": digestHex}
	signed, err := json.Marshal(object)
	require.NoError(t, err)
	return signed
}
