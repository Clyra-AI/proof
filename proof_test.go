package proof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewRecordDeterministicID(t *testing.T) {
	ts := time.Date(2026, 2, 17, 12, 30, 0, 0, time.UTC)
	opts := RecordOpts{
		Timestamp:     ts,
		Source:        "axym-mcp-collector",
		SourceProduct: "axym",
		Type:          "tool_invocation",
		Event:         map[string]any{"tool": "postgres_query", "action": "SELECT"},
	}
	r1, err := NewRecord(opts)
	require.NoError(t, err)
	r2, err := NewRecord(opts)
	require.NoError(t, err)
	require.Equal(t, r1.RecordID, r2.RecordID)
}

func TestChainTamperDetection(t *testing.T) {
	c := NewChain("test")
	r1, _ := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 10, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "scan_finding",
		Event:         map[string]any{"id": "f1"},
	})
	r2, _ := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 10, 1, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"id": "d1"},
	})
	require.NoError(t, AppendToChain(c, r1))
	require.NoError(t, AppendToChain(c, r2))

	c.Records[1].Event["id"] = "tampered"
	v, err := VerifyChain(c)
	require.NoError(t, err)
	require.False(t, v.Intact)
	require.Equal(t, 1, v.BreakIndex)
}

func TestSignAndVerify(t *testing.T) {
	c := NewChain("test")
	r, _ := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 10, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
	})
	require.NoError(t, AppendToChain(c, r))

	key, err := GenerateSigningKey()
	require.NoError(t, err)
	signed, err := Sign(&c.Records[0], key)
	require.NoError(t, err)
	err = Verify(signed, PublicKey{Public: key.Public})
	require.NoError(t, err)
}

func TestSignAndVerifyChainSignature(t *testing.T) {
	c := NewChain("chain-sign")
	r, _ := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 13, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, AppendToChain(c, r))
	key, err := GenerateSigningKey()
	require.NoError(t, err)
	sig, err := SignChain(c, key)
	require.NoError(t, err)
	require.NoError(t, VerifyChainSignature(c, sig, PublicKey{Public: key.Public}))
}

func TestAPIHelpers(t *testing.T) {
	_, err := Canonicalize([]byte(`{"b":2,"a":1}`), DomainJSON)
	require.NoError(t, err)

	types := ListRecordTypes()
	require.NotEmpty(t, types)

	f, err := LoadFramework("eu-ai-act")
	require.NoError(t, err)
	require.Equal(t, "eu-ai-act", f.Framework.ID)
}

func TestWriteReadAndCustomSchemaValidation(t *testing.T) {
	ResetCustomTypes()
	t.Cleanup(ResetCustomTypes)

	r, err := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)

	p := filepath.Join(t.TempDir(), "record.json")
	require.NoError(t, WriteRecord(p, r))
	read, err := ReadRecord(p)
	require.NoError(t, err)
	require.Equal(t, r.RecordID, read.RecordID)

	schemaPath := filepath.Join(t.TempDir(), "custom.schema.json")
	require.NoError(t, os.WriteFile(schemaPath, []byte(`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`), 0o644))
	require.NoError(t, ValidateCustomTypeSchema(schemaPath))

	customTypePath := filepath.Join(t.TempDir(), "custom-type.schema.json")
	require.NoError(t, os.WriteFile(customTypePath, []byte(`{
	  "$schema":"http://json-schema.org/draft-07/schema#",
	  "type":"object",
	  "required":["record_type","event"],
	  "properties":{
	    "record_type":{"const":"vendor.custom_event"},
	    "event":{
	      "type":"object",
	      "required":["custom_value"],
	      "properties":{"custom_value":{"type":"string"}}
	    }
	  }
	}`), 0o644))
	require.NoError(t, RegisterCustomTypeSchema("vendor.custom_event", customTypePath))
	customRecord, err := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 1, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "vendor.custom_event",
		Event:         map[string]any{"custom_value": "ok"},
	})
	require.NoError(t, err)
	require.Equal(t, "vendor.custom_event", customRecord.RecordType)
}

func TestRevocationListAPI(t *testing.T) {
	key, err := GenerateSigningKey()
	require.NoError(t, err)
	list, err := SignRevocationList(RevocationList{
		Version:   "1.0",
		CreatedAt: "2026-02-17T12:00:00Z",
		Revoked: []RevocationEntry{
			{KeyID: key.KeyID, RevokedAt: "2026-02-17T12:10:00Z"},
		},
	}, key)
	require.NoError(t, err)
	require.NoError(t, VerifyRevocationList(list, PublicKey{Public: key.Public}))
	require.True(t, IsKeyRevoked(list, key.KeyID, time.Date(2026, 2, 17, 12, 11, 0, 0, time.UTC)))
}

func TestAdditionalWrappers(t *testing.T) {
	r, err := NewRecord(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	_, err = ComputeRecordHash(r)
	require.NoError(t, err)

	c := NewChain("wrapper")
	require.NoError(t, AppendToChain(c, r))
	_, err = VerifyChainRange(c, time.Date(2026, 2, 17, 11, 59, 0, 0, time.UTC), time.Date(2026, 2, 17, 12, 1, 0, 0, time.UTC))
	require.NoError(t, err)

	_, err = SignCosign(nil, "")
	require.Error(t, err)
	err = VerifyCosign(nil, "")
	require.Error(t, err)
	err = VerifyCosignWithOptions(nil, CosignVerifyOpts{})
	require.Error(t, err)
}

func TestDigestWrappers(t *testing.T) {
	d, err := DigestValue([]byte(`{"b":2,"a":1}`), DomainJSON, "rotation-q1")
	require.NoError(t, err)
	require.Equal(t, "sha256", d.AlgoID)
	require.Equal(t, "rotation-q1", d.SaltID)
	require.Len(t, d.Value, 64)

	h, err := DigestHMACValue([]byte("sensitive"), DomainText, []byte("secret-key"), "salt-1")
	require.NoError(t, err)
	require.Equal(t, "hmac-sha256", h.AlgoID)
	require.Equal(t, "salt-1", h.SaltID)
	require.Len(t, h.Value, 64)
}

func TestBundleSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "records.jsonl"), []byte("{}\n"), 0o644))

	manifest := BundleManifest{
		Files: []BundleManifestEntry{
			{Path: "records.jsonl", SHA256: "sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"},
		},
		AlgoID: "sha256",
		SaltID: "test-salt",
	}
	raw, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644))

	key, err := GenerateSigningKey()
	require.NoError(t, err)
	_, err = SignBundle(dir, key)
	require.NoError(t, err)

	_, err = VerifyBundle(dir, BundleVerifyOpts{
		VerifySignatures: true,
		PublicKey:        PublicKey{Public: key.Public},
	})
	require.NoError(t, err)
}

func TestRegisterCustomTypeInline(t *testing.T) {
	ResetCustomTypes()
	t.Cleanup(ResetCustomTypes)

	require.NoError(t, RegisterCustomType("vendor.inline_event", []byte(`{
	  "$schema":"http://json-schema.org/draft-07/schema#",
	  "type":"object",
	  "required":["record_type"],
	  "properties":{"record_type":{"const":"vendor.inline_event"}}
	}`)))
	require.Error(t, RegisterCustomType("", []byte(`{}`)))
}

func TestVerifyBundleErrorBranches(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "records.jsonl"), []byte("{}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"files":[{"path":"records.jsonl","sha256":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}]}`), 0o644))

	_, err := VerifyBundle(dir, BundleVerifyOpts{})
	require.Error(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"algo_id":"sha512","files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}]}`), 0o644))
	_, err = VerifyBundle(dir, BundleVerifyOpts{})
	require.ErrorContains(t, err, "unsupported bundle digest algorithm")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}]}`), 0o644))
	_, err = VerifyBundle(dir, BundleVerifyOpts{VerifySignatures: true})
	require.ErrorContains(t, err, "has no signatures")
}

func TestBundleCosignBranches(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "records.jsonl"), []byte("{}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{
	  "files":[{"path":"records.jsonl","sha256":"sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"}],
	  "signatures":[{"alg":"cosign","key_id":"cosign:test","sig":"sig","signed_digest":"deadbeef"}]
	}`), 0o644))

	_, err := VerifyBundle(dir, BundleVerifyOpts{VerifySignatures: true})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "signed digest mismatch") || strings.Contains(err.Error(), "requires --cosign-key or --cosign-cert"))

	_, err = SignBundleCosign(dir, "")
	require.ErrorContains(t, err, "cosign key path is required")
}
