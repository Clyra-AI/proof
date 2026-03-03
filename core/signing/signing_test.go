package signing

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/Clyra-AI/proof/core/record"
	"github.com/stretchr/testify/require"
)

func TestDeterministicEd25519Signature(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	key := SigningKey{Private: priv, Public: pub}

	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "test",
		SourceProduct: "test",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)

	r1 := record.Clone(r)
	r2 := record.Clone(r)
	_, err = Sign(r1, key)
	require.NoError(t, err)
	_, err = Sign(r2, key)
	require.NoError(t, err)
	require.Equal(t, r1.Integrity.Signature, r2.Integrity.Signature)
}

func TestDeterministicVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	key := SigningKey{Private: priv, Public: pub, KeyID: "issuer:test:20260101"}

	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "determinism",
		SourceProduct: "proof",
		Type:          "decision",
		Event: map[string]any{
			"action": "allow",
			"actor":  "agent-1",
		},
	})
	require.NoError(t, err)
	_, err = Sign(r, key)
	require.NoError(t, err)

	require.Equal(t, "prf-2026-02-17T12:00:00Z-25de6aab", r.RecordID)
	require.Equal(t, "sha256:84b7caf5dd46e4520ec1083971c93adb5f6181d1e72885be5903359955c8a28c", r.Integrity.RecordHash)
	require.Equal(t, "issuer:test:20260101", r.Integrity.SigningKeyID)
	require.Equal(t, "base64:0AF7w/sErJ1xz/TLN1hGH2btxbrKjth95R/jSdNyQo/+YWbX4U6iQ5shOHVFNEvPsRw2j9e6gQCE1H4PIb13CA==", r.Integrity.Signature)
}

func TestSignAndVerifyDigest(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	sig, err := SignDigest("abcd1234", key)
	require.NoError(t, err)
	err = VerifyDigest(sig, "abcd1234", PublicKey{Public: key.Public})
	require.NoError(t, err)
}

func TestVerifyDigestTypedError(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	sig, err := SignDigest("abcd1234", key)
	require.NoError(t, err)

	err = VerifyDigest(sig, "different", PublicKey{Public: key.Public})
	require.Error(t, err)
	typed, ok := coreerr.As(err)
	require.True(t, ok)
	require.Equal(t, coreerr.KindVerification, typed.Kind)
}

func TestGenerateKeyErrorBranch(t *testing.T) {
	orig := crand.Reader
	t.Cleanup(func() { crand.Reader = orig })
	crand.Reader = errorReader{}

	_, err := GenerateKey()
	require.Error(t, err)
}

func TestRevocationListLifecycle(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	list, err := SignRevocationList(RevocationList{
		Version:   "1.0",
		CreatedAt: "2026-02-17T12:00:00Z",
		Revoked: []RevocationEntry{
			{KeyID: key.KeyID, RevokedAt: "2026-02-17T12:10:00Z", Reason: "rotation"},
		},
	}, key)
	require.NoError(t, err)

	require.NoError(t, VerifyRevocationList(list, PublicKey{Public: key.Public}))

	revoked := IsRevoked(list, key.KeyID, time.Date(2026, 2, 17, 12, 11, 0, 0, time.UTC))
	require.True(t, revoked)
	notRevokedYet := IsRevoked(list, key.KeyID, time.Date(2026, 2, 17, 12, 9, 0, 0, time.UTC))
	require.False(t, notRevokedYet)
}

func TestSignAndVerifyRecord(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)

	_, err = Sign(r, key)
	require.NoError(t, err)
	err = Verify(r, PublicKey{Public: key.Public})
	require.NoError(t, err)
}

func TestVerifyFailsOnMismatchedKey(t *testing.T) {
	keyA, err := GenerateKey()
	require.NoError(t, err)
	keyB, err := GenerateKey()
	require.NoError(t, err)
	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	_, err = Sign(r, keyA)
	require.NoError(t, err)
	err = Verify(r, PublicKey{Public: keyB.Public})
	require.Error(t, err)
}

func TestCosignSignAndVerifyViaMockRunner(t *testing.T) {
	origLookPath := cosignLookPath
	origRun := cosignRun
	t.Cleanup(func() {
		cosignLookPath = origLookPath
		cosignRun = origRun
	})

	cosignLookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	cosignRun = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "sign-blob" {
			for i := 0; i < len(args)-1; i++ {
				if args[i] == "--output-signature" {
					if err := os.WriteFile(args[i+1], []byte("sigbytes"), 0o600); err != nil {
						return nil, err
					}
				}
			}
			return []byte("ok"), nil
		}
		return []byte("verified"), nil
	}

	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	_, err = SignRecordCosign(r, "/tmp/cosign.key")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(r.Integrity.Signature, "cosign:"))

	err = VerifyRecordCosign(r, CosignVerifyOpts{KeyPath: "/tmp/cosign.pub"})
	require.NoError(t, err)
}

func TestCosignErrors(t *testing.T) {
	origLookPath := cosignLookPath
	origRun := cosignRun
	t.Cleanup(func() {
		cosignLookPath = origLookPath
		cosignRun = origRun
	})
	cosignLookPath = func(file string) (string, error) { return "", errors.New("missing") }

	_, err := SignRecordCosign(nil, "")
	require.Error(t, err)
	r, _ := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	err = VerifyRecordCosign(r, CosignVerifyOpts{KeyPath: filepath.Join(t.TempDir(), "pub")})
	require.Error(t, err)

	cosignLookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	cosignRun = func(args ...string) ([]byte, error) { return nil, errors.New("boom") }
	r.Integrity.Signature = "cosign:abc"
	r.Integrity.RecordHash, _ = record.ComputeHash(r)
	err = VerifyRecordCosign(r, CosignVerifyOpts{KeyPath: "/tmp/cosign.pub"})
	require.Error(t, err)
}

func TestVerifyErrorsOnIncompleteRecord(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	r.Integrity.Signature = ""
	err = Verify(r, PublicKey{Public: key.Public})
	require.Error(t, err)
}

func TestVerifyDigestErrors(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	sig, err := SignDigest("abcd", key)
	require.NoError(t, err)
	err = VerifyDigest(sig, "zzz", PublicKey{Public: key.Public})
	require.Error(t, err)
}

func TestSigningEdgeCases(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	// Normalize key id variants.
	require.Equal(t, key.KeyID, NormalizeKeyID("", key.Public))
	require.Equal(t, "issuer:kid:20260101", NormalizeKeyID("issuer:kid:20260101", key.Public))
	require.Equal(t, key.KeyID, NormalizeKeyID("invalid", key.Public))

	_, err = Sign(nil, key)
	require.Error(t, err)
	_, err = Sign(&record.Record{}, SigningKey{})
	require.Error(t, err)
	_, err = SignDigest("", key)
	require.Error(t, err)

	sig, err := SignDigest("abcd", key)
	require.NoError(t, err)
	sig.Alg = "rsa"
	err = VerifyDigest(sig, "abcd", PublicKey{Public: key.Public})
	require.Error(t, err)

	sig.Alg = "ed25519"
	sig.KeyID = "wrong"
	err = VerifyDigest(sig, "abcd", PublicKey{Public: key.Public})
	require.Error(t, err)

	sig.KeyID = key.KeyID
	sig.Sig = "%%%not-base64"
	err = VerifyDigest(sig, "abcd", PublicKey{Public: key.Public})
	require.Error(t, err)

	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	r.Integrity.RecordHash = "sha256:bad"
	r.Integrity.Signature = "base64:abcd"
	r.Integrity.SigningKeyID = key.KeyID
	err = Verify(r, PublicKey{Public: key.Public})
	require.Error(t, err)
}

func TestSignRevocationListDefaultsAndParseFailureBehavior(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	list, err := SignRevocationList(RevocationList{
		Revoked: []RevocationEntry{
			{KeyID: key.KeyID, RevokedAt: "not-a-timestamp"},
		},
	}, key)
	require.NoError(t, err)
	require.Equal(t, "1.0", list.Version)
	require.NotEmpty(t, list.CreatedAt)
	require.True(t, IsRevoked(list, key.KeyID, time.Now().UTC()))
}

func TestVerifyRecordDecodeSignatureError(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	_, err = Sign(r, key)
	require.NoError(t, err)

	r.Integrity.Signature = "base64:not-valid%%"
	err = Verify(r, PublicKey{Public: key.Public})
	require.Error(t, err)
}

func TestCosignAdditionalBranches(t *testing.T) {
	origLookPath := cosignLookPath
	origRun := cosignRun
	t.Cleanup(func() {
		cosignLookPath = origLookPath
		cosignRun = origRun
	})

	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)

	_, err = SignRecordCosign(r, "")
	require.Error(t, err)

	cosignLookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }

	r.Integrity.Signature = "base64:abc"
	err = VerifyRecordCosign(r, CosignVerifyOpts{KeyPath: "/tmp/cosign.pub"})
	require.ErrorContains(t, err, "does not contain cosign signature")

	r.Integrity.Signature = "cosign:abc"
	r.Integrity.RecordHash = "sha256:tampered"
	err = VerifyRecordCosign(r, CosignVerifyOpts{KeyPath: "/tmp/cosign.pub"})
	require.ErrorContains(t, err, "record hash mismatch")

	r.Integrity.RecordHash, err = record.ComputeHash(r)
	require.NoError(t, err)
	err = VerifyRecordCosign(r, CosignVerifyOpts{})
	require.ErrorContains(t, err, "requires --cosign-key or --cosign-cert")

	var gotArgs []string
	cosignRun = func(args ...string) ([]byte, error) {
		gotArgs = append([]string{}, args...)
		return []byte("verified"), nil
	}
	err = VerifyRecordCosign(r, CosignVerifyOpts{
		CertificatePath:     "/tmp/cert.pem",
		CertificateIdentity: "issuer.example/user@example.com",
		CertificateIssuer:   "https://token.actions.githubusercontent.com",
	})
	require.NoError(t, err)
	require.Contains(t, strings.Join(gotArgs, " "), "--certificate /tmp/cert.pem")
	require.Contains(t, strings.Join(gotArgs, " "), "--certificate-identity issuer.example/user@example.com")
	require.Contains(t, strings.Join(gotArgs, " "), "--certificate-oidc-issuer https://token.actions.githubusercontent.com")
}

func TestSignAndSignDigestDerivePublicKeyBranch(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)

	derivedKey := SigningKey{Private: key.Private, KeyID: "issuer:kid:20260101"}
	_, err = Sign(r, derivedKey)
	require.NoError(t, err)
	require.Equal(t, "issuer:kid:20260101", r.Integrity.SigningKeyID)

	sig, err := SignDigest("abcd", SigningKey{Private: key.Private})
	require.NoError(t, err)
	require.NotEmpty(t, sig.KeyID)
}

func TestSignBranchWithPrecomputedHashAndPublicKey(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)

	r.Integrity.RecordHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, err = Sign(r, SigningKey{Private: key.Private, Public: key.Public, KeyID: key.KeyID})
	require.NoError(t, err)
	require.NotEmpty(t, r.Integrity.Signature)
}

func TestCosignSignFailureBranches(t *testing.T) {
	origLookPath := cosignLookPath
	origRun := cosignRun
	t.Cleanup(func() {
		cosignLookPath = origLookPath
		cosignRun = origRun
	})

	cosignLookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	cosignRun = func(args ...string) ([]byte, error) {
		return []byte("boom"), errors.New("sign failed")
	}

	r, err := record.New(record.RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 14, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	_, err = SignRecordCosign(r, "/tmp/cosign.key")
	require.ErrorContains(t, err, "cosign sign-blob failed")

	cosignRun = func(args ...string) ([]byte, error) { return []byte("ok"), nil }
	_, err = SignRecordCosign(r, "/tmp/cosign.key")
	require.Error(t, err)
}

func TestVerifyDigestCosignValidationBranches(t *testing.T) {
	origLookPath := cosignLookPath
	t.Cleanup(func() { cosignLookPath = origLookPath })
	cosignLookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }

	err := VerifyDigestCosign(Signature{Alg: "cosign", Sig: "abc", SignedDigest: "deadbeef"}, "deadbeef", CosignVerifyOpts{})
	require.ErrorContains(t, err, "requires --cosign-key or --cosign-cert")

	err = VerifyDigestCosign(Signature{Alg: "cosign", Sig: "abc"}, "deadbeef", CosignVerifyOpts{KeyPath: "/tmp/pub"})
	require.ErrorContains(t, err, "signed digest is required")

	err = VerifyDigestCosign(Signature{Alg: "cosign", Sig: "abc", SignedDigest: "bad"}, "deadbeef", CosignVerifyOpts{KeyPath: "/tmp/pub"})
	require.ErrorContains(t, err, "signed digest mismatch")
}

func TestSignAndVerifyDigestCosignWithMockRunner(t *testing.T) {
	origLookPath := cosignLookPath
	origRun := cosignRun
	t.Cleanup(func() {
		cosignLookPath = origLookPath
		cosignRun = origRun
	})

	cosignLookPath = func(file string) (string, error) { return "/usr/bin/cosign", nil }
	cosignRun = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "sign-blob" {
			for i := 0; i < len(args)-1; i++ {
				if args[i] == "--output-signature" {
					if err := os.WriteFile(args[i+1], []byte("sigbytes"), 0o600); err != nil {
						return nil, err
					}
				}
			}
			return []byte("ok"), nil
		}
		return []byte("verified"), nil
	}

	sig, err := SignDigestCosign("sha256:abcd", "/tmp/cosign.key")
	require.NoError(t, err)
	require.Equal(t, "cosign", sig.Alg)
	require.Equal(t, "sha256:abcd", sig.SignedDigest)

	err = VerifyDigestCosign(sig, "sha256:abcd", CosignVerifyOpts{
		CertificatePath:     "/tmp/cert.pem",
		CertificateIdentity: "issuer.example/user@example.com",
		CertificateIssuer:   "https://token.actions.githubusercontent.com",
	})
	require.NoError(t, err)
}

func TestSignDigestCosignErrorBranches(t *testing.T) {
	origLookPath := cosignLookPath
	t.Cleanup(func() { cosignLookPath = origLookPath })

	_, err := SignDigestCosign("sha256:abcd", "")
	require.ErrorContains(t, err, "cosign key path is required")

	cosignLookPath = func(file string) (string, error) { return "", errors.New("missing") }
	_, err = SignDigestCosign("sha256:abcd", "/tmp/cosign.key")
	require.ErrorContains(t, err, "cosign binary not found")
}

func TestIsDependencyMissing(t *testing.T) {
	origLookPath := cosignLookPath
	t.Cleanup(func() { cosignLookPath = origLookPath })

	cosignLookPath = func(file string) (string, error) { return "", errors.New("missing") }
	_, err := SignDigestCosign("sha256:abcd", "/tmp/cosign.key")
	require.Error(t, err)
	require.True(t, IsDependencyMissing(err))
	require.False(t, IsDependencyMissing(errors.New("other error")))
}

func TestVerifyRecordCosignNilAndPrefixBranches(t *testing.T) {
	err := VerifyRecordCosign(nil, CosignVerifyOpts{KeyPath: "/tmp/pub"})
	require.ErrorContains(t, err, "record is nil")

	r := &record.Record{}
	err = VerifyRecordCosign(r, CosignVerifyOpts{KeyPath: "/tmp/pub"})
	require.ErrorContains(t, err, "does not contain cosign signature")
}

func TestVerifyRevocationListErrorBranch(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	list, err := SignRevocationList(RevocationList{
		Version:   "1.0",
		CreatedAt: "2026-02-17T12:00:00Z",
		Revoked: []RevocationEntry{
			{KeyID: key.KeyID, RevokedAt: "2026-02-17T12:10:00Z"},
		},
	}, key)
	require.NoError(t, err)

	list.Signature.SignedDigest = "tampered"
	err = VerifyRevocationList(list, PublicKey{Public: key.Public})
	require.Error(t, err)
}

type errorReader struct{}

func (errorReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
