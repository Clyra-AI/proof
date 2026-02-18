package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coresigning "github.com/Clyra-AI/proof/core/signing"
	"github.com/stretchr/testify/require"
)

func TestSignAndVerifyBytes(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	sig := SignBytes(kp.Private, []byte("hello"))
	ok, err := VerifyBytes(kp.Public, sig, []byte("hello"))
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = VerifyBytes(kp.Public, sig, []byte("bye"))
	require.NoError(t, err)
	require.False(t, ok)
}

func TestSignAndVerifyDigestHex(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	sig, err := SignDigestHex(kp.Private, "b94d27b9934d3e08a52e52d7da7dabfade4f7f4a6d7f5d8f7e0e28f1a6f7a4f7")
	require.NoError(t, err)

	ok, err := VerifyDigestHex(kp.Public, sig)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestSignAndVerifyJSON(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	obj := map[string]any{"b": 2, "a": 1}
	raw, err := json.Marshal(obj)
	require.NoError(t, err)

	sig, err := SignJSON(kp.Private, raw)
	require.NoError(t, err)

	ok, err := VerifyJSON(kp.Public, sig, raw)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestKeyLoadingAndModes(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.key")
	pubPath := filepath.Join(dir, "pub.key")
	require.NoError(t, os.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(kp.Private)), 0o600))
	require.NoError(t, os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(kp.Public)), 0o600))

	loaded, warns, err := LoadSigningKey(KeyConfig{Mode: ModeProd, PrivateKeyPath: privPath, PublicKeyPath: pubPath})
	require.NoError(t, err)
	require.Empty(t, warns)
	require.Equal(t, kp.Public, loaded.Public)

	pub, err := LoadVerifyKey(KeyConfig{PublicKeyPath: pubPath})
	require.NoError(t, err)
	require.Equal(t, kp.Public, pub)

	dev, warns, err := LoadSigningKey(KeyConfig{Mode: ModeDev})
	require.NoError(t, err)
	require.NotEmpty(t, dev.Private)
	require.Equal(t, []string{DevKeyWarning}, warns)
}

func TestKeyIDParityWithCoreSigning(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	require.Equal(t, coresigning.KeyID(pub), KeyID(pub))
}

func TestSignatureWrappersAndErrorBranches(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	obj := map[string]any{"x": 1}
	raw, err := json.Marshal(obj)
	require.NoError(t, err)

	manifestSig, err := SignManifestJSON(kp.Private, raw)
	require.NoError(t, err)
	ok, err := VerifyManifestJSON(kp.Public, manifestSig, raw)
	require.NoError(t, err)
	require.True(t, ok)

	traceSig, err := SignTraceRecordJSON(kp.Private, raw)
	require.NoError(t, err)
	ok, err = VerifyTraceRecordJSON(kp.Public, traceSig, raw)
	require.NoError(t, err)
	require.True(t, ok)

	_, err = VerifyJSON(kp.Public, Signature{}, raw)
	require.Error(t, err)

	bad := manifestSig
	bad.SignedDigest = "deadbeef"
	_, err = VerifyJSON(kp.Public, bad, raw)
	require.Error(t, err)
}

func TestVerifyBytesAndDigestErrors(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	sig := SignBytes(kp.Private, []byte("abc"))

	_, err = VerifyBytes(kp.Public, Signature{Alg: "rsa", Sig: sig.Sig, KeyID: sig.KeyID}, []byte("abc"))
	require.Error(t, err)

	_, err = VerifyBytes(kp.Public, Signature{Alg: AlgEd25519, Sig: sig.Sig, KeyID: "wrong"}, []byte("abc"))
	require.Error(t, err)

	_, err = VerifyBytes(kp.Public, Signature{Alg: AlgEd25519, Sig: "%%%bad", KeyID: sig.KeyID}, []byte("abc"))
	require.Error(t, err)

	tooShort := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err = VerifyBytes(kp.Public, Signature{Alg: AlgEd25519, Sig: tooShort, KeyID: sig.KeyID}, []byte("abc"))
	require.Error(t, err)

	_, err = SignDigestHex(kp.Private, "bad")
	require.Error(t, err)

	_, err = SignDigestHex(kp.Private, "abcd")
	require.Error(t, err)

	_, err = VerifyDigestHex(kp.Public, Signature{})
	require.Error(t, err)

	_, err = VerifyDigestHex(kp.Public, Signature{SignedDigest: "bad"})
	require.Error(t, err)

	_, err = VerifyDigestHex(kp.Public, Signature{SignedDigest: "abcd"})
	require.Error(t, err)
}

func TestLoadSigningAndVerifyKeyErrors(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.key")
	pubPath := filepath.Join(dir, "pub.key")
	otherPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	otherPubPath := filepath.Join(dir, "other-pub.key")

	require.NoError(t, os.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(kp.Private)), 0o600))
	require.NoError(t, os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(kp.Public)), 0o600))
	require.NoError(t, os.WriteFile(otherPubPath, []byte(base64.StdEncoding.EncodeToString(otherPub)), 0o600))

	_, _, err = LoadSigningKey(KeyConfig{Mode: ModeDev, PrivateKeyPath: privPath})
	require.Error(t, err)

	_, _, err = LoadSigningKey(KeyConfig{Mode: ModeProd})
	require.Error(t, err)

	_, _, err = LoadSigningKey(KeyConfig{Mode: "invalid"})
	require.Error(t, err)

	_, _, err = LoadSigningKey(KeyConfig{Mode: ModeProd, PrivateKeyPath: privPath, PublicKeyPath: otherPubPath})
	require.Error(t, err)

	_, _, err = LoadSigningKey(KeyConfig{Mode: ModeProd, PrivateKeyPath: privPath, PrivateKeyEnv: "PROOF_SIGNING_KEY"})
	require.Error(t, err)

	_, err = LoadVerifyKey(KeyConfig{})
	require.Error(t, err)

	_, err = LoadVerifyKey(KeyConfig{PublicKeyPath: pubPath, PublicKeyEnv: "PROOF_PUB_KEY"})
	require.Error(t, err)

	_, err = LoadVerifyKey(KeyConfig{PrivateKeyPath: privPath, PrivateKeyEnv: "PROOF_PRIV_KEY"})
	require.Error(t, err)

	require.NoError(t, os.Setenv("PROOF_SIGNING_PRIV", base64.StdEncoding.EncodeToString(kp.Private)))
	require.NoError(t, os.Setenv("PROOF_SIGNING_PUB", base64.StdEncoding.EncodeToString(kp.Public)))
	t.Cleanup(func() {
		_ = os.Unsetenv("PROOF_SIGNING_PRIV")
		_ = os.Unsetenv("PROOF_SIGNING_PUB")
		_ = os.Unsetenv("PROOF_MISSING_PRIV")
		_ = os.Unsetenv("PROOF_MISSING_PUB")
	})

	loaded, warns, err := LoadSigningKey(KeyConfig{Mode: ModeProd, PrivateKeyEnv: "PROOF_SIGNING_PRIV", PublicKeyEnv: "PROOF_SIGNING_PUB"})
	require.NoError(t, err)
	require.Empty(t, warns)
	require.Equal(t, kp.Public, loaded.Public)

	pub, err := LoadVerifyKey(KeyConfig{PublicKeyEnv: "PROOF_SIGNING_PUB"})
	require.NoError(t, err)
	require.Equal(t, kp.Public, pub)

	pub, err = LoadVerifyKey(KeyConfig{PrivateKeyEnv: "PROOF_SIGNING_PRIV"})
	require.NoError(t, err)
	require.Equal(t, kp.Public, pub)

	_, _, err = LoadSigningKey(KeyConfig{Mode: ModeProd, PrivateKeyEnv: "PROOF_MISSING_PRIV"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "private key env not set")

	_, err = LoadVerifyKey(KeyConfig{PublicKeyEnv: "PROOF_MISSING_PUB"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "public key env not set")
}

func TestParseAndLoadKeyErrors(t *testing.T) {
	_, err := ParsePrivateKeyBase64("not-base64")
	require.Error(t, err)
	_, err = ParsePublicKeyBase64("not-base64")
	require.Error(t, err)

	_, err = ParsePrivateKeyBase64(base64.StdEncoding.EncodeToString([]byte("short")))
	require.Error(t, err)
	_, err = ParsePublicKeyBase64(base64.StdEncoding.EncodeToString([]byte("short")))
	require.Error(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "trimmed.key")

	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, []byte(" \n\t"+base64.StdEncoding.EncodeToString(kp.Public)+" \r\n"), 0o600))
	pub, err := LoadPublicKeyBase64(path)
	require.NoError(t, err)
	require.Equal(t, kp.Public, pub)

	require.NoError(t, os.WriteFile(path, []byte(" \n\t"+base64.StdEncoding.EncodeToString(kp.Private)+" \r\n"), 0o600))
	priv, err := LoadPrivateKeyBase64(path)
	require.NoError(t, err)
	require.Equal(t, kp.Private, priv)

	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("x", 20)), 0o600))
	_, err = LoadPrivateKeyBase64(path)
	require.Error(t, err)
}
