package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const AlgEd25519 = "ed25519"

type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

type Signature struct {
	Alg          string `json:"alg"`
	KeyID        string `json:"key_id"`
	Sig          string `json:"sig"`
	SignedDigest string `json:"signed_digest,omitempty"`
}

func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Public: pub, Private: priv}, nil
}

func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func SignBytes(priv ed25519.PrivateKey, data []byte) Signature {
	sig := ed25519.Sign(priv, data)
	return Signature{
		Alg:   AlgEd25519,
		KeyID: KeyID(priv.Public().(ed25519.PublicKey)),
		Sig:   base64.StdEncoding.EncodeToString(sig),
	}
}

func VerifyBytes(pub ed25519.PublicKey, sig Signature, data []byte) (bool, error) {
	if sig.Alg != AlgEd25519 {
		return false, fmt.Errorf("unsupported alg: %s", sig.Alg)
	}
	if sig.KeyID != "" && sig.KeyID != KeyID(pub) {
		return false, fmt.Errorf("key id mismatch")
	}
	rawSig, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil {
		return false, fmt.Errorf("decode sig: %w", err)
	}
	if len(rawSig) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature length: %d", len(rawSig))
	}
	return ed25519.Verify(pub, data, rawSig), nil
}

func SignDigestHex(priv ed25519.PrivateKey, digestHex string) (Signature, error) {
	digest, err := hex.DecodeString(digestHex)
	if err != nil {
		return Signature{}, fmt.Errorf("decode digest: %w", err)
	}
	if len(digest) != sha256.Size {
		return Signature{}, fmt.Errorf("invalid digest length: %d", len(digest))
	}
	sig := SignBytes(priv, digest)
	sig.SignedDigest = digestHex
	return sig, nil
}

func VerifyDigestHex(pub ed25519.PublicKey, sig Signature) (bool, error) {
	if sig.SignedDigest == "" {
		return false, fmt.Errorf("missing signed_digest")
	}
	digest, err := hex.DecodeString(sig.SignedDigest)
	if err != nil {
		return false, fmt.Errorf("decode digest: %w", err)
	}
	if len(digest) != sha256.Size {
		return false, fmt.Errorf("invalid digest length: %d", len(digest))
	}
	return VerifyBytes(pub, sig, digest)
}
