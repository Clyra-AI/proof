package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Clyra-AI/proof/core/record"
)

type SigningKey struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	KeyID   string
}

type PublicKey struct {
	Public ed25519.PublicKey
	KeyID  string
}

var digestKeyIDRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

func GenerateKey() (SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SigningKey{}, err
	}
	kid := KeyID(pub)
	return SigningKey{Private: priv, Public: pub, KeyID: kid}, nil
}

func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func NormalizeKeyID(id string, pub ed25519.PublicKey) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return KeyID(pub)
	}
	if digestKeyIDRE.MatchString(id) {
		return id
	}
	parts := strings.Split(id, ":")
	if len(parts) >= 3 {
		return id
	}
	return KeyID(pub)
}

func Sign(r *record.Record, key SigningKey) (*record.Record, error) {
	if r == nil {
		return nil, errors.New("record is nil")
	}
	if len(key.Private) == 0 {
		return nil, errors.New("private key is required")
	}
	if r.Integrity.RecordHash == "" {
		h, err := record.ComputeHash(r)
		if err != nil {
			return nil, err
		}
		r.Integrity.RecordHash = h
	}
	sig := ed25519.Sign(key.Private, []byte(r.Integrity.RecordHash))
	r.Integrity.Signature = "base64:" + base64.StdEncoding.EncodeToString(sig)
	if len(key.Public) == 0 {
		key.Public = key.Private.Public().(ed25519.PublicKey)
	}
	r.Integrity.SigningKeyID = NormalizeKeyID(key.KeyID, key.Public)
	return r, nil
}

func Verify(r *record.Record, pub PublicKey) error {
	if r == nil {
		return errors.New("record is nil")
	}
	if r.Integrity.RecordHash == "" || r.Integrity.Signature == "" || r.Integrity.SigningKeyID == "" {
		return errors.New("record integrity signature block is incomplete")
	}
	expectedHash, err := record.ComputeHash(r)
	if err != nil {
		return err
	}
	if expectedHash != r.Integrity.RecordHash {
		return fmt.Errorf("record hash mismatch: expected %s got %s", expectedHash, r.Integrity.RecordHash)
	}
	kid := NormalizeKeyID(pub.KeyID, pub.Public)
	if kid != r.Integrity.SigningKeyID {
		return fmt.Errorf("signing key mismatch: expected %s got %s", kid, r.Integrity.SigningKeyID)
	}
	enc := strings.TrimPrefix(r.Integrity.Signature, "base64:")
	sig, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub.Public, []byte(r.Integrity.RecordHash), sig) {
		return errors.New("signature verification failed")
	}
	return nil
}
