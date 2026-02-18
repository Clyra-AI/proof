package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Clyra-AI/proof/core/canon"
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

type Signature struct {
	Alg          string `json:"alg"`
	KeyID        string `json:"key_id"`
	Sig          string `json:"sig"`
	SignedDigest string `json:"signed_digest"`
}

type RevocationEntry struct {
	KeyID     string `json:"key_id"`
	RevokedAt string `json:"revoked_at"`
	Reason    string `json:"reason,omitempty"`
}

type RevocationList struct {
	Version   string            `json:"version"`
	CreatedAt string            `json:"created_at"`
	Revoked   []RevocationEntry `json:"revoked"`
	Signature Signature         `json:"signature"`
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

func SignDigest(digest string, key SigningKey) (Signature, error) {
	digest = strings.TrimSpace(digest)
	if digest == "" {
		return Signature{}, errors.New("digest is required")
	}
	if len(key.Private) == 0 {
		return Signature{}, errors.New("private key is required")
	}
	if len(key.Public) == 0 {
		key.Public = key.Private.Public().(ed25519.PublicKey)
	}
	sig := ed25519.Sign(key.Private, []byte(digest))
	return Signature{
		Alg:          "ed25519",
		KeyID:        NormalizeKeyID(key.KeyID, key.Public),
		Sig:          base64.StdEncoding.EncodeToString(sig),
		SignedDigest: digest,
	}, nil
}

func VerifyDigest(sig Signature, digest string, pub PublicKey) error {
	if sig.Alg != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm: %s", sig.Alg)
	}
	digest = strings.TrimSpace(digest)
	if sig.SignedDigest != digest {
		return fmt.Errorf("signed digest mismatch: expected %s got %s", digest, sig.SignedDigest)
	}
	kid := NormalizeKeyID(pub.KeyID, pub.Public)
	if sig.KeyID != kid {
		return fmt.Errorf("signing key mismatch: expected %s got %s", kid, sig.KeyID)
	}
	decoded, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub.Public, []byte(digest), decoded) {
		return errors.New("signature verification failed")
	}
	return nil
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

func SignRevocationList(in RevocationList, key SigningKey) (RevocationList, error) {
	if in.Version == "" {
		in.Version = "1.0"
	}
	if in.CreatedAt == "" {
		in.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	digest, err := revocationDigest(in)
	if err != nil {
		return RevocationList{}, err
	}
	sig, err := SignDigest(digest, key)
	if err != nil {
		return RevocationList{}, err
	}
	in.Signature = sig
	return in, nil
}

func VerifyRevocationList(in RevocationList, pub PublicKey) error {
	digest, err := revocationDigest(in)
	if err != nil {
		return err
	}
	return VerifyDigest(in.Signature, digest, pub)
}

func IsRevoked(in RevocationList, keyID string, at time.Time) bool {
	for _, revoked := range in.Revoked {
		if strings.TrimSpace(revoked.KeyID) != strings.TrimSpace(keyID) {
			continue
		}
		ts, err := time.Parse(time.RFC3339, revoked.RevokedAt)
		if err != nil {
			return true
		}
		if at.IsZero() || !at.Before(ts) {
			return true
		}
	}
	return false
}

func revocationDigest(in RevocationList) (string, error) {
	payload := map[string]any{
		"version":    in.Version,
		"created_at": in.CreatedAt,
		"revoked":    in.Revoked,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	canonical, err := canon.Canonicalize(raw, canon.DomainJSON)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
