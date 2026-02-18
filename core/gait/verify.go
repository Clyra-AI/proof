package gait

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/proof/core/canon"
	"github.com/Clyra-AI/proof/core/signing"
)

type Signature struct {
	Alg          string `json:"alg"`
	KeyID        string `json:"key_id"`
	Sig          string `json:"sig"`
	SignedDigest string `json:"signed_digest"`
}

type PackManifest struct {
	SchemaID      string      `json:"schema_id"`
	SchemaVersion string      `json:"schema_version"`
	CreatedAt     string      `json:"created_at"`
	PackID        string      `json:"pack_id"`
	PackType      string      `json:"pack_type"`
	Contents      []PackEntry `json:"contents"`
	Signatures    []Signature `json:"signatures,omitempty"`
}

type PackEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Type   string `json:"type"`
}

type Result struct {
	PackID             string `json:"pack_id"`
	PackType           string `json:"pack_type"`
	FilesVerified      int    `json:"files_verified"`
	SignaturesVerified int    `json:"signatures_verified"`
}

func VerifyPack(path string, verifySignatures bool, pub ed25519.PublicKey) (*Result, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()

	manifestRaw, err := readZipFile(zr.File, "pack_manifest.json")
	if err != nil {
		return nil, err
	}
	var manifest PackManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("unmarshal pack_manifest.json: %w", err)
	}

	for _, entry := range manifest.Contents {
		content, err := readZipFile(zr.File, entry.Path)
		if err != nil {
			return nil, fmt.Errorf("missing content %s: %w", entry.Path, err)
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != strings.ToLower(strings.TrimSpace(entry.SHA256)) {
			return nil, fmt.Errorf("content hash mismatch for %s", entry.Path)
		}

		if !verifySignatures {
			continue
		}
		if isLikelySignedJSON(entry.Type, entry.Path) {
			if err := VerifyEmbeddedSignedJSON(content, pub); err != nil {
				return nil, fmt.Errorf("verify embedded signature for %s: %w", entry.Path, err)
			}
		}
	}

	result := &Result{PackID: manifest.PackID, PackType: manifest.PackType, FilesVerified: len(manifest.Contents)}
	if verifySignatures {
		if len(pub) == 0 {
			return nil, fmt.Errorf("public key is required for signature verification")
		}
		if len(manifest.Signatures) == 0 {
			return nil, fmt.Errorf("manifest has no signatures")
		}
		for _, sig := range manifest.Signatures {
			if err := verifyManifestSignature(manifest, sig, pub); err != nil {
				return nil, err
			}
			result.SignaturesVerified++
		}
	}
	return result, nil
}

func VerifyEmbeddedSignedJSON(raw []byte, pub ed25519.PublicKey) error {
	if len(pub) == 0 {
		return fmt.Errorf("public key is required")
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}
	sigRaw, ok := obj["signature"]
	if !ok {
		return nil
	}
	sigMap, ok := sigRaw.(map[string]any)
	if !ok {
		return fmt.Errorf("signature field is malformed")
	}
	sig, err := signatureFromMap(sigMap)
	if err != nil {
		return err
	}
	delete(obj, "signature")
	canonical, err := canonicalDigestHex(obj)
	if err != nil {
		return err
	}
	if canonical != sig.SignedDigest {
		return fmt.Errorf("signed digest mismatch: expected %s got %s", canonical, sig.SignedDigest)
	}
	if err := verifySignature(sig, pub); err != nil {
		return err
	}
	return nil
}

func verifyManifestSignature(manifest PackManifest, sig Signature, pub ed25519.PublicKey) error {
	m := manifest
	m.Signatures = nil
	digest, err := canonicalDigestHex(m)
	if err != nil {
		return err
	}
	if sig.SignedDigest != digest {
		return fmt.Errorf("manifest signed_digest mismatch")
	}
	return verifySignature(sig, pub)
}

func verifySignature(sig Signature, pub ed25519.PublicKey) error {
	if strings.ToLower(sig.Alg) != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm: %s", sig.Alg)
	}
	if strings.TrimSpace(sig.KeyID) != signing.KeyID(pub) {
		return fmt.Errorf("signature key_id mismatch")
	}
	decoded, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(sig.SignedDigest), decoded) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func signatureFromMap(m map[string]any) (Signature, error) {
	marshal, err := json.Marshal(m)
	if err != nil {
		return Signature{}, err
	}
	var sig Signature
	if err := json.Unmarshal(marshal, &sig); err != nil {
		return Signature{}, err
	}
	if sig.Alg == "" || sig.KeyID == "" || sig.Sig == "" || sig.SignedDigest == "" {
		return Signature{}, fmt.Errorf("signature field is incomplete")
	}
	return sig, nil
}

func canonicalDigestHex(v any) (string, error) {
	raw, err := json.Marshal(v)
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

func readZipFile(files []*zip.File, path string) ([]byte, error) {
	clean := filepath.Clean(path)
	for _, f := range files {
		if filepath.Clean(f.Name) != clean {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("%s not found", path)
}

func isLikelySignedJSON(t, p string) bool {
	t = strings.ToLower(t)
	if strings.HasPrefix(t, "gait.gate.") || strings.HasPrefix(t, "gait.runpack.") {
		return true
	}
	return strings.HasSuffix(strings.ToLower(p), ".json")
}
