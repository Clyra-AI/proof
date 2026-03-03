package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/proof/core/canon"
	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/Clyra-AI/proof/core/schema"
	"github.com/Clyra-AI/proof/core/signing"
)

type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Files      []ManifestEntry     `json:"files"`
	AlgoID     string              `json:"algo_id,omitempty"`
	SaltID     string              `json:"salt_id,omitempty"`
	Signatures []signing.Signature `json:"signatures,omitempty"`
}

type VerifyOpts struct {
	VerifySignatures bool
	PublicKey        signing.PublicKey
	Cosign           signing.CosignVerifyOpts
}

const manifestFilename = "manifest.json"

func Verify(path string, opts VerifyOpts) (*Manifest, error) {
	manifest, err := ReadManifest(path)
	if err != nil {
		return nil, err
	}
	if err := normalizeAlgorithm(&manifest); err != nil {
		return nil, err
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return nil, coreerr.Wrap(coreerr.KindInternal, "bundle.marshal_manifest_failed", "marshal bundle manifest", err)
	}
	if err := schema.ValidateAgainstSchema(manifestRaw, "v1/bundle-manifest-v1.schema.json"); err != nil {
		return nil, coreerr.Wrap(coreerr.KindValidation, "bundle.schema_validation_failed", "bundle manifest schema validation failed", err, coreerr.WithPath("v1/bundle-manifest-v1.schema.json"))
	}
	for _, file := range manifest.Files {
		// #nosec G304 -- manifest drives local bundle verification.
		data, err := os.ReadFile(filepath.Join(path, file.Path))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		want := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(file.SHA256)), "sha256:")
		if got != want {
			return nil, coreerr.New(coreerr.KindVerification, "bundle.hash_mismatch", fmt.Sprintf("bundle hash mismatch for %s", file.Path), coreerr.WithPath(file.Path))
		}
	}
	if opts.VerifySignatures {
		if len(manifest.Signatures) == 0 {
			return nil, coreerr.New(coreerr.KindVerification, "bundle.signature_missing", "bundle manifest has no signatures")
		}
		digest, err := ManifestDigest(manifest)
		if err != nil {
			return nil, err
		}
		for _, sig := range manifest.Signatures {
			switch strings.ToLower(strings.TrimSpace(sig.Alg)) {
			case "ed25519":
				if len(opts.PublicKey.Public) == 0 {
					return nil, coreerr.New(coreerr.KindInvalidInput, "bundle.public_key_required", "public key is required for bundle signature verification", coreerr.WithField("public_key"))
				}
				if err := signing.VerifyDigest(sig, digest, opts.PublicKey); err != nil {
					return nil, err
				}
			case "cosign":
				if err := signing.VerifyDigestCosign(sig, digest, opts.Cosign); err != nil {
					return nil, err
				}
			default:
				return nil, coreerr.New(coreerr.KindVerification, "bundle.unsupported_signature_algorithm", fmt.Sprintf("unsupported bundle signature algorithm: %s", sig.Alg), coreerr.WithField("alg"))
			}
		}
	}
	return &manifest, nil
}

func ReadManifest(path string) (Manifest, error) {
	manifestPath := filepath.Join(path, manifestFilename)
	// #nosec G304 -- caller provides explicit local artifact path.
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func WriteManifest(path string, manifest Manifest) error {
	manifestPath := filepath.Join(path, manifestFilename)
	out, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return coreerr.Wrap(coreerr.KindInternal, "bundle.marshal_manifest_failed", "marshal bundle manifest", err)
	}
	// #nosec G306 -- bundle manifests are workspace artifacts.
	if err := os.WriteFile(manifestPath, out, 0o644); err != nil {
		return err
	}
	return nil
}

func SignManifest(manifest Manifest, key signing.SigningKey) (Manifest, error) {
	if err := normalizeAlgorithm(&manifest); err != nil {
		return Manifest{}, err
	}
	digest, err := ManifestDigest(manifest)
	if err != nil {
		return Manifest{}, err
	}
	sig, err := signing.SignDigest(digest, key)
	if err != nil {
		return Manifest{}, err
	}
	manifest.Signatures = append(manifest.Signatures, sig)
	return manifest, nil
}

func SignManifestCosign(manifest Manifest, keyPath string) (Manifest, error) {
	if err := normalizeAlgorithm(&manifest); err != nil {
		return Manifest{}, err
	}
	digest, err := ManifestDigest(manifest)
	if err != nil {
		return Manifest{}, err
	}
	sig, err := signing.SignDigestCosign(digest, keyPath)
	if err != nil {
		return Manifest{}, err
	}
	manifest.Signatures = append(manifest.Signatures, sig)
	return manifest, nil
}

func SignFile(path string, key signing.SigningKey) (*Manifest, error) {
	manifest, err := ReadManifest(path)
	if err != nil {
		return nil, err
	}
	signed, err := SignManifest(manifest, key)
	if err != nil {
		return nil, err
	}
	if err := WriteManifest(path, signed); err != nil {
		return nil, err
	}
	return &signed, nil
}

func SignFileCosign(path string, keyPath string) (*Manifest, error) {
	manifest, err := ReadManifest(path)
	if err != nil {
		return nil, err
	}
	signed, err := SignManifestCosign(manifest, keyPath)
	if err != nil {
		return nil, err
	}
	if err := WriteManifest(path, signed); err != nil {
		return nil, err
	}
	return &signed, nil
}

func ManifestDigest(manifest Manifest) (string, error) {
	m := manifest
	m.Signatures = nil
	raw, err := json.Marshal(m)
	if err != nil {
		return "", coreerr.Wrap(coreerr.KindInternal, "bundle.marshal_manifest_failed", "marshal bundle manifest", err)
	}
	canonical, err := canon.Canonicalize(raw, canon.DomainJSON)
	if err != nil {
		return "", coreerr.Wrap(coreerr.KindInternal, "bundle.canonicalize_manifest_failed", "canonicalize bundle manifest", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeAlgorithm(manifest *Manifest) error {
	algoID := strings.ToLower(strings.TrimSpace(manifest.AlgoID))
	if algoID == "" {
		algoID = "sha256"
		manifest.AlgoID = algoID
	}
	if algoID != "sha256" {
		return coreerr.New(coreerr.KindValidation, "bundle.unsupported_digest_algorithm", fmt.Sprintf("unsupported bundle digest algorithm: %s", manifest.AlgoID), coreerr.WithField("algo_id"))
	}
	return nil
}
