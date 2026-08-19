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
	"github.com/Clyra-AI/proof/core/chain"
	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/Clyra-AI/proof/core/schema"
	"github.com/Clyra-AI/proof/core/signing"
	"github.com/Clyra-AI/proof/core/structure"
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
	Strict           bool
}

const manifestFilename = "manifest.json"
const manifestRecordTypesPath = "record-types.json"

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
	if opts.Strict {
		if err := validateStrictStructure(path, manifest); err != nil {
			return nil, err
		}
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
	if opts.Strict {
		// Strict verification loads custom schemas into a registry owned by this
		// call. It is intentionally not installed in schema's legacy global
		// registry, so concurrent bundle verifications cannot influence one
		// another.
		registry, err := loadStrictRecordTypeRegistry(path, manifest)
		if err != nil {
			return nil, err
		}
		if registry != nil {
			if err := validateStrictRecordFiles(path, manifest, registry); err != nil {
				return nil, err
			}
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

func validateStrictRecordFiles(root string, manifest Manifest, registry *schema.Registry) error {
	for _, file := range manifest.Files {
		base := strings.ToLower(filepath.Base(file.Path))
		switch {
		case base == "chain.json":
			// #nosec G304 -- path has passed strict bundle membership and path checks.
			raw, err := os.ReadFile(filepath.Join(root, file.Path))
			if err != nil {
				return err
			}
			var c chain.Chain
			if err := json.Unmarshal(raw, &c); err != nil {
				return coreerr.Wrap(coreerr.KindValidation, "schema.record.chain_invalid", "parse strict bundle chain", err, coreerr.WithPath(file.Path))
			}
			for i := range c.Records {
				recordRaw, err := json.Marshal(c.Records[i])
				if err != nil {
					return err
				}
				if err := registry.ValidateRecord(recordRaw, c.Records[i].RecordType); err != nil {
					return coreerr.Wrap(coreerr.KindValidation, "schema.record.bundle_validation_failed", "strict bundle record validation failed", err, coreerr.WithPath(fmt.Sprintf("%s.records[%d]", file.Path, i)))
				}
			}
		case strings.HasSuffix(base, ".jsonl"):
			// JSONL files may be non-Proof data. Validate only lines that clearly
			// identify themselves as records, preserving existing bundle use cases.
			// #nosec G304 -- path has passed strict bundle membership and path checks.
			raw, err := os.ReadFile(filepath.Join(root, file.Path))
			if err != nil {
				return err
			}
			for lineNo, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var header struct {
					RecordType string `json:"record_type"`
				}
				if err := json.Unmarshal([]byte(line), &header); err != nil || header.RecordType == "" {
					continue
				}
				if err := registry.ValidateRecord([]byte(line), header.RecordType); err != nil {
					return coreerr.Wrap(coreerr.KindValidation, "schema.record.bundle_validation_failed", "strict bundle record validation failed", err, coreerr.WithPath(fmt.Sprintf("%s[%d]", file.Path, lineNo+1)))
				}
			}
		}
	}
	return nil
}

func loadStrictRecordTypeRegistry(root string, manifest Manifest) (*schema.Registry, error) {
	entries := make(map[string]ManifestEntry, len(manifest.Files))
	for _, file := range manifest.Files {
		key, err := structure.ValidatePath(file.Path)
		if err != nil {
			return nil, err
		}
		entries[key] = file
	}
	manifestEntry, ok := entries[manifestRecordTypesPath]
	if !ok {
		return nil, nil
	}
	// #nosec G304 -- path has passed strict bundle membership and path checks.
	raw, err := os.ReadFile(filepath.Join(root, manifestEntry.Path))
	if err != nil {
		return nil, coreerr.Wrap(coreerr.KindVerification, "schema.custom.manifest_missing", "read record type manifest", err, coreerr.WithPath(manifestRecordTypesPath))
	}
	typesManifest, err := schema.ParseRecordTypeManifest(raw)
	if err != nil {
		return nil, err
	}
	schemaFiles := make(map[string][]byte, len(typesManifest.RecordTypes))
	for _, def := range typesManifest.RecordTypes {
		key, err := structure.ValidatePath(def.SchemaPath)
		if err != nil {
			return nil, err
		}
		entry, listed := entries[key]
		if !listed {
			return nil, coreerr.New(coreerr.KindVerification, "schema.custom.schema_unlisted", fmt.Sprintf("custom schema is not covered by bundle manifest: %s", def.SchemaPath), coreerr.WithPath(def.SchemaPath))
		}
		// #nosec G304 -- path has passed strict bundle membership and path checks.
		data, err := os.ReadFile(filepath.Join(root, entry.Path))
		if err != nil {
			return nil, coreerr.Wrap(coreerr.KindVerification, "schema.custom.schema_missing", "read custom schema", err, coreerr.WithPath(def.SchemaPath))
		}
		schemaFiles[key] = data
		got := sha256.Sum256(data)
		want := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(def.SHA256)), "sha256:")
		if hex.EncodeToString(got[:]) != want {
			return nil, coreerr.New(coreerr.KindVerification, "schema.custom.digest_mismatch", fmt.Sprintf("schema digest mismatch for %s", def.SchemaPath), coreerr.WithPath(def.SchemaPath))
		}
	}
	return schema.LoadRecordTypeManifest(raw, schemaFiles)
}

func validateStrictStructure(root string, manifest Manifest) error {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return structure.SymlinkAmbiguityError(root)
	}

	paths := make([]string, 0, len(manifest.Files))
	for i := range manifest.Files {
		paths = append(paths, manifest.Files[i].Path)
	}
	listed, err := structure.ValidateListedPaths(paths)
	if err != nil {
		return err
	}

	return filepath.WalkDir(root, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return structure.SymlinkAmbiguityError(rel)
		}
		if entry.IsDir() {
			return nil
		}
		if rel == manifestFilename {
			return nil
		}
		key, err := structure.ValidatePath(rel)
		if err != nil {
			return err
		}
		if _, ok := listed[key]; !ok {
			return structure.UnlistedFileError(rel)
		}
		return nil
	})
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
