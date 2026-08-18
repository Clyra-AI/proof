package gait

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/proof/core/canon"
	"github.com/Clyra-AI/proof/core/record"
	"github.com/Clyra-AI/proof/core/schema"
	"github.com/Clyra-AI/proof/core/signing"
	"github.com/Clyra-AI/proof/core/structure"
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
	PackID               string `json:"pack_id"`
	PackType             string `json:"pack_type"`
	FilesVerified        int    `json:"files_verified"`
	SignaturesVerified   int    `json:"signatures_verified"`
	ProofRecordsVerified int    `json:"proof_records_verified,omitempty"`
}

type RunpackManifest struct {
	SchemaID       string        `json:"schema_id"`
	SchemaVersion  string        `json:"schema_version"`
	RunID          string        `json:"run_id"`
	Files          []RunpackFile `json:"files"`
	ManifestDigest string        `json:"manifest_digest"`
	Signatures     []Signature   `json:"signatures,omitempty"`
}

type RunpackFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type RunpackResult struct {
	RunID              string `json:"run_id"`
	ManifestDigest     string `json:"manifest_digest"`
	FilesVerified      int    `json:"files_verified"`
	SignaturesVerified int    `json:"signatures_verified"`
}

type VerifyOpts struct {
	VerifySignatures bool
	PublicKey        ed25519.PublicKey
	Cosign           signing.CosignVerifyOpts
	Strict           bool
}

func VerifyPack(path string, verifySignatures bool, pub ed25519.PublicKey) (*Result, error) {
	return VerifyPackWithOptions(path, VerifyOpts{
		VerifySignatures: verifySignatures,
		PublicKey:        pub,
	})
}

func VerifyPackWithOptions(path string, opts VerifyOpts) (*Result, error) {
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
	if opts.Strict {
		paths := make([]string, 0, len(manifest.Contents))
		for i := range manifest.Contents {
			paths = append(paths, manifest.Contents[i].Path)
		}
		if err := validateStrictZipStructure(zr.File, "pack_manifest.json", paths); err != nil {
			return nil, err
		}
	}

	var proofRecordsVerified int
	for _, entry := range manifest.Contents {
		content, err := readZipFile(zr.File, entry.Path)
		if err != nil {
			return nil, fmt.Errorf("missing content %s: %w", entry.Path, err)
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != strings.ToLower(strings.TrimSpace(entry.SHA256)) {
			return nil, fmt.Errorf("content hash mismatch for %s", entry.Path)
		}

		if !opts.VerifySignatures {
			if filepath.Clean(entry.Path) == filepath.Clean("proof_records.jsonl") {
				verified, err := verifyProofRecordsJSONL(content, false, nil, signing.CosignVerifyOpts{})
				if err != nil {
					return nil, fmt.Errorf("verify proof records for %s: %w", entry.Path, err)
				}
				proofRecordsVerified = verified
			}
			continue
		}
		if isLikelySignedJSON(entry.Type, entry.Path) {
			if err := VerifyEmbeddedSignedJSON(content, opts.PublicKey); err != nil {
				return nil, fmt.Errorf("verify embedded signature for %s: %w", entry.Path, err)
			}
		}
		if filepath.Clean(entry.Path) == filepath.Clean("proof_records.jsonl") {
			verified, err := verifyProofRecordsJSONL(content, true, opts.PublicKey, opts.Cosign)
			if err != nil {
				return nil, fmt.Errorf("verify proof records for %s: %w", entry.Path, err)
			}
			proofRecordsVerified = verified
		}
	}

	result := &Result{
		PackID:               manifest.PackID,
		PackType:             manifest.PackType,
		FilesVerified:        len(manifest.Contents),
		ProofRecordsVerified: proofRecordsVerified,
	}
	if opts.VerifySignatures {
		if len(opts.PublicKey) == 0 {
			return nil, fmt.Errorf("public key is required for signature verification")
		}
		if len(manifest.Signatures) == 0 {
			return nil, fmt.Errorf("manifest has no signatures")
		}
		for _, sig := range manifest.Signatures {
			if err := verifyManifestSignature(manifest, sig, opts.PublicKey); err != nil {
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

func VerifyRunpack(path string, verifySignatures bool, pub ed25519.PublicKey) (*RunpackResult, error) {
	return VerifyRunpackWithOptions(path, VerifyOpts{
		VerifySignatures: verifySignatures,
		PublicKey:        pub,
	})
}

func VerifyRunpackWithOptions(path string, opts VerifyOpts) (*RunpackResult, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()

	manifestRaw, err := readZipFile(zr.File, "manifest.json")
	if err != nil {
		return nil, err
	}
	var manifest RunpackManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("unmarshal manifest.json: %w", err)
	}
	if manifest.SchemaID != "gait.runpack.manifest" {
		return nil, fmt.Errorf("manifest schema_id must be gait.runpack.manifest")
	}
	if manifest.SchemaVersion != "1.0.0" {
		return nil, fmt.Errorf("manifest schema_version must be 1.0.0")
	}
	if opts.Strict {
		paths := make([]string, 0, len(manifest.Files))
		for i := range manifest.Files {
			paths = append(paths, manifest.Files[i].Path)
		}
		if err := validateStrictZipStructure(zr.File, "manifest.json", paths); err != nil {
			return nil, err
		}
	}

	for _, entry := range manifest.Files {
		content, err := readZipFile(zr.File, entry.Path)
		if err != nil {
			return nil, fmt.Errorf("missing content %s: %w", entry.Path, err)
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != strings.ToLower(strings.TrimSpace(entry.SHA256)) {
			return nil, fmt.Errorf("content hash mismatch for %s", entry.Path)
		}
	}
	manifestDigest, err := runpackManifestDigest(manifest)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(manifest.ManifestDigest), manifestDigest) {
		return nil, fmt.Errorf("manifest digest mismatch: expected %s got %s", manifest.ManifestDigest, manifestDigest)
	}

	result := &RunpackResult{
		RunID:          manifest.RunID,
		ManifestDigest: manifest.ManifestDigest,
		FilesVerified:  len(manifest.Files),
	}
	if opts.VerifySignatures {
		if len(opts.PublicKey) == 0 {
			return nil, fmt.Errorf("public key is required for signature verification")
		}
		if len(manifest.Signatures) == 0 {
			return nil, fmt.Errorf("manifest has no signatures")
		}
		for _, sig := range manifest.Signatures {
			if err := verifyRunpackSignature(manifestDigest, sig, opts.PublicKey); err != nil {
				return nil, err
			}
			result.SignaturesVerified++
		}
	}
	return result, nil
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
	digestBytes, err := hex.DecodeString(strings.TrimSpace(sig.SignedDigest))
	if err != nil {
		return fmt.Errorf("decode signed digest: %w", err)
	}
	if len(digestBytes) != sha256.Size {
		return fmt.Errorf("invalid signed digest length: %d", len(digestBytes))
	}
	if !ed25519.Verify(pub, digestBytes, decoded) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func verifyRunpackSignature(manifestDigest string, sig Signature, pub ed25519.PublicKey) error {
	if !strings.EqualFold(strings.TrimSpace(sig.SignedDigest), strings.TrimSpace(manifestDigest)) {
		return fmt.Errorf("manifest signed_digest mismatch")
	}
	return verifySignature(sig, pub)
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

func runpackManifestDigest(manifest RunpackManifest) (string, error) {
	m := manifest
	m.ManifestDigest = ""
	m.Signatures = nil
	sort.Slice(m.Files, func(i, j int) bool {
		return m.Files[i].Path < m.Files[j].Path
	})
	return canonicalDigestHex(m)
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

func validateStrictZipStructure(files []*zip.File, manifestPath string, listedPaths []string) error {
	listed, err := structure.ValidateListedPaths(listedPaths)
	if err != nil {
		return err
	}
	archivePaths := make([]string, 0, len(files))
	fileKeys := make([]struct {
		path string
		key  string
	}, 0, len(files))
	for _, file := range files {
		if file.Mode()&os.ModeSymlink != 0 {
			return structure.SymlinkAmbiguityError(file.Name)
		}
		archivePaths = append(archivePaths, file.Name)
		key, err := structure.ValidateArchivePath(file.Name, file.FileInfo().IsDir())
		if err != nil {
			return err
		}
		if file.FileInfo().IsDir() {
			continue
		}
		fileKeys = append(fileKeys, struct {
			path string
			key  string
		}{path: file.Name, key: key})
	}
	if _, err := structure.ValidateArchivePaths(archivePaths); err != nil {
		return err
	}
	sort.Slice(fileKeys, func(i, j int) bool {
		return fileKeys[i].path < fileKeys[j].path
	})
	for _, file := range fileKeys {
		if file.path == manifestPath {
			continue
		}
		if _, ok := listed[file.key]; !ok {
			return structure.UnlistedFileError(file.path)
		}
	}
	return nil
}

func isLikelySignedJSON(t, p string) bool {
	t = strings.ToLower(t)
	if strings.HasPrefix(t, "gait.gate.") || strings.HasPrefix(t, "gait.runpack.") {
		return true
	}
	return strings.HasSuffix(strings.ToLower(p), ".json")
}

func verifyProofRecordsJSONL(raw []byte, verifySignatures bool, pub ed25519.PublicKey, cosignOpts signing.CosignVerifyOpts) (int, error) {
	if verifySignatures && len(pub) == 0 {
		if strings.TrimSpace(cosignOpts.KeyPath) == "" && strings.TrimSpace(cosignOpts.CertificatePath) == "" {
			return 0, fmt.Errorf("public key is required for proof record signature verification")
		}
	}

	count := 0
	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec record.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return count, fmt.Errorf("line %d: parse record: %w", lineNo, err)
		}
		if err := record.Validate(&rec); err != nil {
			return count, fmt.Errorf("line %d: validate record: %w", lineNo, err)
		}
		if err := schema.ValidateRecord([]byte(line), rec.RecordType); err != nil {
			return count, fmt.Errorf("line %d: validate schema: %w", lineNo, err)
		}
		expectedHash, err := record.ComputeHash(&rec)
		if err != nil {
			return count, fmt.Errorf("line %d: compute record hash: %w", lineNo, err)
		}
		if expectedHash != rec.Integrity.RecordHash {
			return count, fmt.Errorf("line %d: record hash mismatch: expected %s got %s", lineNo, expectedHash, rec.Integrity.RecordHash)
		}
		if verifySignatures {
			if strings.TrimSpace(rec.Integrity.Signature) == "" {
				return count, fmt.Errorf("line %d: missing signature", lineNo)
			}
			if strings.HasPrefix(rec.Integrity.Signature, "cosign:") {
				if err := signing.VerifyRecordCosign(&rec, cosignOpts); err != nil {
					return count, fmt.Errorf("line %d: signature verification failed: %w", lineNo, err)
				}
				count++
				continue
			}
			if err := signing.Verify(&rec, signing.PublicKey{Public: pub}); err != nil {
				return count, fmt.Errorf("line %d: signature verification failed: %w", lineNo, err)
			}
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("read jsonl: %w", err)
	}
	return count, nil
}
