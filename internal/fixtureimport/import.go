// Package fixtureimport owns the staging contract for final cross-product
// conformance fixtures. It deliberately does not create producer artifacts or
// Proof assessments: every staged byte must be supplied by a released source.
package fixtureimport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	prooffcanon "github.com/Clyra-AI/proof/core/canon"
	prooffsign "github.com/Clyra-AI/proof/signing"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	ContractFormat       = "proof.cross_product_fixture_import/v1"
	ManifestPath         = "provenance/import-manifest.json"
	ContractPath         = "provenance/import-contract.json"
	ManagedMarker        = ".proof-fixture-managed"
	ManagedContent       = "proof-cross-product-fixture/v1\n"
	AxymRegisterSchemaID = "https://axym.dev/schemas/v1/governance/action-contract-register.schema.json"
	AxymPacketSchemaID   = "https://axym.dev/schemas/v1/governance/action-contract-evidence-packet.schema.json"
	AxymSchemaVersion    = "v1"
)

// RuntimeError marks an internal destination/I/O failure. Validation and
// verification failures intentionally remain ordinary errors so the CLI can
// preserve the stable exit-code distinction.
type RuntimeError struct{ Err error }

func (e *RuntimeError) Error() string {
	if e == nil || e.Err == nil {
		return "fixture import runtime failure"
	}
	return e.Err.Error()
}

func (e *RuntimeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func runtimeError(err error) error {
	if err == nil {
		return nil
	}
	return &RuntimeError{Err: err}
}

func classifyReadFailure(label string, err error) error {
	if err == nil {
		return nil
	}
	wrapped := fmt.Errorf("%s: %w", label, err)
	if isUnsafePathError(err) {
		return unsafeError(wrapped)
	}
	return runtimeError(wrapped)
}

// ReadContractFile reads the operator-supplied import contract without
// following symlinks or opening non-regular files. Contract paths are input
// boundaries, so an unsafe file type is distinct from an ordinary I/O error;
// in particular, this prevents a FIFO/device from blocking os.ReadFile.
func ReadContractFile(path string) ([]byte, error) {
	raw, err := readNoSymlink(path)
	if err == nil {
		return raw, nil
	}
	if isUnsafePathError(err) {
		return nil, unsafeError(fmt.Errorf("contract path: %w", err))
	}
	return nil, runtimeError(fmt.Errorf("read import contract: %w", err))
}

func isUnsafePathError(err error) bool {
	message := err.Error()
	return strings.Contains(message, "symlink path is not allowed") || strings.Contains(message, "path is not a regular file") || strings.Contains(message, "path escapes source root")
}

// UnsafeError marks an existing destination that is not a previously staged
// fixture. Update refuses to replace such paths.
type UnsafeError struct{ Err error }

func (e *UnsafeError) Error() string {
	if e == nil || e.Err == nil {
		return "unsafe fixture destination"
	}
	return e.Err.Error()
}

func (e *UnsafeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func unsafeError(err error) error {
	if err == nil {
		return nil
	}
	return &UnsafeError{Err: err}
}

// SchemaError marks a pinned-schema or artifact-schema contract violation.
type SchemaError struct{ Err error }

func (e *SchemaError) Error() string {
	if e == nil || e.Err == nil {
		return "fixture schema validation failed"
	}
	return e.Err.Error()
}

func (e *SchemaError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func schemaError(err error) error {
	if err == nil {
		return nil
	}
	return &SchemaError{Err: err}
}

// DriftError marks a committed fixture that no longer matches its generated
// contract, manifest, or allowlisted file set.
type DriftError struct{ Err error }

func (e *DriftError) Error() string {
	if e == nil || e.Err == nil {
		return "fixture drift"
	}
	return e.Err.Error()
}

func (e *DriftError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func driftError(err error) error {
	if err == nil {
		return nil
	}
	return &DriftError{Err: err}
}

// Contract pins the exact producer identities and bytes accepted by the
// importer. Paths are relative to the source root and use slash separators.
// The contract is intentionally supplied by the release owner; no defaults
// contain a developer checkout or a guessed tag/commit.
type Contract struct {
	Format      string   `json:"format"`
	FixtureID   string   `json:"fixture_id"`
	ProofCommit string   `json:"proof_commit,omitempty"`
	Sources     []Source `json:"sources"`
}

type Source struct {
	Product         string         `json:"product"`
	Version         string         `json:"version"`
	Commit          string         `json:"commit"`
	Tag             string         `json:"tag"`
	TagObject       string         `json:"tag_object,omitempty"`
	PeeledCommit    string         `json:"peeled_commit,omitempty"`
	IntegrityMode   string         `json:"integrity_mode"`
	ManifestPath    string         `json:"manifest_path"`
	ManifestSHA256  string         `json:"manifest_sha256"`
	PublicKeyPath   string         `json:"public_key_path"`
	PublicKeySHA256 string         `json:"public_key_sha256"`
	ReleaseAssets   []ReleaseAsset `json:"release_assets,omitempty"`
	Schemas         []File         `json:"schemas"`
	Artifacts       []Artifact     `json:"artifacts"`
}

// ReleaseAsset pins the detached release material used to anchor an
// extracted authoritative bundle. The bytes are copied and digest-checked
// like every other source file; the role keeps checksum, signature,
// certificate, attestation, provenance, and bundle inputs distinguishable.
type ReleaseAsset struct {
	Role   string `json:"role"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type File struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	SchemaID      string `json:"schema_id,omitempty"`
	SchemaVersion string `json:"schema_version,omitempty"`
}

type Artifact struct {
	Path              string      `json:"path"`
	SHA256            string      `json:"sha256"`
	Kind              string      `json:"kind"`
	SchemaPath        string      `json:"schema_path"`
	SchemaSHA256      string      `json:"schema_sha256"`
	SchemaID          string      `json:"schema_id"`
	SchemaVersion     string      `json:"schema_version"`
	ProducerArtifact  bool        `json:"producer_artifact"`
	Synthetic         bool        `json:"synthetic"`
	SignaturePath     string      `json:"signature_path,omitempty"`
	SignatureSHA256   string      `json:"signature_sha256,omitempty"`
	SignatureRequired bool        `json:"signature_required,omitempty"`
	RelationshipRefs  []Reference `json:"relationship_refs,omitempty"`
}

type Reference struct {
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	Digest        string `json:"digest"`
	SchemaID      string `json:"schema_id"`
	SchemaVersion string `json:"schema_version"`
	SourceProduct string `json:"source_product"`
}

type importedManifest struct {
	Format      string           `json:"format"`
	FixtureID   string           `json:"fixture_id"`
	ContractSHA string           `json:"contract_sha256"`
	FixtureOnly bool             `json:"fixture_only"`
	Sources     []importedSource `json:"sources"`
}

type importedSource struct {
	Product         string         `json:"product"`
	Version         string         `json:"version"`
	Commit          string         `json:"commit"`
	Tag             string         `json:"tag"`
	TagObject       string         `json:"tag_object,omitempty"`
	PeeledCommit    string         `json:"peeled_commit,omitempty"`
	IntegrityMode   string         `json:"integrity_mode"`
	Manifest        string         `json:"manifest"`
	ManifestSHA256  string         `json:"manifest_sha256"`
	PublicKey       string         `json:"public_key"`
	PublicKeySHA256 string         `json:"public_key_sha256"`
	ReleaseAssets   []ReleaseAsset `json:"release_assets,omitempty"`
	Schemas         []string       `json:"schemas"`
	Artifacts       []string       `json:"artifacts"`
}

// LoadContract parses and validates the shape of a contract. Byte and
// producer validation happens in ValidateSource so callers can use this in a
// preflight without writing anything.
func LoadContract(raw []byte) (Contract, error) {
	if err := validateJSONBytes(raw, "import contract"); err != nil {
		return Contract{}, err
	}
	var c Contract
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return Contract{}, fmt.Errorf("decode import contract: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Contract{}, errors.New("decode import contract: trailing JSON")
		}
		return Contract{}, fmt.Errorf("decode import contract: trailing JSON: %w", err)
	}
	if c.Format != ContractFormat {
		return Contract{}, fmt.Errorf("unsupported import contract format %q", c.Format)
	}
	if strings.TrimSpace(c.FixtureID) == "" {
		return Contract{}, errors.New("import contract fixture_id is required")
	}
	if len(c.Sources) != 3 {
		return Contract{}, fmt.Errorf("import contract must contain exactly three sources")
	}
	seen := map[string]bool{}
	for i := range c.Sources {
		if err := validateSourceShape(&c.Sources[i]); err != nil {
			return Contract{}, fmt.Errorf("source[%d]: %w", i, err)
		}
		if seen[c.Sources[i].Product] {
			return Contract{}, fmt.Errorf("duplicate source product %q", c.Sources[i].Product)
		}
		seen[c.Sources[i].Product] = true
	}
	for _, product := range []string{"wrkr", "gait", "axym"} {
		if !seen[product] {
			return Contract{}, fmt.Errorf("required source product %q is missing", product)
		}
	}
	return c, nil
}

func validateSourceShape(s *Source) error {
	s.Product = strings.ToLower(strings.TrimSpace(s.Product))
	if s.Product != "wrkr" && s.Product != "gait" && s.Product != "axym" {
		return fmt.Errorf("unsupported product %q", s.Product)
	}
	required := []struct {
		name  string
		value string
	}{
		{"version", s.Version},
		{"commit", s.Commit},
		{"tag", s.Tag},
		{"integrity_mode", s.IntegrityMode},
		{"manifest_path", s.ManifestPath},
		{"manifest_sha256", s.ManifestSHA256},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tag_object", s.TagObject},
		{"peeled_commit", s.PeeledCommit},
	} {
		if field.value == "" {
			continue
		}
		if len(field.value) != 40 {
			return fmt.Errorf("%s must be a 40-character hexadecimal object ID", field.name)
		}
		if _, err := hex.DecodeString(field.value); err != nil {
			return fmt.Errorf("%s must be a 40-character hexadecimal object ID", field.name)
		}
	}
	if s.IntegrityMode != "manifest_digest" && s.IntegrityMode != "tagged_tree" && s.IntegrityMode != "inline_ed25519" {
		return fmt.Errorf("unsupported integrity_mode %q", s.IntegrityMode)
	}
	if (s.PublicKeyPath == "") != (s.PublicKeySHA256 == "") {
		return errors.New("public_key_path and public_key_sha256 must be supplied together")
	}
	if s.IntegrityMode == "inline_ed25519" && (s.PublicKeyPath == "" || s.PublicKeySHA256 == "") {
		return errors.New("inline_ed25519 requires a public key and digest")
	}
	if s.Product == "wrkr" && s.IntegrityMode == "inline_ed25519" {
		return errors.New("Wrkr source must use manifest_digest or tagged_tree")
	}
	if s.Product != "wrkr" && s.IntegrityMode != "inline_ed25519" {
		return fmt.Errorf("%s source must use inline_ed25519", s.Product)
	}
	seenReleaseRoles := map[string]bool{}
	seenReleasePaths := map[string]bool{}
	for i, asset := range s.ReleaseAssets {
		if strings.TrimSpace(asset.Role) == "" || strings.TrimSpace(asset.Path) == "" || strings.TrimSpace(asset.SHA256) == "" {
			return fmt.Errorf("release_assets[%d] requires role, path, and sha256", i)
		}
		if seenReleaseRoles[asset.Role] {
			return fmt.Errorf("release_assets contains duplicate role %q", asset.Role)
		}
		seenReleaseRoles[asset.Role] = true
		if seenReleasePaths[asset.Path] {
			return fmt.Errorf("release_assets contains duplicate path %q", asset.Path)
		}
		seenReleasePaths[asset.Path] = true
		if err := safePath(asset.Path); err != nil {
			return fmt.Errorf("release_assets[%d] path: %w", i, err)
		}
		if _, err := parseDigest(asset.SHA256); err != nil {
			return fmt.Errorf("release_assets[%d] sha256: %w", i, err)
		}
	}
	paths := []struct {
		name string
		path string
	}{
		{"manifest_path", s.ManifestPath},
		{"public_key_path", s.PublicKeyPath},
	}
	for _, field := range paths {
		if field.path == "" {
			continue
		}
		if err := safePath(field.path); err != nil {
			return fmt.Errorf("%s: %w", field.name, err)
		}
	}
	if _, err := parseDigest(s.ManifestSHA256); err != nil {
		return fmt.Errorf("manifest_sha256: %w", err)
	}
	if s.PublicKeySHA256 != "" {
		if _, err := parseDigest(s.PublicKeySHA256); err != nil {
			return fmt.Errorf("public_key_sha256: %w", err)
		}
	}
	if len(s.Schemas) == 0 {
		return errors.New("at least one portable schema is required")
	}
	for i := range s.Schemas {
		if err := validateFile(&s.Schemas[i], true); err != nil {
			return fmt.Errorf("schema[%d]: %w", i, err)
		}
	}
	if len(s.Artifacts) == 0 {
		return errors.New("at least one producer artifact is required")
	}
	for i := range s.Artifacts {
		if err := validateArtifact(&s.Artifacts[i], s.Product); err != nil {
			return fmt.Errorf("artifact[%d]: %w", i, err)
		}
	}
	seenPaths := []struct {
		path  string
		label string
	}{}
	addPath := func(label, path string) error {
		if path == "" {
			return nil
		}
		normalized := cases.Fold().String(norm.NFC.String(filepath.ToSlash(path)))
		for _, previous := range seenPaths {
			if normalized == previous.path || strings.HasPrefix(normalized, previous.path+"/") || strings.HasPrefix(previous.path, normalized+"/") {
				return fmt.Errorf("portable path collision between %s and %s", previous.label, label)
			}
		}
		seenPaths = append(seenPaths, struct {
			path  string
			label string
		}{path: normalized, label: label})
		return nil
	}
	if err := addPath("manifest_path", s.ManifestPath); err != nil {
		return err
	}
	if err := addPath("public_key_path", s.PublicKeyPath); err != nil {
		return err
	}
	for i, schema := range s.Schemas {
		if err := addPath(fmt.Sprintf("schema[%d]", i), schema.Path); err != nil {
			return err
		}
	}
	for i, artifact := range s.Artifacts {
		if err := addPath(fmt.Sprintf("artifact[%d]", i), artifact.Path); err != nil {
			return err
		}
		if err := addPath(fmt.Sprintf("artifact[%d].signature_path", i), artifact.SignaturePath); err != nil {
			return err
		}
	}
	if s.IntegrityMode == "inline_ed25519" {
		signed := false
		for _, artifact := range s.Artifacts {
			signed = signed || artifact.SignatureRequired
		}
		if !signed {
			return errors.New("inline_ed25519 source must require at least one signed artifact")
		}
	}
	if s.Product == "axym" {
		register, packet := false, false
		registerPath, packetPath := "", ""
		for _, a := range s.Artifacts {
			kind := strings.ToLower(a.Kind)
			if strings.Contains(kind, "register") {
				register = true
				registerPath = a.Path
			}
			if strings.Contains(kind, "packet") {
				packet = true
				packetPath = a.Path
			}
		}
		if !register || !packet {
			return errors.New("Axym source must provide exact register and evidence packet artifacts")
		}
		if registerPath == packetPath {
			return errors.New("Axym register and evidence packet must be distinct artifacts")
		}
	}
	return nil
}

func validateFile(f *File, schema bool) error {
	if err := safePath(f.Path); err != nil {
		return err
	}
	if _, err := parseDigest(f.SHA256); err != nil {
		return fmt.Errorf("sha256: %w", err)
	}
	if schema && (strings.TrimSpace(f.SchemaID) == "" || strings.TrimSpace(f.SchemaVersion) == "") {
		return errors.New("schema_id and schema_version are required")
	}
	return nil
}

func validateArtifact(a *Artifact, product string) error {
	if err := validateFile(&File{Path: a.Path, SHA256: a.SHA256}, false); err != nil {
		return err
	}
	if strings.TrimSpace(a.Kind) == "" || strings.TrimSpace(a.SchemaPath) == "" || strings.TrimSpace(a.SchemaID) == "" || strings.TrimSpace(a.SchemaVersion) == "" {
		return errors.New("kind, schema_path, schema_id, and schema_version are required")
	}
	if err := safePath(a.SchemaPath); err != nil {
		return fmt.Errorf("schema_path: %w", err)
	}
	if _, err := parseDigest(a.SchemaSHA256); err != nil {
		return fmt.Errorf("schema_sha256: %w", err)
	}
	if (a.SignaturePath == "") != (a.SignatureSHA256 == "") {
		return errors.New("signature_path and signature_sha256 must be supplied together")
	}
	if a.SignaturePath != "" {
		if err := safePath(a.SignaturePath); err != nil {
			return fmt.Errorf("signature_path: %w", err)
		}
		if _, err := parseDigest(a.SignatureSHA256); err != nil {
			return fmt.Errorf("signature_sha256: %w", err)
		}
	}
	if !a.ProducerArtifact {
		return errors.New("producer_artifact must be true")
	}
	if a.Synthetic {
		return errors.New("synthetic artifacts are not releasable producer artifacts")
	}
	for i := range a.RelationshipRefs {
		if err := validateReference(&a.RelationshipRefs[i], product); err != nil {
			return fmt.Errorf("relationship_ref[%d]: %w", i, err)
		}
	}
	return nil
}

func validateReference(r *Reference, product string) error {
	required := []struct {
		name  string
		value string
	}{
		{"kind", r.Kind},
		{"id", r.ID},
		{"digest", r.Digest},
		{"schema_id", r.SchemaID},
		{"schema_version", r.SchemaVersion},
		{"source_product", r.SourceProduct},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	if _, err := parseDigest(r.Digest); err != nil {
		return fmt.Errorf("digest: %w", err)
	}
	if r.SourceProduct != product && r.SourceProduct != "wrkr" && r.SourceProduct != "gait" && r.SourceProduct != "axym" {
		return fmt.Errorf("unsupported source_product %q", r.SourceProduct)
	}
	return nil
}

// Update validates all source bytes and then stages exact copies beneath dest.
// No normalization or assessment generation is performed. Existing output is
// left untouched if preflight fails.
func Update(sourceRoot, dest string, contract Contract, contractRaw []byte) error {
	if strings.TrimSpace(sourceRoot) == "" || strings.TrimSpace(dest) == "" {
		return errors.New("source root and destination are required")
	}
	loadedContract, err := LoadContract(contractRaw)
	if err != nil {
		return err
	}
	canonicalProvided, err := canonicalJSON(contract)
	if err != nil {
		return err
	}
	canonicalLoaded, err := canonicalJSON(loadedContract)
	if err != nil || !bytes.Equal(canonicalProvided, canonicalLoaded) {
		return errors.New("contract and contractRaw disagree")
	}
	contract = loadedContract
	if err := validateSources(sourceRoot, contract); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return runtimeError(err)
	}
	var expectedTarget *destinationIdentity
	if info, err := os.Lstat(dest); err == nil {
		if err := requireManagedDestination(dest, info); err != nil {
			return err
		}
		expectedTarget, err = destinationIdentityFor(dest, info)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return runtimeError(err)
	}
	target := dest
	staging, err := os.MkdirTemp(filepath.Dir(target), ".proof-fixture-staging-")
	if err != nil {
		return runtimeError(err)
	}
	defer os.RemoveAll(staging)
	dest = staging
	if err := os.MkdirAll(filepath.Join(dest, "provenance"), 0o750); err != nil {
		return runtimeError(err)
	}
	if err := os.WriteFile(filepath.Join(dest, ManagedMarker), []byte(ManagedContent), 0o600); err != nil {
		return runtimeError(err)
	}
	canonicalContract, err := canonicalJSON(contract)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dest, ContractPath), canonicalContract, 0o600); err != nil {
		return runtimeError(err)
	}
	if expectedTarget != nil {
		// Scenario metadata is maintained alongside the managed fixture but is
		// not part of the producer import contract. Preserve it across the
		// atomic replacement so a documented update does not delete the
		// scenario's expected outcome file.
		expectedPath := filepath.Join(target, "expected.yaml")
		if _, err := os.Lstat(expectedPath); err == nil {
			expectedRaw, err := readSafe(target, "expected.yaml")
			if err != nil {
				return classifyReadFailure("read fixture expected metadata", err)
			}
			if err := os.WriteFile(filepath.Join(dest, "expected.yaml"), expectedRaw, 0o600); err != nil {
				return runtimeError(err)
			}
		} else if !os.IsNotExist(err) {
			return runtimeError(err)
		}
	}
	for _, s := range contract.Sources {
		for _, f := range append(sourceFiles(s), artifactFiles(s)...) {
			if err := copyExact(filepath.Join(sourceRoot, s.Product, f.Path), filepath.Join(dest, "source", s.Product, f.Path)); err != nil {
				return classifyReadFailure(fmt.Sprintf("copy %s source file", s.Product), err)
			}
		}
	}
	if err := validateSources(filepath.Join(dest, "source"), contract); err != nil {
		return err
	}
	manifest, err := buildManifest(contract, canonicalContract)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dest, ManifestPath), manifest, 0o600); err != nil {
		return runtimeError(err)
	}
	if err := replaceDirectory(staging, target, expectedTarget); err != nil {
		var unsafeErr *UnsafeError
		if errors.As(err, &unsafeErr) {
			return err
		}
		return runtimeError(err)
	}
	return nil
}

// Check validates the committed staged tree without reading any external
// checkout. It is deterministic and offline.
func Check(dest string) error {
	if _, err := readManagedMarker(dest); err != nil {
		return err
	}
	contractRaw, err := readSafe(dest, ContractPath)
	if err != nil {
		return classifyReadFailure("read fixture contract", err)
	}
	contract, err := LoadContract(contractRaw)
	if err != nil {
		return err
	}
	canonicalContract, err := canonicalJSON(contract)
	if err != nil {
		return err
	}
	if err := compareUnder(dest, ContractPath, canonicalContract); err != nil {
		return err
	}
	// Validate the shared source root before using each product directory as
	// readSafe's root. Otherwise a symlink at source/ could become an
	// unobserved ancestor of every product path and redirect reads outside the
	// committed fixture.
	if err := rejectSymlinkBetween(dest, filepath.Join(dest, "source")); err != nil {
		return classifyReadFailure("validate fixture source root", err)
	}
	if err := validateSources(filepath.Join(dest, "source"), contract); err != nil {
		return err
	}
	want, err := buildManifest(contract, canonicalContract)
	if err != nil {
		return err
	}
	if err := compareUnder(dest, ManifestPath, want); err != nil {
		return err
	}
	return orphanCheck(dest, contract)
}

func validateSources(root string, c Contract) error {
	for _, s := range c.Sources {
		productRoot := filepath.Join(root, s.Product)
		manifestRaw, err := readSafe(productRoot, s.ManifestPath)
		if err != nil {
			return classifyReadFailure(fmt.Sprintf("%s manifest", s.Product), err)
		}
		if !digestEqual(manifestRaw, s.ManifestSHA256) {
			return fmt.Errorf("%s manifest digest mismatch", s.Product)
		}
		if err := validateJSONBytes(manifestRaw, "manifest"); err != nil {
			return fmt.Errorf("%s manifest JSON integrity: %w", s.Product, err)
		}
		if err := validateProducerMetadata(manifestRaw, s); err != nil {
			return fmt.Errorf("%s producer metadata: %w", s.Product, err)
		}
		authoritativeManifest, err := parseAuthoritativeManifest(manifestRaw, s)
		if err != nil {
			return fmt.Errorf("%s authoritative manifest: %w", s.Product, err)
		}
		var publicKey ed25519.PublicKey
		if s.PublicKeyPath != "" {
			key, err := readSafe(productRoot, s.PublicKeyPath)
			if err != nil {
				return classifyReadFailure(fmt.Sprintf("%s public key", s.Product), err)
			}
			if !digestEqual(key, s.PublicKeySHA256) {
				return fmt.Errorf("%s public key digest mismatch", s.Product)
			}
			publicKey, err = decodePublicKey(key)
			if err != nil {
				return fmt.Errorf("%s public key: %w", s.Product, err)
			}
		}
		schemas := map[string]File{}
		schemaBytes := map[string][]byte{}
		schemaIDs := map[string]string{}
		for _, schema := range s.Schemas {
			b, err := readSafe(productRoot, schema.Path)
			if err != nil {
				return classifyReadFailure(fmt.Sprintf("%s schema %s", s.Product, schema.Path), err)
			}
			if !digestEqual(b, schema.SHA256) {
				return fmt.Errorf("%s schema digest mismatch: %s", s.Product, schema.Path)
			}
			if err := validateJSONBytes(b, "schema"); err != nil {
				return schemaError(fmt.Errorf("%s schema %s JSON integrity: %w", s.Product, schema.Path, err))
			}
			if err := validateSchemaIdentity(b, schema); err != nil {
				return schemaError(fmt.Errorf("%s schema %s: %w", s.Product, schema.Path, err))
			}
			if previous, exists := schemaIDs[schema.SchemaID]; exists {
				return schemaError(fmt.Errorf("%s schema identity %q is declared by both %s and %s", s.Product, schema.SchemaID, previous, schema.Path))
			}
			schemaIDs[schema.SchemaID] = schema.Path
			schemas[schema.Path] = schema
			schemaBytes[schema.Path] = b
		}
		for _, artifact := range s.Artifacts {
			b, err := readSafe(productRoot, artifact.Path)
			if err != nil {
				return classifyReadFailure(fmt.Sprintf("%s artifact %s", s.Product, artifact.Path), err)
			}
			if !digestEqual(b, artifact.SHA256) {
				return fmt.Errorf("%s artifact digest mismatch: %s", s.Product, artifact.Path)
			}
			if err := validateArtifactAgainstSchema(b, s.Product, artifact, schemas, schemaBytes); err != nil {
				return schemaError(fmt.Errorf("%s artifact schema validation %s: %w", s.Product, artifact.Path, err))
			}
			if s.Product == "axym" {
				if err := validateAxymArtifactRole(b, artifact); err != nil {
					return schemaError(fmt.Errorf("%s artifact role %s: %w", s.Product, artifact.Path, err))
				}
			}
			schema, ok := schemas[artifact.SchemaPath]
			if !ok || !digestEqualBytes(schema.SHA256, artifact.SchemaSHA256) {
				return fmt.Errorf("%s artifact schema digest mismatch: %s", s.Product, artifact.Path)
			}
			if artifact.Synthetic || !artifact.ProducerArtifact {
				return fmt.Errorf("%s artifact is not an exact producer artifact: %s", s.Product, artifact.Path)
			}
			if s.Product == "axym" {
				if err := rejectSyntheticPayload(b); err != nil {
					return fmt.Errorf("%s artifact provenance %s: %w", s.Product, artifact.Path, err)
				}
			}
			if artifact.SignaturePath != "" {
				signature, err := readSafe(productRoot, artifact.SignaturePath)
				if err != nil {
					return classifyReadFailure(fmt.Sprintf("%s artifact signature %s", s.Product, artifact.Path), err)
				}
				if !digestEqual(signature, artifact.SignatureSHA256) {
					return fmt.Errorf("%s artifact signature digest mismatch: %s", s.Product, artifact.Path)
				}
			}
			requireSignature := artifact.SignatureRequired
			if err := verifyInlineSignatures(b, publicKey, requireSignature); err != nil {
				return fmt.Errorf("%s artifact signature %s: %w", s.Product, artifact.Path, err)
			}
			if err := rejectIdentifierOnlyOverclaim(b); err != nil {
				return fmt.Errorf("%s artifact integrity claim %s: %w", s.Product, artifact.Path, err)
			}
			if err := validateArtifactRelationships(b, artifact.RelationshipRefs); err != nil {
				return fmt.Errorf("%s artifact relationships %s: %w", s.Product, artifact.Path, err)
			}
		}
		if authoritativeManifest != nil {
			if err := validateAuthoritativeFileSet(authoritativeManifest, s); err != nil {
				return fmt.Errorf("%s authoritative manifest files: %w", s.Product, err)
			}
		}
	}
	return nil
}

func rejectIdentifierOnlyOverclaim(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	var walk func(any) error
	walk = func(v any) error {
		switch item := v.(type) {
		case map[string]any:
			if mode, _ := item["binding_mode"].(string); mode == "identifier_only" {
				if digest, ok := item["content_digest"]; ok && digest != nil && digest != "" {
					return errors.New("identifier_only binding cannot claim content_digest")
				}
				if ref, ok := item["proof_ref"].(map[string]any); ok {
					if digest, exists := ref["digest"]; exists && digest != nil && digest != "" {
						return errors.New("identifier_only binding cannot claim a proof digest")
					}
				}
			}
			keys := make([]string, 0, len(item))
			for key := range item {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if err := walk(item[key]); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range item {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}

func rejectSyntheticPayload(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	var walk func(any) error
	walk = func(v any) error {
		switch item := v.(type) {
		case map[string]any:
			for _, key := range []string{"synthetic", "fixture_only"} {
				if flagged, ok := item[key].(bool); ok && flagged {
					return fmt.Errorf("payload marks itself %s", key)
				}
			}
			if assessment, ok := item["assessment"].(string); ok && strings.EqualFold(strings.TrimSpace(assessment), "synthetic") {
				return errors.New("payload marks itself synthetic")
			}
			for _, key := range []string{"quarantine", "non_authoritative", "synthetic_extension", "fixture_test_only", "development_signing"} {
				if flagged, ok := item[key].(bool); ok && flagged {
					return fmt.Errorf("payload marks itself %s", key)
				}
			}
			if authoritative, ok := item["authoritative"].(bool); ok && !authoritative {
				return errors.New("payload is not authoritative")
			}
			keys := make([]string, 0, len(item))
			for key := range item {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if err := walk(item[key]); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range item {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}

func decodePublicKey(raw []byte) (ed25519.PublicKey, error) {
	value := strings.TrimSpace(string(raw))
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("public key must be 32-byte hex or base64")
	}
	return ed25519.PublicKey(decoded), nil
}

func verifyInlineSignatures(raw []byte, publicKey ed25519.PublicKey, required bool) error {
	if !json.Valid(raw) {
		if required {
			return errors.New("signed artifact is not JSON")
		}
		return nil
	}
	count := 0
	var walk func([]byte, bool) error
	walk = func(data []byte, root bool) error {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err == nil && object != nil {
			// Gait typed evidence signs the containing evidence object while
			// storing its signature under provenance.signature. Verify that
			// containing object here and do not reinterpret provenance itself as
			// a separately signed artifact.
			if provenanceRaw, hasProvenance := object["provenance"]; hasProvenance {
				var provenance map[string]json.RawMessage
				if err := json.Unmarshal(provenanceRaw, &provenance); err == nil && provenance != nil {
					if signatureRaw, hasSignature := provenance["signature"]; hasSignature {
						var signature map[string]any
						if err := json.Unmarshal(signatureRaw, &signature); err != nil || signature == nil {
							return errors.New("inline signature must be an object")
						}
						count++
						if err := verifyInlineSignature(object, signature, publicKey); err != nil {
							return err
						}
					}
				}
			}
			signatureRaw, hasSignature := object["signature"]
			if hasSignature {
				count++
				var signature map[string]any
				if err := json.Unmarshal(signatureRaw, &signature); err != nil || signature == nil {
					return errors.New("inline signature must be an object")
				}
				if err := verifyInlineSignature(object, signature, publicKey); err != nil {
					return err
				}
			} else if root && signedObjectIdentity(object) && required {
				return errors.New("required inline signature is missing")
			}
			keys := make([]string, 0, len(object))
			for key := range object {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				child := object[key]
				if key == "signature" || key == "provenance" {
					continue
				}
				if err := walk(child, false); err != nil {
					return err
				}
			}
			return nil
		}
		var list []json.RawMessage
		if err := json.Unmarshal(data, &list); err == nil && list != nil {
			for _, child := range list {
				if err := walk(child, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(raw, true); err != nil {
		return err
	}
	if required && count == 0 {
		return errors.New("required inline signature is missing")
	}
	return nil
}

func signedObjectIdentity(object map[string]json.RawMessage) bool {
	for _, key := range []string{"record_id", "artifact_id", "packet_id", "token_id", "register_id", "evidence_id"} {
		if _, ok := object[key]; ok {
			return true
		}
	}
	return false
}

func verifyInlineSignature(object map[string]json.RawMessage, signature map[string]any, publicKey ed25519.PublicKey) error {
	var parsed prooffsign.Signature
	rawSignature, err := json.Marshal(signature)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(rawSignature, &parsed); err != nil {
		return err
	}
	if parsed.Alg != "ed25519" || parsed.KeyID == "" || parsed.Sig == "" || parsed.SignedDigest == "" {
		return errors.New("inline signature must contain ed25519 alg, key_id, sig, and signed_digest")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("inline signature requires a valid pinned public key")
	}
	if parsed.KeyID != prooffsign.KeyID(publicKey) {
		return errors.New("inline signature key_id does not match pinned public key")
	}
	canonicalObject := make(map[string]json.RawMessage, len(object))
	for key, value := range object {
		canonicalObject[key] = value
	}
	_, packet := canonicalObject["packet_id"]
	_, packetDigest := canonicalObject["digest"]
	_, register := canonicalObject["contracts"]
	_, registerDigest := canonicalObject["digest"]
	_, evidence := canonicalObject["evidence_id"]
	if packet && packetDigest {
		// Axym Packet signs the content with digest cleared and omits the
		// optional signature pointer while calculating that digest.
		if _, hasDigest := canonicalObject["digest"]; hasDigest {
			delete(canonicalObject, "digest")
			delete(canonicalObject, "signature")
		} else {
			canonicalObject["signature"] = json.RawMessage(`{"alg":"","key_id":"","sig":""}`)
		}
	} else if register && registerDigest && canonicalObject["schema_id"] != nil && strings.Contains(string(canonicalObject["schema_id"]), "action-contract-register.schema.json") {
		// Axym registers, like packets, sign the object with its digest and
		// signature fields cleared.
		delete(canonicalObject, "digest")
		delete(canonicalObject, "signature")
	} else if _, token := canonicalObject["token_id"]; token {
		// Gait approval/delegation tokens use an omitempty signature pointer;
		// their signable form removes signature entirely and retains token_id.
		delete(canonicalObject, "signature")
	} else if evidence {
		// Gait typed evidence signs the object after removing its identity and
		// canonical digest, plus the nested provenance signature.
		delete(canonicalObject, "evidence_id")
		delete(canonicalObject, "canonical_content_digest")
		if provenance, ok := canonicalObject["provenance"]; ok {
			var provenanceObject map[string]json.RawMessage
			if err := json.Unmarshal(provenance, &provenanceObject); err != nil {
				return err
			}
			delete(provenanceObject, "signature")
			provenance, err = json.Marshal(provenanceObject)
			if err != nil {
				return err
			}
			canonicalObject["provenance"] = provenance
		}
	} else {
		// Gait's producer canonicalization clears fields while preserving the
		// typed Signature object shape; its optional signed_digest field is
		// omitted when zero-valued.
		canonicalObject["signature"] = json.RawMessage(`{"alg":"","key_id":"","sig":""}`)
		if _, exists := canonicalObject["record_id"]; exists {
			canonicalObject["record_id"] = json.RawMessage(`""`)
		}
		if _, exists := canonicalObject["artifact_id"]; exists {
			canonicalObject["artifact_id"] = json.RawMessage(`""`)
		}
	}
	canonicalRaw, err := json.Marshal(canonicalObject)
	if err != nil {
		return err
	}
	digestHex, err := prooffcanon.DigestHex(canonicalRaw, prooffcanon.DomainJSON)
	if err != nil {
		return err
	}
	if packet && packetDigest {
		var declared string
		if err := json.Unmarshal(object["digest"], &declared); err != nil || !digestEqualBytes(declared, "sha256:"+digestHex) {
			return errors.New("packet declared digest does not match canonical content")
		}
	} else if register && registerDigest {
		var declared string
		if err := json.Unmarshal(object["digest"], &declared); err != nil || !digestEqualBytes(declared, "sha256:"+digestHex) {
			return errors.New("register declared digest does not match canonical content")
		}
	} else if evidence {
		var declared string
		if err := json.Unmarshal(object["canonical_content_digest"], &declared); err != nil || strings.TrimPrefix(declared, "sha256:") != strings.TrimPrefix(digestHex, "sha256:") {
			return errors.New("typed evidence canonical_content_digest does not match canonical content")
		}
	}
	if strings.TrimPrefix(parsed.SignedDigest, "sha256:") != strings.TrimPrefix(digestHex, "sha256:") {
		return errors.New("inline signature signed_digest does not match canonical content")
	}
	valid, err := prooffsign.VerifyDigestHex(publicKey, prooffsign.Signature{Alg: parsed.Alg, KeyID: parsed.KeyID, Sig: parsed.Sig, SignedDigest: parsed.SignedDigest})
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("inline signature verification failed")
	}
	return nil
}

func validateProducerMetadata(raw []byte, s Source) error {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("manifest is not JSON: %w", err)
	}
	if authoritative, err := parseAuthoritativeManifest(raw, s); authoritative != nil || err != nil {
		return err
	}
	producer, _ := obj["producer"].(map[string]any)
	name, err := consistentStringAlias(producer, obj, "name", "product")
	if err != nil {
		return err
	}
	version, err := consistentStringAlias(producer, obj, "version")
	if err != nil {
		return err
	}
	commit, err := consistentStringAlias(producer, obj, "commit", "source_commit")
	if err != nil {
		return err
	}
	if name != s.Product || version != s.Version {
		return fmt.Errorf("manifest producer %q/%q does not match pinned %q/%q", name, version, s.Product, s.Version)
	}
	if commit != "" && commit != s.Commit {
		return fmt.Errorf("manifest commit %q does not match pinned %q", commit, s.Commit)
	}
	manifestTag, err := consistentStringAlias(producer, obj, "tag")
	if err != nil {
		return err
	}
	if manifestTag != "" && manifestTag != s.Tag {
		return fmt.Errorf("manifest tag %q does not match pinned %q", manifestTag, s.Tag)
	}
	if _, has := obj["proof_commit"]; has {
		return errors.New("source manifest contains stale self-provenance proof_commit")
	}
	if _, has := obj["proof_version"]; has {
		return errors.New("source manifest contains stale self-provenance proof_version")
	}
	return nil
}

type authoritativeManifest struct {
	SchemaID        string          `json:"schema_id"`
	SchemaVersion   string          `json:"schema_version"`
	ReleaseTag      string          `json:"release_tag"`
	PeeledCommit    string          `json:"peeled_commit"`
	Authoritative   bool            `json:"authoritative"`
	FixtureOnly     bool            `json:"fixture_only"`
	DevelopmentSign bool            `json:"development_signing"`
	Quarantine      bool            `json:"quarantine"`
	Artifacts       json.RawMessage `json:"artifacts"`
	ArtifactFiles   []File          `json:"-"`
	Referenced      []File          `json:"referenced_schemas"`
	ManifestVersion string          `json:"manifest_version"`
	Producer        struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"producer"`
	Schemas []File `json:"schemas"`
	Files   []File `json:"files"`
	Signing struct {
		Algorithm       string `json:"algorithm"`
		PublicKeyPath   string `json:"public_key_path"`
		PublicKeySHA256 string `json:"public_key_sha256"`
		KeyID           string `json:"key_id"`
	} `json:"signing"`
}

func parseAuthoritativeManifest(raw []byte, s Source) (*authoritativeManifest, error) {
	var marker struct {
		SchemaID string `json:"schema_id"`
	}
	if err := json.Unmarshal(raw, &marker); err != nil {
		return nil, fmt.Errorf("authoritative manifest JSON: %w", err)
	}
	var markerFields struct {
		SchemaID     string `json:"schema_id"`
		ReleaseTag   string `json:"release_tag"`
		PeeledCommit string `json:"peeled_commit"`
	}
	if err := json.Unmarshal(raw, &markerFields); err != nil {
		return nil, fmt.Errorf("authoritative manifest JSON: %w", err)
	}
	if !strings.Contains(marker.SchemaID, "authoritative-evidence-bundle-manifest.schema.json") && (markerFields.ReleaseTag == "" || markerFields.PeeledCommit == "") {
		return nil, nil
	}
	var manifest authoritativeManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("authoritative manifest JSON: %w", err)
	}
	if strings.Contains(manifest.SchemaID, "authoritative-evidence-bundle-manifest.schema.json") {
		wantSchema := fmt.Sprintf("https://%s.dev/schemas/v1/action-contract/authoritative-evidence-bundle-manifest.schema.json", s.Product)
		if manifest.SchemaID != wantSchema || manifest.SchemaVersion != "1" {
			return nil, fmt.Errorf("authoritative manifest schema identity does not match %s", s.Product)
		}
		if err := json.Unmarshal(manifest.Artifacts, &manifest.ArtifactFiles); err != nil {
			return nil, errors.New("authoritative manifest artifacts must be an array")
		}
	} else if s.Product == "axym" && manifest.ManifestVersion == "v1" {
		if manifest.Producer.Name != "axym" || manifest.Producer.Version != s.Version {
			return nil, errors.New("authoritative manifest producer identity does not match pinned source")
		}
		manifest.SchemaVersion = manifest.ManifestVersion
		manifest.Referenced = manifest.Schemas
		var artifacts map[string]string
		if err := json.Unmarshal(manifest.Artifacts, &artifacts); err != nil {
			return nil, errors.New("authoritative manifest artifacts must be an object")
		}
		for _, file := range manifest.Files {
			if !strings.Contains(file.Path, ".schema.") && (strings.Contains(file.Path, "register") || strings.Contains(file.Path, "packet") || strings.Contains(file.Path, "public-key")) {
				manifest.ArtifactFiles = append(manifest.ArtifactFiles, file)
			}
		}
	}
	if manifest.ReleaseTag != s.Tag || manifest.PeeledCommit != s.PeeledCommit {
		return nil, errors.New("authoritative manifest release identity does not match pinned tag")
	}
	if !manifest.Authoritative || manifest.FixtureOnly || manifest.DevelopmentSign || manifest.Quarantine {
		return nil, errors.New("authoritative manifest must be authoritative and non-quarantined")
	}
	if manifest.Signing.Algorithm != "ed25519" || manifest.Signing.PublicKeyPath != s.PublicKeyPath || manifest.Signing.PublicKeySHA256 != s.PublicKeySHA256 {
		return nil, errors.New("authoritative manifest signing identity does not match pinned public key")
	}
	if len(manifest.Artifacts) == 0 || len(manifest.Referenced) == 0 {
		return nil, errors.New("authoritative manifest must list artifacts and referenced schemas")
	}
	return &manifest, nil
}

func validateAuthoritativeFileSet(manifest *authoritativeManifest, s Source) error {
	wantArtifacts := map[string]string{}
	for _, artifact := range s.Artifacts {
		wantArtifacts[artifact.Path] = artifact.SHA256
	}
	if s.PublicKeyPath != "" {
		wantArtifacts[s.PublicKeyPath] = s.PublicKeySHA256
	}
	if len(manifest.ArtifactFiles) != len(wantArtifacts) {
		return errors.New("authoritative manifest artifact set does not match contract")
	}
	for _, file := range manifest.ArtifactFiles {
		if wantArtifacts[file.Path] != file.SHA256 {
			return fmt.Errorf("authoritative manifest artifact digest is not pinned: %s", file.Path)
		}
		delete(wantArtifacts, file.Path)
	}
	if len(wantArtifacts) != 0 {
		return errors.New("contract is missing an authoritative manifest artifact")
	}
	wantSchemas := map[string]string{}
	for _, schema := range s.Schemas {
		wantSchemas[schema.Path] = schema.SHA256
	}
	manifestSchemas := map[string]string{}
	for _, file := range manifest.Referenced {
		manifestSchemas[file.Path] = file.SHA256
	}
	for path, digest := range wantSchemas {
		if manifestSchemas[path] != digest {
			return fmt.Errorf("contract schema is not pinned by authoritative manifest: %s", path)
		}
	}
	return nil
}

func consistentStringAlias(producer, top map[string]any, keys ...string) (string, error) {
	chosen := ""
	locations := []struct {
		label  string
		object map[string]any
	}{
		{"producer", producer},
		{"top-level", top},
	}
	for _, key := range keys {
		for _, location := range locations {
			if v, ok := location.object[key].(string); ok && strings.TrimSpace(v) != "" {
				if chosen != "" && chosen != v {
					return "", fmt.Errorf("manifest has conflicting producer %s values (%q versus %q)", location.label+"."+key, chosen, v)
				}
				chosen = v
			}
		}
	}
	return chosen, nil
}

func validateSchemaIdentity(raw []byte, expected File) error {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("schema is not JSON: %w", err)
	}
	if id, _ := obj["$id"].(string); id != expected.SchemaID {
		return fmt.Errorf("schema $id %q does not match %q", id, expected.SchemaID)
	}
	markers := []struct {
		name  string
		value string
	}{
		{name: "x-proof-schema-version", value: schemaString(obj, "x-proof-schema-version")},
		{name: "schema_version", value: schemaConst(obj, "schema_version")},
		{name: "version", value: schemaConst(obj, "version")},
		{name: "contract_version", value: schemaConst(obj, "contract_version")},
	}
	found := false
	for _, marker := range markers {
		if marker.value == "" {
			continue
		}
		found = true
		if marker.value != expected.SchemaVersion {
			return fmt.Errorf("schema version %s %q does not match %q", marker.name, marker.value, expected.SchemaVersion)
		}
	}
	if !found {
		return fmt.Errorf("schema version %q does not match %q", "", expected.SchemaVersion)
	}
	return nil
}

func schemaString(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}

func schemaConst(schema map[string]any, property string) string {
	properties, _ := schema["properties"].(map[string]any)
	entry, _ := properties[property].(map[string]any)
	value, _ := entry["const"].(string)
	return value
}

func rejectDuplicateJSONMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkJSONTokens(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("artifact contains trailing JSON")
		}
		return fmt.Errorf("artifact contains trailing data: %w", err)
	}
	return nil
}

func validateJSONBytes(raw []byte, label string) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("%s is not valid UTF-8", label)
	}
	if err := rejectUnpairedSurrogates(raw); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return err
	}
	return nil
}

func rejectUnpairedSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		if !inString {
			if raw[i] == '"' {
				inString = true
			}
			continue
		}
		if raw[i] == '"' {
			inString = false
			continue
		}
		if raw[i] != '\\' || i+1 >= len(raw) {
			continue
		}
		if raw[i+1] != 'u' || i+5 >= len(raw) {
			i++
			continue
		}
		code, ok := parseUnicodeEscape(raw[i+2 : i+6])
		if !ok {
			i++
			continue
		}
		switch {
		case code >= 0xdc00 && code <= 0xdfff:
			return errors.New("JSON contains an unpaired low surrogate escape")
		case code >= 0xd800 && code <= 0xdbff:
			if i+11 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
				return errors.New("JSON contains an unpaired high surrogate escape")
			}
			low, lowOK := parseUnicodeEscape(raw[i+8 : i+12])
			if !lowOK || low < 0xdc00 || low > 0xdfff {
				return errors.New("JSON contains an unpaired high surrogate escape")
			}
			i += 11
		default:
			i += 5
		}
	}
	return nil
}

func parseUnicodeEscape(raw []byte) (int, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	value := 0
	for _, digit := range raw {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value += int(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value += int(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value += int(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func walkJSONTokens(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("JSON object member name is not a string")
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("duplicate JSON object member %q", name)
			}
			seen[name] = struct{}{}
			if err := walkJSONTokens(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("JSON object does not terminate correctly")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONTokens(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("JSON array does not terminate correctly")
		}
	case '}', ']':
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func validateArtifactAgainstSchema(raw []byte, product string, artifact Artifact, schemas map[string]File, schemaBytes map[string][]byte) error {
	if err := validateJSONBytes(raw, "artifact"); err != nil {
		return fmt.Errorf("artifact is not valid JSON or has duplicate members: %w", err)
	}
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return fmt.Errorf("artifact is not valid JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("artifact contains trailing JSON")
		}
		return fmt.Errorf("artifact contains trailing data: %w", err)
	}
	payloads := []map[string]any{payload}
	// Gait lifecycle exports are exact packs containing signed records; the
	// pinned runtime-lifecycle schema applies to every member record.
	if product == "gait" && artifact.SchemaID == "https://gait.dev/schemas/v1/runtime-lifecycle-record.schema.json" {
		if _, hasID := payload["schema_id"]; !hasID {
			members, ok := payload["records"].([]any)
			if !ok || len(members) == 0 {
				return fmt.Errorf("payload schema_id is missing")
			}
			payloads = make([]map[string]any, 0, len(members))
			for i, member := range members {
				object, ok := member.(map[string]any)
				if !ok {
					return fmt.Errorf("payload records[%d] is not an object", i)
				}
				payloads = append(payloads, object)
			}
		}
	}
	schema, ok := schemas[artifact.SchemaPath]
	if !ok {
		return errors.New("artifact schema is not pinned")
	}
	if artifact.SchemaID != schema.SchemaID || artifact.SchemaVersion != schema.SchemaVersion {
		return errors.New("contract artifact schema identity does not match pinned schema")
	}
	compiler := jsonschema.NewCompiler()
	// Never fetch schema references from the network. Every reference must be
	// backed by a contract-pinned resource added below.
	compiler.LoadURL = func(url string) (io.ReadCloser, error) {
		return nil, fmt.Errorf("remote schema loading is disabled: %s", url)
	}
	schemaPaths := make([]string, 0, len(schemas))
	for path := range schemas {
		schemaPaths = append(schemaPaths, path)
	}
	sort.Strings(schemaPaths)
	for _, path := range schemaPaths {
		definition := schemas[path]
		bytesForSchema, ok := schemaBytes[path]
		if !ok {
			return fmt.Errorf("schema bytes are missing: %s", path)
		}
		if err := compiler.AddResource(definition.SchemaID, bytes.NewReader(bytesForSchema)); err != nil {
			return fmt.Errorf("compile schema %s: %w", path, err)
		}
	}
	for _, path := range schemaPaths {
		definition := schemas[path]
		if _, err := compiler.Compile(definition.SchemaID); err != nil {
			return fmt.Errorf("compile pinned schema %s: %w", path, err)
		}
	}
	compiled, err := compiler.Compile(schema.SchemaID)
	if err != nil {
		return fmt.Errorf("compile artifact schema: %w", err)
	}
	for i, item := range payloads {
		payloadID, _ := item["schema_id"].(string)
		if payloadID != artifact.SchemaID {
			return fmt.Errorf("payload schema_id %q does not match contract %q", payloadID, artifact.SchemaID)
		}
		payloadVersion, _ := item["schema_version"].(string)
		if payloadVersion == "" {
			payloadVersion, _ = item["version"].(string)
		}
		if payloadVersion != artifact.SchemaVersion {
			return fmt.Errorf("payload schema version %q does not match contract %q", payloadVersion, artifact.SchemaVersion)
		}
		if err := compiled.Validate(item); err != nil {
			return fmt.Errorf("artifact record %d does not satisfy schema: %w", i, err)
		}
	}
	return nil
}

func validateAxymArtifactRole(raw []byte, artifact Artifact) error {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("payload is not valid JSON: %w", err)
	}
	kind := strings.ToLower(artifact.Kind)
	if strings.Contains(kind, "register") {
		if artifact.SchemaID != AxymRegisterSchemaID || artifact.SchemaVersion != AxymSchemaVersion {
			return fmt.Errorf("register artifact must use normative schema %s", AxymRegisterSchemaID)
		}
		if _, ok := payload["contracts"].([]any); !ok {
			return errors.New("register artifact must contain contracts")
		}
	}
	if strings.Contains(kind, "packet") {
		if artifact.SchemaID != AxymPacketSchemaID || artifact.SchemaVersion != AxymSchemaVersion {
			return fmt.Errorf("evidence packet must use normative schema %s", AxymPacketSchemaID)
		}
		packetID, _ := payload["packet_id"].(string)
		if strings.TrimSpace(packetID) == "" {
			return errors.New("evidence packet must contain packet_id")
		}
	}
	return nil
}

func validateArtifactRelationships(raw []byte, expected []Reference) error {
	if len(expected) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("artifact is not JSON: %w", err)
	}
	refs := []Reference{}
	collectReferences(value, &refs)
	for _, want := range expected {
		found := false
		for _, got := range refs {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("pinned relationship ref missing or mutated: %s/%s", want.Kind, want.ID)
		}
	}
	return nil
}

func collectReferences(value any, refs *[]Reference) {
	switch v := value.(type) {
	case map[string]any:
		if _, ok := v["kind"]; ok {
			if _, ok := v["id"]; ok {
				r := Reference{}
				r.Kind, _ = v["kind"].(string)
				r.ID, _ = v["id"].(string)
				r.Digest, _ = v["digest"].(string)
				r.SchemaID, _ = v["schema_id"].(string)
				r.SchemaVersion, _ = v["schema_version"].(string)
				r.SourceProduct, _ = v["source_product"].(string)
				*refs = append(*refs, r)
			}
		}
		for _, child := range v {
			collectReferences(child, refs)
		}
	case []any:
		for _, child := range v {
			collectReferences(child, refs)
		}
	}
}

func sourceFiles(s Source) []File {
	files := []File{{Path: s.ManifestPath, SHA256: s.ManifestSHA256}}
	if s.PublicKeyPath != "" {
		files = append(files, File{Path: s.PublicKeyPath, SHA256: s.PublicKeySHA256})
	}
	for _, asset := range s.ReleaseAssets {
		files = append(files, File{Path: asset.Path, SHA256: asset.SHA256})
	}
	return append(files, s.Schemas...)
}

func artifactFiles(s Source) []File {
	files := make([]File, 0, len(s.Artifacts))
	for _, a := range s.Artifacts {
		files = append(files, File{Path: a.Path, SHA256: a.SHA256})
		if a.SignaturePath != "" {
			files = append(files, File{Path: a.SignaturePath, SHA256: a.SignatureSHA256})
		}
	}
	return files
}

func buildManifest(c Contract, contractRaw []byte) ([]byte, error) {
	contractDigest, err := canonicalDigest(contractRaw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize import contract: %w", err)
	}
	manifest := importedManifest{Format: ContractFormat, FixtureID: c.FixtureID, ContractSHA: contractDigest, FixtureOnly: true}
	for _, s := range c.Sources {
		out := importedSource{Product: s.Product, Version: s.Version, Commit: s.Commit, Tag: s.Tag, TagObject: s.TagObject, PeeledCommit: s.PeeledCommit, IntegrityMode: s.IntegrityMode, Manifest: s.ManifestPath, ManifestSHA256: s.ManifestSHA256, PublicKey: s.PublicKeyPath, PublicKeySHA256: s.PublicKeySHA256, ReleaseAssets: s.ReleaseAssets}
		for _, schema := range s.Schemas {
			out.Schemas = append(out.Schemas, schema.Path)
		}
		for _, artifact := range s.Artifacts {
			out.Artifacts = append(out.Artifacts, artifact.Path)
		}
		sort.Strings(out.Schemas)
		sort.Strings(out.Artifacts)
		manifest.Sources = append(manifest.Sources, out)
	}
	return canonicalJSON(manifest)
}

func canonicalDigest(raw []byte) (string, error) {
	digestHex, err := prooffcanon.DigestHex(raw, prooffcanon.DomainJSON)
	if err != nil {
		return "", err
	}
	return "sha256:" + strings.TrimPrefix(digestHex, "sha256:"), nil
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// CanonicalContractBytes returns the exact contract representation staged by
// Update and checked by Check.
func CanonicalContractBytes(contract Contract) ([]byte, error) {
	return canonicalJSON(contract)
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestEqual(raw []byte, expected string) bool { return digestEqualBytes(digest(raw), expected) }

func digestEqualBytes(actual, expected string) bool {
	a, errA := parseDigest(actual)
	b, errB := parseDigest(expected)
	return errA == nil && errB == nil && a == b
}

func parseDigest(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "sha256:")
	if len(value) != sha256.Size*2 {
		return "", errors.New("must be a 64-character SHA-256 digest")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("must be hexadecimal SHA-256")
	}
	return value, nil
}

func safePath(path string) error {
	if path == "" || filepath.IsAbs(path) || hasWindowsVolume(path) || strings.Contains(path, "\\") {
		return errors.New("path must be a non-empty portable relative path")
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("path must contain no empty or traversal components")
		}
		if err := validatePortableComponent(part); err != nil {
			return err
		}
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return errors.New("path escapes source root")
	}
	return nil
}

func hasWindowsVolume(path string) bool {
	return len(path) >= 2 && path[1] == ':' && ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z'))
}

func validatePortableComponent(component string) error {
	if strings.TrimRight(component, " .") != component {
		return errors.New("path components may not end with a space or period")
	}
	if strings.ContainsAny(component, `<>:"|?*`) {
		return errors.New("path contains a platform-reserved character")
	}
	for _, r := range component {
		if r < 0x20 {
			return errors.New("path contains a control character")
		}
	}
	base := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return errors.New("path contains a Windows-reserved device name")
	}
	return nil
}

func readSafe(root, path string) ([]byte, error) {
	if err := safePath(path); err != nil {
		return nil, err
	}
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, err
	}
	full := filepath.Join(rootAbs, filepath.FromSlash(path))
	if err := rejectSymlinkBetween(rootAbs, full); err != nil {
		return nil, err
	}
	before, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("path is not a regular file: %s", full)
	}
	file, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) {
		return nil, errors.New("file changed during read")
	}
	after, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !sameStableFile(before, after) {
		return nil, errors.New("file changed during read")
	}
	return io.ReadAll(file)
}

func readNoSymlink(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("symlink path is not allowed: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !sameStableFile(info, opened) {
		return nil, errors.New("file changed during read")
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !sameStableFile(info, after) {
		return nil, fmt.Errorf("symlink path is not allowed: %s", path)
	}
	return io.ReadAll(file)
}

func rejectSymlinkBetween(root, path string) error {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return err
	}
	pathAbs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("path escapes source root")
	}
	for current := pathAbs; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		} else if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink path is not allowed: %s", current)
		}
		if current == rootAbs {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("path escapes source root")
		}
	}
}

func compareUnder(root, rel string, want []byte) error {
	got, err := readSafe(root, rel)
	if err != nil {
		return classifyReadFailure(fmt.Sprintf("read fixture file %s", rel), err)
	}
	if !bytes.Equal(got, want) {
		return driftError(fmt.Errorf("fixture drift: %s", rel))
	}
	return nil
}

func copyExact(source, dest string) error {
	b, err := readNoSymlink(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return err
	}
	return os.WriteFile(dest, b, 0o600)
}

type destinationIdentity struct {
	directory os.FileInfo
	marker    os.FileInfo
}

func destinationIdentityFor(path string, directory os.FileInfo) (*destinationIdentity, error) {
	marker, err := os.Lstat(filepath.Join(path, ManagedMarker))
	if err != nil {
		return nil, runtimeError(fmt.Errorf("stat fixture managed marker: %w", err))
	}
	if marker.Mode()&os.ModeSymlink != 0 || !marker.Mode().IsRegular() {
		return nil, unsafeError(errors.New("fixture managed marker is missing or invalid"))
	}
	return &destinationIdentity{directory: directory, marker: marker}, nil
}

func replaceDirectory(staging, target string, expectedTarget *destinationIdentity) error {
	backup, err := os.MkdirTemp(filepath.Dir(target), ".proof-fixture-backup-")
	if err != nil {
		return err
	}
	if err := os.Remove(backup); err != nil {
		return err
	}
	hadTarget := false
	if info, err := os.Lstat(target); err == nil {
		if expectedTarget == nil {
			return unsafeError(errors.New("fixture destination appeared during import"))
		}
		if !sameStableFile(expectedTarget.directory, info) {
			return unsafeError(errors.New("fixture destination changed during import"))
		}
		markerInfo, markerErr := os.Lstat(filepath.Join(target, ManagedMarker))
		if markerErr != nil || markerInfo.Mode()&os.ModeSymlink != 0 || !markerInfo.Mode().IsRegular() || !sameStableFile(expectedTarget.marker, markerInfo) {
			return unsafeError(errors.New("fixture destination marker changed during import"))
		}
		if err := requireManagedDestination(target, info); err != nil {
			return err
		}
		hadTarget = true
		if err := os.Rename(target, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(staging, target); err != nil {
		if hadTarget {
			_ = os.Rename(backup, target)
		}
		return err
	}
	if hadTarget {
		_ = os.RemoveAll(backup)
	}
	return nil
}

func sameStableFile(want, got os.FileInfo) bool {
	return os.SameFile(want, got) && want.Mode() == got.Mode() && want.Size() == got.Size() && want.ModTime().Equal(got.ModTime())
}

func requireManagedDestination(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return unsafeError(errors.New("fixture destination is not a directory"))
	}
	if _, err := readManagedMarker(path); err != nil {
		if isUnsafeMarkerError(err) {
			return unsafeError(errors.New("refusing to replace unmanaged fixture destination"))
		}
		return err
	}
	return nil
}

func readManagedMarker(path string) ([]byte, error) {
	marker, err := readSafe(path, ManagedMarker)
	if err != nil {
		if os.IsNotExist(err) || isUnsafeMarkerPathError(err) {
			return nil, unsafeError(errors.New("fixture managed marker is missing or invalid"))
		}
		return nil, runtimeError(fmt.Errorf("read fixture managed marker: %w", err))
	}
	if !bytes.Equal(marker, []byte(ManagedContent)) {
		return nil, unsafeError(errors.New("fixture managed marker is missing or invalid"))
	}
	return marker, nil
}

func isUnsafeMarkerError(err error) bool {
	var unsafeErr *UnsafeError
	return errors.As(err, &unsafeErr)
}

func isUnsafeMarkerPathError(err error) bool {
	message := err.Error()
	return strings.Contains(message, "symlink path is not allowed") || strings.Contains(message, "path escapes source root") || strings.Contains(message, "path is not a regular file")
}

func compare(path string, want []byte) error {
	got, err := readNoSymlink(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("fixture drift: %s", path)
	}
	return nil
}

func orphanCheck(dest string, c Contract) error {
	allowed := map[string]bool{ManagedMarker: true, ContractPath: true, ManifestPath: true, "expected.yaml": true}
	for _, s := range c.Sources {
		for _, f := range append(sourceFiles(s), artifactFiles(s)...) {
			allowed[filepath.ToSlash(filepath.Join("source", s.Product, f.Path))] = true
		}
	}
	return filepath.Walk(dest, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return runtimeError(fmt.Errorf("walk fixture: %w", err))
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return driftError(fmt.Errorf("fixture symlink: %s", path))
		}
		rel, err := filepath.Rel(dest, path)
		if err != nil {
			return err
		}
		if !allowed[filepath.ToSlash(rel)] {
			return driftError(fmt.Errorf("fixture orphan: %s", rel))
		}
		return nil
	})
}
