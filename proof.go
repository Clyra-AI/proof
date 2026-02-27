package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Clyra-AI/proof/core/canon"
	"github.com/Clyra-AI/proof/core/chain"
	"github.com/Clyra-AI/proof/core/framework"
	"github.com/Clyra-AI/proof/core/record"
	"github.com/Clyra-AI/proof/core/schema"
	"github.com/Clyra-AI/proof/core/signing"
)

type Record = record.Record
type RecordOpts = record.RecordOpts
type Controls = record.Controls
type Relationship = record.Relationship
type Relations = record.Relations
type RelationshipRef = record.RelationshipRef
type RelationshipEdge = record.RelationshipEdge
type AgentChainHop = record.AgentChainHop
type PolicyRef = record.PolicyRef
type AgentLineageHop = record.AgentLineageHop
type Chain = chain.Chain
type ChainVerification = chain.Verification
type SigningKey = signing.SigningKey
type PublicKey = signing.PublicKey
type Signature = signing.Signature
type RevocationList = signing.RevocationList
type RevocationEntry = signing.RevocationEntry
type CosignVerifyOpts = signing.CosignVerifyOpts
type Framework = framework.Framework
type RecordType = schema.RecordType
type CanonDomain = canon.Domain
type Digest = canon.Digest

type BundleManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type BundleManifest struct {
	Files      []BundleManifestEntry `json:"files"`
	AlgoID     string                `json:"algo_id,omitempty"`
	SaltID     string                `json:"salt_id,omitempty"`
	Signatures []Signature           `json:"signatures,omitempty"`
}

type BundleVerifyOpts struct {
	VerifySignatures bool
	PublicKey        PublicKey
	Cosign           CosignVerifyOpts
}

const (
	DomainJSON   = canon.DomainJSON
	DomainSQL    = canon.DomainSQL
	DomainURL    = canon.DomainURL
	DomainText   = canon.DomainText
	DomainPrompt = canon.DomainPrompt
)

func NewRecord(opts RecordOpts) (*Record, error) {
	r, err := record.New(opts)
	if err != nil {
		return nil, err
	}
	if err := ValidateRecord(r); err != nil {
		return nil, err
	}
	return r, nil
}

func Sign(r *Record, key SigningKey) (*Record, error) {
	return signing.Sign(r, key)
}

func Verify(r *Record, publicKey PublicKey) error {
	return signing.Verify(r, publicKey)
}

func AppendToChain(c *Chain, r *Record) error {
	return chain.Append(c, r)
}

func VerifyChain(c *Chain) (*ChainVerification, error) {
	return chain.Verify(c)
}

func Canonicalize(input []byte, domain CanonDomain) ([]byte, error) {
	return canon.Canonicalize(input, domain)
}

func DigestValue(input []byte, domain CanonDomain, saltID string) (Digest, error) {
	return canon.DigestInfo(input, domain, saltID)
}

func DigestHMACValue(input []byte, domain CanonDomain, secret []byte, saltID string) (Digest, error) {
	return canon.DigestHMACInfo(input, domain, secret, saltID)
}

func LoadFramework(pathOrID string) (*Framework, error) {
	return framework.Load(pathOrID)
}

func ListRecordTypes() []RecordType {
	return schema.ListRecordTypes()
}

func ValidateRecord(r *Record) error {
	if err := record.Validate(r); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return schema.ValidateRecord(raw, r.RecordType)
}

func ComputeRecordHash(r *Record) (string, error) {
	return record.ComputeHash(r)
}

func NewChain(id string) *Chain {
	return chain.New(id, time.Now().UTC())
}

func VerifyChainRange(c *Chain, from, to time.Time) (*ChainVerification, error) {
	return chain.VerifyRange(c, from, to)
}

func GenerateSigningKey() (SigningKey, error) {
	return signing.GenerateKey()
}

func WriteRecord(path string, r *Record) error {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	// #nosec G306 -- proof artifacts are intentionally shareable within local workspace.
	return os.WriteFile(path, raw, 0o644)
}

func ReadRecord(path string) (*Record, error) {
	// #nosec G304 -- library API reads explicit caller-provided artifact paths.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func ValidateCustomTypeSchema(schemaPath string) error {
	// #nosec G304 -- schema path is explicit user input for validation.
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		return err
	}
	if err := schema.ValidateCustomSchema(schemaPath, raw); err != nil {
		return fmt.Errorf("invalid schema: %w", err)
	}
	return nil
}

func RegisterCustomType(recordType string, schemaJSON []byte) error {
	return schema.RegisterCustomType(recordType, "<inline>", schemaJSON)
}

func RegisterCustomTypeSchema(recordType, schemaPath string) error {
	// #nosec G304 -- schema path is explicit user input for validation.
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		return err
	}
	return schema.RegisterCustomType(recordType, schemaPath, raw)
}

func ResetCustomTypes() {
	schema.ResetCustomTypes()
}

func SignChain(c *Chain, key SigningKey) (Signature, error) {
	if c == nil {
		return Signature{}, fmt.Errorf("chain is nil")
	}
	digest, err := chainDigest(c)
	if err != nil {
		return Signature{}, err
	}
	sig, err := signing.SignDigest(digest, key)
	if err != nil {
		return Signature{}, err
	}
	c.Signatures = append(c.Signatures, sig)
	return sig, nil
}

func VerifyChainSignature(c *Chain, sig Signature, pub PublicKey) error {
	if c == nil {
		return fmt.Errorf("chain is nil")
	}
	digest, err := chainDigest(c)
	if err != nil {
		return err
	}
	return signing.VerifyDigest(sig, digest, pub)
}

func SignRevocationList(list RevocationList, key SigningKey) (RevocationList, error) {
	return signing.SignRevocationList(list, key)
}

func VerifyRevocationList(list RevocationList, pub PublicKey) error {
	return signing.VerifyRevocationList(list, pub)
}

func IsKeyRevoked(list RevocationList, keyID string, at time.Time) bool {
	return signing.IsRevoked(list, keyID, at)
}

func SignCosign(r *Record, keyPath string) (*Record, error) {
	return signing.SignRecordCosign(r, keyPath)
}

func VerifyCosign(r *Record, keyPath string) error {
	return signing.VerifyRecordCosign(r, signing.CosignVerifyOpts{KeyPath: keyPath})
}

func VerifyCosignWithOptions(r *Record, opts CosignVerifyOpts) error {
	return signing.VerifyRecordCosign(r, opts)
}

func IsDependencyMissing(err error) bool {
	return signing.IsDependencyMissing(err)
}

func VerifyBundle(path string, opts BundleVerifyOpts) (*BundleManifest, error) {
	manifestPath := filepath.Join(path, "manifest.json")
	// #nosec G304 -- caller provides explicit local artifact path.
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var manifest BundleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	algoID := strings.ToLower(strings.TrimSpace(manifest.AlgoID))
	if algoID == "" {
		algoID = "sha256"
		manifest.AlgoID = algoID
	}
	if algoID != "sha256" {
		return nil, fmt.Errorf("unsupported bundle digest algorithm: %s", manifest.AlgoID)
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if err := schema.ValidateAgainstSchema(manifestRaw, "v1/bundle-manifest-v1.schema.json"); err != nil {
		return nil, fmt.Errorf("bundle manifest schema validation failed: %w", err)
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
			return nil, fmt.Errorf("bundle hash mismatch for %s", file.Path)
		}
	}
	if opts.VerifySignatures {
		if len(manifest.Signatures) == 0 {
			return nil, fmt.Errorf("bundle manifest has no signatures")
		}
		digest, err := bundleManifestDigest(manifest)
		if err != nil {
			return nil, err
		}
		for _, sig := range manifest.Signatures {
			switch strings.ToLower(strings.TrimSpace(sig.Alg)) {
			case "ed25519":
				if len(opts.PublicKey.Public) == 0 {
					return nil, fmt.Errorf("public key is required for bundle signature verification")
				}
				if err := signing.VerifyDigest(sig, digest, opts.PublicKey); err != nil {
					return nil, err
				}
			case "cosign":
				if err := signing.VerifyDigestCosign(sig, digest, opts.Cosign); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("unsupported bundle signature algorithm: %s", sig.Alg)
			}
		}
	}
	return &manifest, nil
}

func SignBundle(path string, key SigningKey) (*BundleManifest, error) {
	manifestPath := filepath.Join(path, "manifest.json")
	// #nosec G304 -- caller provides explicit local artifact path.
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var manifest BundleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	if strings.TrimSpace(manifest.AlgoID) == "" {
		manifest.AlgoID = "sha256"
	}
	digest, err := bundleManifestDigest(manifest)
	if err != nil {
		return nil, err
	}
	sig, err := signing.SignDigest(digest, key)
	if err != nil {
		return nil, err
	}
	manifest.Signatures = append(manifest.Signatures, sig)
	out, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	// #nosec G306 -- bundle manifests are workspace artifacts.
	if err := os.WriteFile(manifestPath, out, 0o644); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func SignBundleCosign(path string, keyPath string) (*BundleManifest, error) {
	manifestPath := filepath.Join(path, "manifest.json")
	// #nosec G304 -- caller provides explicit local artifact path.
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var manifest BundleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	if strings.TrimSpace(manifest.AlgoID) == "" {
		manifest.AlgoID = "sha256"
	}
	digest, err := bundleManifestDigest(manifest)
	if err != nil {
		return nil, err
	}
	sig, err := signing.SignDigestCosign(digest, keyPath)
	if err != nil {
		return nil, err
	}
	manifest.Signatures = append(manifest.Signatures, sig)
	out, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	// #nosec G306 -- bundle manifests are workspace artifacts.
	if err := os.WriteFile(manifestPath, out, 0o644); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func chainDigest(c *Chain) (string, error) {
	payload := map[string]any{
		"chain_id":     c.ChainID,
		"created_at":   c.CreatedAt.UTC().Format(time.RFC3339),
		"record_count": c.RecordCount,
		"head_hash":    c.HeadHash,
		"records":      c.Records,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return canon.DigestHex(raw, canon.DomainJSON)
}

func bundleManifestDigest(manifest BundleManifest) (string, error) {
	m := manifest
	m.Signatures = nil
	raw, err := json.Marshal(m)
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
