package proof

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Clyra-AI/proof/core/bundle"
	"github.com/Clyra-AI/proof/core/canon"
	"github.com/Clyra-AI/proof/core/chain"
	"github.com/Clyra-AI/proof/core/framework"
	"github.com/Clyra-AI/proof/core/record"
	"github.com/Clyra-AI/proof/core/schema"
	"github.com/Clyra-AI/proof/core/signing"
	"github.com/Clyra-AI/proof/core/structure"
)

type Record = record.Record
type RecordOpts = record.RecordOpts
type Controls = record.Controls
type Integrity = record.Integrity
type Relationship = record.Relationship
type Relations = record.Relations
type RelationshipRef = record.RelationshipRef
type RelationshipEdge = record.RelationshipEdge
type ControlContainmentTelemetryProfile = record.ControlContainmentTelemetryProfile
type ControlContainmentTelemetry = record.ControlContainmentTelemetry
type ControlContainmentTelemetryRef = record.ControlContainmentTelemetryRef
type CorrelationRef = record.CorrelationRef
type RedactionMetadata = record.RedactionMetadata
type AgentChainHop = record.AgentChainHop
type PolicyRef = record.PolicyRef
type AgentLineageHop = record.AgentLineageHop
type Chain = chain.Chain
type ChainVerification = chain.Verification
type ChainVerifyOpts = chain.VerifyOpts
type SigningKey = signing.SigningKey
type PublicKey = signing.PublicKey
type Signature = signing.Signature
type RevocationList = signing.RevocationList
type RevocationEntry = signing.RevocationEntry
type CosignVerifyOpts = signing.CosignVerifyOpts
type Framework = framework.Framework
type FrameworkCoverage = framework.Coverage
type FrameworkControlCoverage = framework.ControlCoverage
type FrameworkEvidenceSetCoverage = framework.EvidenceSetCoverage
type RecordType = schema.RecordType
type RecordTypeDefinition = schema.RecordTypeDefinition
type RecordTypeManifest = schema.RecordTypeManifest
type SchemaRegistry = schema.Registry
type Registry = schema.Registry
type CanonDomain = canon.Domain
type Digest = canon.Digest
type BundleManifestEntry = bundle.ManifestEntry
type BundleManifest = bundle.Manifest
type BundleVerifyOpts = bundle.VerifyOpts

const (
	RecordTypeManifestVersion = schema.RecordTypeManifestVersion
	RecordTypeManifestPath    = schema.RecordTypeManifestPath

	DomainJSON   = canon.DomainJSON
	DomainSQL    = canon.DomainSQL
	DomainURL    = canon.DomainURL
	DomainText   = canon.DomainText
	DomainPrompt = canon.DomainPrompt
)

const (
	ControlContainmentTelemetryProfileVersion = record.ControlContainmentTelemetryProfileVersion
	BindingModeIdentifierOnly                 = record.BindingModeIdentifierOnly
	BindingModeDigestBound                    = record.BindingModeDigestBound
)

const (
	ErrorCodeRelationshipRefIDRequired    = record.ErrorCodeRelationshipRefIDRequired
	ErrorCodeRelationshipRefKindInvalid   = record.ErrorCodeRelationshipRefKindInvalid
	ErrorCodeRelationshipRefDigestInvalid = record.ErrorCodeRelationshipRefDigestInvalid
	ErrorCodeRelationshipEdgeKindInvalid  = record.ErrorCodeRelationshipEdgeKindInvalid
	ErrorCodeChainRecordCountMismatch     = chain.ErrorCodeRecordCountMismatch
	ErrorCodeChainHeadHashMismatch        = chain.ErrorCodeHeadHashMismatch
	ErrorCodeStructurePathInvalid         = structure.ErrorCodePathInvalid
	ErrorCodeStructurePathAmbiguous       = structure.ErrorCodePathAmbiguous
	ErrorCodeStructurePathDuplicate       = structure.ErrorCodePathDuplicate
	ErrorCodeStructureUnlistedFile        = structure.ErrorCodeUnlistedFile
	ErrorCodeStructureSymlinkAmbiguous    = structure.ErrorCodeSymlinkAmbiguous
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

func VerifyChainWithOptions(c *Chain, opts ChainVerifyOpts) (*ChainVerification, error) {
	return chain.VerifyWithOptions(c, opts)
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

// EvaluateFrameworkCoverage reports deterministic evidence-path coverage only.
// Deprecated: callers must not treat this helper as a compliance decision or
// regulatory applicability engine; use product-owned compliance evaluation for
// those semantics while this compatibility API remains available.
func EvaluateFrameworkCoverage(f *Framework, records []Record) (*FrameworkCoverage, error) {
	return framework.EvaluateCoverage(f, records)
}

func ListRecordTypes() []RecordType {
	return schema.ListRecordTypes()
}

func ValidateRecord(r *Record) error {
	return ValidateRecordWithRegistry(nil, r)
}

// ValidateRecordWithRegistry validates using a caller-owned scoped registry.
// A nil registry preserves the legacy process-global custom type behavior.
func ValidateRecordWithRegistry(registry *SchemaRegistry, r *Record) error {
	if err := record.Validate(r); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return schema.ValidateRecordWithRegistry(registry, raw, r.RecordType)
}

func NewSchemaRegistry() *SchemaRegistry { return schema.NewRegistry() }

func NewRegistry() *Registry { return schema.NewRegistry() }

func ParseRecordTypeManifest(raw []byte) (RecordTypeManifest, error) {
	return schema.ParseRecordTypeManifest(raw)
}

func LoadRecordTypeManifest(raw []byte, schemaFiles map[string][]byte) (*SchemaRegistry, error) {
	return schema.LoadRecordTypeManifest(raw, schemaFiles)
}

func LoadRecordTypeManifestWithResources(raw []byte, schemaFiles map[string][]byte) (*SchemaRegistry, error) {
	return schema.LoadRecordTypeManifestWithResources(raw, schemaFiles)
}

func ValidateControlContainmentTelemetryProfile(p *ControlContainmentTelemetryProfile) error {
	return record.ValidateControlContainmentTelemetryProfile(p)
}

func ValidateControlContainmentTelemetry(p *ControlContainmentTelemetryProfile) error {
	return record.ValidateControlContainmentTelemetry(p)
}

func CanonicalizeControlContainmentTelemetry(p *ControlContainmentTelemetryProfile) ([]byte, error) {
	return record.CanonicalizeControlContainmentTelemetry(p)
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

func VerifyChainRangeWithOptions(c *Chain, from, to time.Time, opts ChainVerifyOpts) (*ChainVerification, error) {
	return chain.VerifyRangeWithOptions(c, from, to, opts)
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

func ReadAndValidateRecord(path string) (*Record, error) {
	r, err := ReadRecord(path)
	if err != nil {
		return nil, err
	}
	if err := ValidateRecord(r); err != nil {
		return nil, err
	}
	return r, nil
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
	return bundle.Verify(path, opts)
}

func SignBundleManifest(manifest BundleManifest, key SigningKey) (*BundleManifest, error) {
	signed, err := bundle.SignManifest(manifest, key)
	if err != nil {
		return nil, err
	}
	return &signed, nil
}

func SignBundleManifestCosign(manifest BundleManifest, keyPath string) (*BundleManifest, error) {
	signed, err := bundle.SignManifestCosign(manifest, keyPath)
	if err != nil {
		return nil, err
	}
	return &signed, nil
}

func SignBundleFile(path string, key SigningKey) (*BundleManifest, error) {
	return bundle.SignFile(path, key)
}

func SignBundleCosignFile(path string, keyPath string) (*BundleManifest, error) {
	return bundle.SignFileCosign(path, keyPath)
}

// Deprecated: SignBundle mutates <path>/manifest.json.
// Use SignBundleManifest for pure signing or SignBundleFile for explicit file mutation.
func SignBundle(path string, key SigningKey) (*BundleManifest, error) {
	return SignBundleFile(path, key)
}

// Deprecated: SignBundleCosign mutates <path>/manifest.json.
// Use SignBundleManifestCosign for pure signing or SignBundleCosignFile for explicit file mutation.
func SignBundleCosign(path string, keyPath string) (*BundleManifest, error) {
	return SignBundleCosignFile(path, keyPath)
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
