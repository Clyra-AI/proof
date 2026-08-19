package schema

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"

	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/Clyra-AI/proof/core/structure"
)

//go:embed v1/*.json v1/types/*.json
var schemaFS embed.FS

type RecordType struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	SchemaPath  string `json:"schema_path"`
}

// RecordTypeDefinition describes one portable custom record type. SchemaPath
// is always relative to the bundle root when the definition comes from a
// record-types.json manifest.
type RecordTypeDefinition struct {
	RecordType    string `json:"record_type"`
	SchemaID      string `json:"schema_id"`
	SchemaVersion string `json:"schema_version"`
	SchemaPath    string `json:"schema_path"`
	SHA256        string `json:"sha256"`
	// Digest is an API-friendly alias for SHA256. It is not emitted as a
	// second manifest field.
	Digest string `json:"-"`
}

func (d RecordTypeDefinition) MarshalJSON() ([]byte, error) {
	type manifestDefinition struct {
		RecordType    string `json:"record_type"`
		SchemaID      string `json:"schema_id"`
		SchemaVersion string `json:"schema_version"`
		SchemaPath    string `json:"schema_path"`
		SHA256        string `json:"sha256"`
	}
	sha := d.SHA256
	if sha == "" {
		sha = d.Digest
	}
	return json.Marshal(manifestDefinition{RecordType: d.RecordType, SchemaID: d.SchemaID, SchemaVersion: d.SchemaVersion, SchemaPath: d.SchemaPath, SHA256: sha})
}

func (d *RecordTypeDefinition) UnmarshalJSON(raw []byte) error {
	type manifestDefinition struct {
		RecordType    string `json:"record_type"`
		SchemaID      string `json:"schema_id"`
		SchemaVersion string `json:"schema_version"`
		SchemaPath    string `json:"schema_path"`
		SHA256        string `json:"sha256"`
	}
	var parsed manifestDefinition
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return err
	}
	d.RecordType = parsed.RecordType
	d.SchemaID = parsed.SchemaID
	d.SchemaVersion = parsed.SchemaVersion
	d.SchemaPath = parsed.SchemaPath
	d.SHA256 = parsed.SHA256
	d.Digest = parsed.SHA256
	return nil
}

// RecordTypeManifest is the portable, versioned custom type registry format.
type RecordTypeManifest struct {
	Version     string                 `json:"version"`
	RecordTypes []RecordTypeDefinition `json:"record_types"`
}

const (
	RecordTypeManifestVersion = "1"
	RecordTypeManifestPath    = "record-types.json"
)

var builtins = []RecordType{
	{Name: "tool_invocation", Description: "An AI agent invoked a tool", SchemaPath: "v1/types/tool-invocation.schema.json"},
	{Name: "dynamic_tool_discovery", Description: "A tool was discovered dynamically at runtime", SchemaPath: "v1/types/dynamic-tool-discovery.schema.json"},
	{Name: "decision", Description: "An AI agent made a decision", SchemaPath: "v1/types/decision.schema.json"},
	{Name: "guardrail_activation", Description: "A guardrail triggered or passed", SchemaPath: "v1/types/guardrail-activation.schema.json"},
	{Name: "permission_check", Description: "A permission was enforced", SchemaPath: "v1/types/permission-check.schema.json"},
	{Name: "human_oversight", Description: "A human reviewed or approved", SchemaPath: "v1/types/human-oversight.schema.json"},
	{Name: "policy_enforcement", Description: "A policy rule was evaluated", SchemaPath: "v1/types/policy-enforcement.schema.json"},
	{Name: "scan_finding", Description: "An AI tool or risk was discovered", SchemaPath: "v1/types/scan-finding.schema.json"},
	{Name: "risk_assessment", Description: "A risk was identified and scored", SchemaPath: "v1/types/risk-assessment.schema.json"},
	{Name: "deployment", Description: "An AI system was deployed or changed", SchemaPath: "v1/types/deployment.schema.json"},
	{Name: "model_change", Description: "A model version or config changed", SchemaPath: "v1/types/model-change.schema.json"},
	{Name: "test_result", Description: "A test or evaluation was run", SchemaPath: "v1/types/test-result.schema.json"},
	{Name: "incident", Description: "An AI-related incident occurred", SchemaPath: "v1/types/incident.schema.json"},
	{Name: "data_pipeline_run", Description: "A data pipeline executed", SchemaPath: "v1/types/data-pipeline-run.schema.json"},
	{Name: "replay_certification", Description: "A replay was run and certified", SchemaPath: "v1/types/replay-certification.schema.json"},
	{Name: "approval", Description: "An approval or delegation was issued", SchemaPath: "v1/types/approval.schema.json"},
	{Name: "delegation", Description: "Authority was delegated from one agent to another", SchemaPath: "v1/types/delegation.schema.json"},
	{Name: "compiled_action", Description: "A compound agent action was compiled for execution", SchemaPath: "v1/types/compiled-action.schema.json"},
}

var customMu sync.RWMutex
var customTypes = map[string]RecordType{}
var customSchemas = map[string]*jsonschema.Schema{}

// Registry scopes custom type definitions to one caller or verification. A
// Registry is safe for concurrent validation and registration; callers should
// generally finish registration before sharing it with verifiers.
type Registry struct {
	mu       sync.RWMutex
	custom   map[string]RecordType
	defs     map[string]RecordTypeDefinition
	compiled map[string]*jsonschema.Schema
}

// NewRegistry creates an empty scoped registry containing only built-ins.
func NewRegistry() *Registry {
	return &Registry{
		custom:   make(map[string]RecordType),
		defs:     make(map[string]RecordTypeDefinition),
		compiled: make(map[string]*jsonschema.Schema),
	}
}

// NewScopedRegistry is an explicit alias for NewRegistry.
func NewScopedRegistry() *Registry { return NewRegistry() }

// Register adds a portable custom definition and its schema bytes to this
// registry. Registration is additive: built-ins cannot be replaced and an
// existing name cannot be rebound to a different definition or digest.
func (r *Registry) Register(def RecordTypeDefinition, data []byte) error {
	if r == nil {
		return coreerr.New(coreerr.KindInvalidInput, "schema.registry_nil", "schema registry is nil")
	}
	def.RecordType = strings.TrimSpace(def.RecordType)
	def.SchemaID = strings.TrimSpace(def.SchemaID)
	def.SchemaVersion = strings.TrimSpace(def.SchemaVersion)
	def.SchemaPath = strings.TrimSpace(def.SchemaPath)
	if def.SHA256 == "" {
		def.SHA256 = def.Digest
	}
	if err := validateDefinition(def); err != nil {
		return err
	}
	if _, ok := schemaPathForType(def.RecordType); ok {
		return coreerr.New(coreerr.KindValidation, "schema.custom.record_type_conflicts_builtin", fmt.Sprintf("record type %s conflicts with built-in type", def.RecordType), coreerr.WithField("record_type"))
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	want := normalizeSHA256(def.SHA256)
	if want == "" || want != digest {
		return coreerr.New(coreerr.KindVerification, "schema.custom.digest_mismatch", fmt.Sprintf("schema digest mismatch for %s", def.SchemaPath), coreerr.WithPath(def.SchemaPath))
	}
	def.SHA256 = digest
	def.Digest = digest
	compiled, err := compileSchema(def.SchemaPath, data)
	if err != nil {
		return coreerr.Wrap(coreerr.KindValidation, "schema.custom.compile_failed", fmt.Sprintf("compile custom schema %s", filepath.Base(def.SchemaPath)), err, coreerr.WithPath(def.SchemaPath))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.defs[def.RecordType]; ok {
		if existing.SchemaID != def.SchemaID || existing.SchemaVersion != def.SchemaVersion || existing.SchemaPath != def.SchemaPath || normalizeSHA256(existing.SHA256) != digest {
			return coreerr.New(coreerr.KindValidation, "schema.custom.conflicting_definition", fmt.Sprintf("conflicting definition for record type %s", def.RecordType), coreerr.WithField("record_type"))
		}
		return nil
	}
	r.defs[def.RecordType] = def
	r.custom[def.RecordType] = RecordType{Name: def.RecordType, Description: "Custom record type", SchemaPath: def.SchemaPath}
	r.compiled[def.RecordType] = compiled
	return nil
}

// RegisterCustomType is a convenient scoped API. The supported form is
// RegisterCustomType(recordType, schemaID, schemaVersion, schemaPath, data).
func (r *Registry) RegisterCustomType(recordType, schemaID, schemaVersion, schemaPath string, data []byte) error {
	sum := sha256.Sum256(data)
	return r.Register(RecordTypeDefinition{RecordType: recordType, SchemaID: schemaID, SchemaVersion: schemaVersion, SchemaPath: schemaPath, SHA256: hex.EncodeToString(sum[:])}, data)
}

// RegisterSchema registers a schema from a portable definition. It is an
// alias useful to callers that prefer schema-oriented terminology.
func (r *Registry) RegisterSchema(def RecordTypeDefinition, data []byte) error {
	return r.Register(def, data)
}

// RegisterFile registers a definition by reading its already validated local
// schema path. Portable bundle verification uses explicit bytes instead so it
// can bind reads to the outer bundle manifest.
func (r *Registry) RegisterFile(def RecordTypeDefinition) error {
	if _, err := structure.ValidatePath(def.SchemaPath); err != nil {
		return err
	}
	// #nosec G304 -- callers explicitly opt into loading this safe relative path.
	data, err := os.ReadFile(def.SchemaPath)
	if err != nil {
		return err
	}
	if def.SHA256 == "" && def.Digest == "" {
		sum := sha256.Sum256(data)
		def.SHA256 = hex.EncodeToString(sum[:])
	}
	return r.Register(def, data)
}

// RegisterCustomTypeSchema is a scoped file-based convenience API.
func (r *Registry) RegisterCustomTypeSchema(recordType, schemaID, schemaVersion, schemaPath string) error {
	return r.RegisterFile(RecordTypeDefinition{RecordType: recordType, SchemaID: schemaID, SchemaVersion: schemaVersion, SchemaPath: schemaPath})
}

// ValidateRecord validates a record against the base and scoped type schema.
func (r *Registry) ValidateRecord(data []byte, recordType string) error {
	if r == nil {
		return coreerr.New(coreerr.KindInvalidInput, "schema.registry_nil", "schema registry is nil")
	}
	if err := validateWithSchema(data, "v1/proof-record-v1.schema.json"); err != nil {
		return coreerr.Wrap(wrappedKind(err, coreerr.KindValidation), "schema.record.base_validation_failed", "record schema validation failed", err, coreerr.WithPath("v1/proof-record-v1.schema.json"))
	}
	path, ok := schemaPathForType(recordType)
	if ok {
		if err := validateWithSchema(data, path); err != nil {
			return coreerr.Wrap(wrappedKind(err, coreerr.KindValidation), "schema.record.type_validation_failed", "record type schema validation failed", err, coreerr.WithPath(path))
		}
		return nil
	}
	r.mu.RLock()
	compiled, customOK := r.compiled[recordType]
	r.mu.RUnlock()
	if !customOK {
		return coreerr.New(coreerr.KindValidation, "schema.record.unknown_record_type", fmt.Sprintf("unknown record type: %s", recordType), coreerr.WithField("record_type"))
	}
	if err := validateWithCompiledSchema(data, compiled); err != nil {
		return coreerr.Wrap(wrappedKind(err, coreerr.KindValidation), "schema.record.custom_type_validation_failed", "custom record type schema validation failed", err, coreerr.WithField("record_type"))
	}
	return nil
}

// ListRecordTypes returns built-ins and this registry's custom definitions.
func (r *Registry) ListRecordTypes() []RecordType {
	out := make([]RecordType, len(builtins))
	copy(out, builtins)
	if r != nil {
		r.mu.RLock()
		for _, rt := range r.custom {
			out = append(out, rt)
		}
		r.mu.RUnlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Definitions returns a deterministic copy of portable custom definitions.
func (r *Registry) Definitions() []RecordTypeDefinition {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]RecordTypeDefinition, 0, len(r.defs))
	for _, def := range r.defs {
		out = append(out, def)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].RecordType < out[j].RecordType })
	return out
}

// Manifest returns a deterministic portable manifest for the custom entries.
func (r *Registry) Manifest() RecordTypeManifest {
	return RecordTypeManifest{Version: RecordTypeManifestVersion, RecordTypes: r.Definitions()}
}

// ParseRecordTypeManifest validates and parses a record-types.json document.
func ParseRecordTypeManifest(raw []byte) (RecordTypeManifest, error) {
	if err := ValidateAgainstSchema(raw, "v1/record-types-v1.schema.json"); err != nil {
		return RecordTypeManifest{}, coreerr.Wrap(coreerr.KindValidation, "schema.custom.manifest_invalid", "record type manifest validation failed", err, coreerr.WithPath(RecordTypeManifestPath))
	}
	var manifest RecordTypeManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return RecordTypeManifest{}, coreerr.Wrap(coreerr.KindInvalidInput, "schema.custom.manifest_invalid_json", "parse record type manifest", err, coreerr.WithPath(RecordTypeManifestPath))
	}
	return manifest, nil
}

// LoadRecordTypeManifest builds a scoped registry from manifest bytes and
// schema bytes keyed by their canonical safe manifest paths. It performs no
// process-global registration.
func LoadRecordTypeManifest(raw []byte, schemaFiles map[string][]byte) (*Registry, error) {
	manifest, err := ParseRecordTypeManifest(raw)
	if err != nil {
		return nil, err
	}
	registry := NewRegistry()
	seen := make(map[string]struct{}, len(manifest.RecordTypes))
	for _, def := range manifest.RecordTypes {
		if _, ok := seen[def.RecordType]; ok {
			return nil, coreerr.New(coreerr.KindValidation, "schema.custom.conflicting_definition", fmt.Sprintf("duplicate definition for record type %s", def.RecordType), coreerr.WithField("record_type"))
		}
		seen[def.RecordType] = struct{}{}
		key, err := structure.ValidatePath(def.SchemaPath)
		if err != nil {
			return nil, err
		}
		data, ok := schemaFiles[def.SchemaPath]
		if !ok {
			data, ok = schemaFiles[key]
		}
		if !ok {
			return nil, coreerr.New(coreerr.KindVerification, "schema.custom.schema_missing", fmt.Sprintf("schema file is missing: %s", def.SchemaPath), coreerr.WithPath(def.SchemaPath))
		}
		if err := registry.Register(def, data); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// LoadRecordTypeManifestFile loads a portable manifest from a local root.
// Callers performing strict bundle verification should additionally enforce
// manifest membership before invoking this helper.
func LoadRecordTypeManifestFile(root, manifestPath string) (*Registry, error) {
	key, err := structure.ValidatePath(manifestPath)
	if err != nil {
		return nil, err
	}
	if key != RecordTypeManifestPath {
		return nil, coreerr.New(coreerr.KindValidation, "schema.custom.manifest_path_invalid", "record type manifest must be record-types.json", coreerr.WithPath(manifestPath))
	}
	// #nosec G304 -- caller provides an explicit local bundle root and a path validated above.
	raw, err := os.ReadFile(filepath.Join(root, manifestPath))
	if err != nil {
		return nil, err
	}
	manifest, err := ParseRecordTypeManifest(raw)
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(manifest.RecordTypes))
	for _, def := range manifest.RecordTypes {
		if _, err := structure.ValidatePath(def.SchemaPath); err != nil {
			return nil, err
		}
		// #nosec G304 -- schema path was validated as a safe relative path.
		data, err := os.ReadFile(filepath.Join(root, def.SchemaPath))
		if err != nil {
			return nil, err
		}
		files[def.SchemaPath] = data
	}
	return LoadRecordTypeManifest(raw, files)
}

func ListRecordTypes() []RecordType {
	out := make([]RecordType, len(builtins))
	copy(out, builtins)
	customMu.RLock()
	for _, rt := range customTypes {
		out = append(out, rt)
	}
	customMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func ValidateRecord(data []byte, recordType string) error {
	if err := validateWithSchema(data, "v1/proof-record-v1.schema.json"); err != nil {
		return coreerr.Wrap(
			wrappedKind(err, coreerr.KindValidation),
			"schema.record.base_validation_failed",
			"record schema validation failed",
			err,
			coreerr.WithPath("v1/proof-record-v1.schema.json"),
		)
	}
	path, ok := schemaPathForType(recordType)
	if !ok {
		customMu.RLock()
		customSchema, customOK := customSchemas[recordType]
		customMu.RUnlock()
		if !customOK {
			return coreerr.New(
				coreerr.KindValidation,
				"schema.record.unknown_record_type",
				fmt.Sprintf("unknown record type: %s", recordType),
				coreerr.WithField("record_type"),
			)
		}
		if err := validateWithCompiledSchema(data, customSchema); err != nil {
			return coreerr.Wrap(
				wrappedKind(err, coreerr.KindValidation),
				"schema.record.custom_type_validation_failed",
				"custom record type schema validation failed",
				err,
				coreerr.WithField("record_type"),
			)
		}
		return nil
	}
	if err := validateWithSchema(data, path); err != nil {
		return coreerr.Wrap(
			wrappedKind(err, coreerr.KindValidation),
			"schema.record.type_validation_failed",
			"record type schema validation failed",
			err,
			coreerr.WithPath(path),
		)
	}
	return nil
}

// ValidateRecordWithRegistry is the scoped counterpart to ValidateRecord.
// It never consults or mutates the legacy process-global registry.
func ValidateRecordWithRegistry(registry *Registry, data []byte, recordType string) error {
	if registry == nil {
		return ValidateRecord(data, recordType)
	}
	return registry.ValidateRecord(data, recordType)
}

func ValidateCustomSchema(schemaPath string, data []byte) error {
	_, err := compileSchema("custom.json", data)
	if err != nil {
		return coreerr.Wrap(
			coreerr.KindValidation,
			"schema.custom.compile_failed",
			fmt.Sprintf("compile custom schema %s", filepath.Base(schemaPath)),
			err,
			coreerr.WithPath(schemaPath),
		)
	}
	return nil
}

func RegisterCustomType(recordType string, schemaPath string, data []byte) error {
	recordType = strings.TrimSpace(recordType)
	if recordType == "" {
		return coreerr.New(
			coreerr.KindInvalidInput,
			"schema.custom.record_type_required",
			"record type is required",
			coreerr.WithField("record_type"),
		)
	}
	if _, ok := schemaPathForType(recordType); ok {
		return coreerr.New(
			coreerr.KindValidation,
			"schema.custom.record_type_conflicts_builtin",
			fmt.Sprintf("record type %s conflicts with built-in type", recordType),
			coreerr.WithField("record_type"),
		)
	}
	s, err := compileSchema("custom.json", data)
	if err != nil {
		return coreerr.Wrap(
			coreerr.KindValidation,
			"schema.custom.compile_failed",
			fmt.Sprintf("compile custom schema %s", filepath.Base(schemaPath)),
			err,
			coreerr.WithPath(schemaPath),
		)
	}
	customMu.Lock()
	customTypes[recordType] = RecordType{
		Name:        recordType,
		Description: "Custom record type",
		SchemaPath:  schemaPath,
	}
	customSchemas[recordType] = s
	customMu.Unlock()
	return nil
}

func ResetCustomTypes() {
	customMu.Lock()
	customTypes = map[string]RecordType{}
	customSchemas = map[string]*jsonschema.Schema{}
	customMu.Unlock()
}

func ValidateAgainstSchema(data []byte, schemaPath string) error {
	return validateWithSchema(data, schemaPath)
}

func validateWithSchema(data []byte, schemaPath string) error {
	raw, err := schemaFS.ReadFile(schemaPath)
	if err != nil {
		return coreerr.Wrap(coreerr.KindInternal, "schema.read_embedded_schema_failed", "read embedded schema", err, coreerr.WithPath(schemaPath))
	}
	s, err := compileSchema("schema.json", raw)
	if err != nil {
		return err
	}
	return validateWithCompiledSchema(data, s)
}

func validateWithCompiledSchema(data []byte, s *jsonschema.Schema) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return coreerr.Wrap(coreerr.KindInvalidInput, "schema.invalid_json", "parse json", err)
	}
	if err := s.Validate(v); err != nil {
		return coreerr.Wrap(coreerr.KindValidation, "schema.validation_failed", "schema validation failed", err)
	}
	return nil
}

func compileSchema(name string, raw []byte) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(name, strings.NewReader(string(raw))); err != nil {
		return nil, coreerr.Wrap(coreerr.KindValidation, "schema.compile_resource_failed", "compile schema resource", err)
	}
	compiled, err := compiler.Compile(name)
	if err != nil {
		return nil, coreerr.Wrap(coreerr.KindValidation, "schema.compile_failed", "compile schema", err)
	}
	return compiled, nil
}

func validateDefinition(def RecordTypeDefinition) error {
	if def.RecordType == "" {
		return coreerr.New(coreerr.KindInvalidInput, "schema.custom.record_type_required", "record type is required", coreerr.WithField("record_type"))
	}
	if def.SchemaID == "" {
		return coreerr.New(coreerr.KindInvalidInput, "schema.custom.schema_id_required", "schema id is required", coreerr.WithField("schema_id"))
	}
	if def.SchemaVersion == "" {
		return coreerr.New(coreerr.KindInvalidInput, "schema.custom.schema_version_required", "schema version is required", coreerr.WithField("schema_version"))
	}
	key, err := structure.ValidatePath(def.SchemaPath)
	if err != nil {
		return coreerr.Wrap(coreerr.KindValidation, "schema.custom.schema_path_invalid", "custom schema path is unsafe", err, coreerr.WithPath(def.SchemaPath))
	}
	if key == "manifest.json" || key == RecordTypeManifestPath {
		return coreerr.New(coreerr.KindValidation, "schema.custom.schema_path_invalid", "custom schema path is reserved for bundle metadata", coreerr.WithPath(def.SchemaPath))
	}
	if normalizeSHA256(def.SHA256) == "" {
		return coreerr.New(coreerr.KindValidation, "schema.custom.digest_invalid", "schema digest must be a SHA-256 hex digest", coreerr.WithField("sha256"))
	}
	return nil
}

func normalizeSHA256(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "sha256:")
	if len(value) != sha256.Size*2 {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	return value
}

func wrappedKind(err error, fallback coreerr.Kind) coreerr.Kind {
	if typed, ok := coreerr.As(err); ok {
		return typed.Kind
	}
	return fallback
}

func schemaPathForType(recordType string) (string, bool) {
	for _, rt := range builtins {
		if rt.Name == recordType {
			return rt.SchemaPath, true
		}
	}
	return "", false
}
