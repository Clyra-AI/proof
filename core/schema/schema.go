package schema

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"

	coreerr "github.com/Clyra-AI/proof/core/errors"
)

//go:embed v1/*.json v1/types/*.json
var schemaFS embed.FS

type RecordType struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	SchemaPath  string `json:"schema_path"`
}

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
