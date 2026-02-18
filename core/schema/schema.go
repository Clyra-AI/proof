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
		return err
	}
	path, ok := schemaPathForType(recordType)
	if !ok {
		customMu.RLock()
		customSchema, customOK := customSchemas[recordType]
		customMu.RUnlock()
		if !customOK {
			return fmt.Errorf("unknown record type: %s", recordType)
		}
		return validateWithCompiledSchema(data, customSchema)
	}
	return validateWithSchema(data, path)
}

func ValidateCustomSchema(schemaPath string, data []byte) error {
	_, err := compileSchema("custom.json", data)
	if err != nil {
		return fmt.Errorf("compile custom schema %s: %w", filepath.Base(schemaPath), err)
	}
	return nil
}

func RegisterCustomType(recordType string, schemaPath string, data []byte) error {
	recordType = strings.TrimSpace(recordType)
	if recordType == "" {
		return fmt.Errorf("record type is required")
	}
	if _, ok := schemaPathForType(recordType); ok {
		return fmt.Errorf("record type %s conflicts with built-in type", recordType)
	}
	s, err := compileSchema("custom.json", data)
	if err != nil {
		return fmt.Errorf("compile custom schema %s: %w", filepath.Base(schemaPath), err)
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
		return err
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
		return err
	}
	return s.Validate(v)
}

func compileSchema(name string, raw []byte) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(name, strings.NewReader(string(raw))); err != nil {
		return nil, err
	}
	return compiler.Compile(name)
}

func schemaPathForType(recordType string) (string, bool) {
	for _, rt := range builtins {
		if rt.Name == recordType {
			return rt.SchemaPath, true
		}
	}
	return "", false
}
