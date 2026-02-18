package schema

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

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

func ListRecordTypes() []RecordType {
	out := make([]RecordType, len(builtins))
	copy(out, builtins)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func ValidateRecord(data []byte, recordType string) error {
	if err := validateWithSchema(data, "v1/proof-record-v1.schema.json"); err != nil {
		return err
	}
	path, ok := schemaPathForType(recordType)
	if !ok {
		return fmt.Errorf("unknown record type: %s", recordType)
	}
	return validateWithSchema(data, path)
}

func ValidateCustomSchema(schemaPath string, data []byte) error {
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("custom.json", strings.NewReader(string(data))); err != nil {
		return err
	}
	_, err := compiler.Compile("custom.json")
	if err != nil {
		return fmt.Errorf("compile custom schema %s: %w", filepath.Base(schemaPath), err)
	}
	return nil
}

func ValidateAgainstSchema(data []byte, schemaPath string) error {
	return validateWithSchema(data, schemaPath)
}

func validateWithSchema(data []byte, schemaPath string) error {
	raw, err := schemaFS.ReadFile(schemaPath)
	if err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("schema.json", strings.NewReader(string(raw))); err != nil {
		return err
	}
	s, err := compiler.Compile("schema.json")
	if err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	return s.Validate(v)
}

func schemaPathForType(recordType string) (string, bool) {
	for _, rt := range builtins {
		if rt.Name == recordType {
			return rt.SchemaPath, true
		}
	}
	return "", false
}
