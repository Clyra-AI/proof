package schema

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

// ValidateJSONFile validates a JSON file against a JSON schema file.
func ValidateJSONFile(schemaPath, jsonPath string) error {
	schema, err := loadSchema(schemaPath)
	if err != nil {
		return err
	}
	// #nosec G304 -- caller provides explicit local input path.
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("read json: %w", err)
	}
	return validateJSON(schema, data)
}

// ValidateJSON validates JSON bytes against a JSON schema file.
func ValidateJSON(schemaPath string, data []byte) error {
	schema, err := loadSchema(schemaPath)
	if err != nil {
		return err
	}
	return validateJSON(schema, data)
}

// ValidateJSONLFile validates each non-empty line in a JSONL file against a schema.
func ValidateJSONLFile(schemaPath, jsonlPath string) error {
	schema, err := loadSchema(schemaPath)
	if err != nil {
		return err
	}
	// #nosec G304 -- caller provides explicit local input path.
	data, err := os.ReadFile(jsonlPath)
	if err != nil {
		return fmt.Errorf("read jsonl: %w", err)
	}
	return validateJSONL(schema, data)
}

// ValidateJSONL validates each non-empty JSONL line against a schema.
func ValidateJSONL(schemaPath string, data []byte) error {
	schema, err := loadSchema(schemaPath)
	if err != nil {
		return err
	}
	return validateJSONL(schema, data)
}

func loadSchema(schemaPath string) (*jsonschema.Schema, error) {
	// #nosec G304 -- caller provides explicit local schema path.
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("schema.json", strings.NewReader(string(schemaBytes))); err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}
	schema, err := compiler.Compile("schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}
	return schema, nil
}

func validateJSON(schema *jsonschema.Schema, data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("parse json: %w", err)
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}
	return nil
}

func validateJSONL(schema *jsonschema.Schema, data []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		current := bytes.TrimSpace(scanner.Bytes())
		if len(current) == 0 {
			continue
		}
		if err := validateJSON(schema, current); err != nil {
			return fmt.Errorf("jsonl line %d: %w", line, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read jsonl: %w", err)
	}
	return nil
}
