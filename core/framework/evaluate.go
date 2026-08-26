package framework

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/proof/core/record"
)

// Coverage is the deterministic evidence-path coverage result for a framework.
//
// Deprecated: framework coverage is retained as a compatibility API. It must
// not be interpreted as compliance status, regulatory applicability, or gap
// scoring; those semantics belong to the consuming product.
type Coverage struct {
	FrameworkID      string            `json:"framework_id"`
	FrameworkVersion string            `json:"framework_version"`
	TotalControls    int               `json:"total_controls"`
	CoveredControls  int               `json:"covered_controls"`
	Controls         []ControlCoverage `json:"controls"`
}

// ControlCoverage describes deterministic evidence-path matches for one
// framework control.
//
// Deprecated: retained for compatibility; this type carries no compliance
// interpretation.
type ControlCoverage struct {
	ID                    string                `json:"id"`
	Title                 string                `json:"title"`
	Covered               bool                  `json:"covered"`
	MatchedEvidenceSetIDs []string              `json:"matched_evidence_set_ids,omitempty"`
	EvidenceSets          []EvidenceSetCoverage `json:"evidence_sets,omitempty"`
	Children              []ControlCoverage     `json:"children,omitempty"`
}

// EvidenceSetCoverage describes deterministic record matches for one evidence
// set.
//
// Deprecated: retained for compatibility; this type carries no compliance
// interpretation.
type EvidenceSetCoverage struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title,omitempty"`
	Covered             bool     `json:"covered"`
	SourceProducts      []string `json:"source_products,omitempty"`
	RequiredRecordTypes []string `json:"required_record_types"`
	MinimumFrequency    string   `json:"minimum_frequency"`
	RequiredFields      []string `json:"required_fields"`
	MatchingRecordIDs   []string `json:"matching_record_ids,omitempty"`
	MissingRecordTypes  []string `json:"missing_record_types,omitempty"`
}

type indexedRecord struct {
	record record.Record
	raw    map[string]any
}

// EvaluateCoverage reports deterministic evidence-path coverage.
//
// Deprecated: use this only as a compatibility helper. It does not evaluate
// regulatory applicability, compliance status, or gap scoring.
func EvaluateCoverage(f *Framework, records []record.Record) (*Coverage, error) {
	if f == nil {
		return nil, fmt.Errorf("framework is nil")
	}
	if err := validateControls(f.Controls, "controls"); err != nil {
		return nil, fmt.Errorf("framework invalid: %w", err)
	}

	indexed := make([]indexedRecord, 0, len(records))
	for i := range records {
		raw, err := recordMap(records[i])
		if err != nil {
			return nil, err
		}
		indexed = append(indexed, indexedRecord{record: records[i], raw: raw})
	}

	controls := make([]ControlCoverage, 0, len(f.Controls))
	for _, control := range f.Controls {
		controls = append(controls, evaluateControl(control, indexed))
	}

	coveredControls := countCoveredControls(controls)
	return &Coverage{
		FrameworkID:      f.Framework.ID,
		FrameworkVersion: f.Framework.Version,
		TotalControls:    countControls(f.Controls),
		CoveredControls:  coveredControls,
		Controls:         controls,
	}, nil
}

func evaluateControl(control Control, indexed []indexedRecord) ControlCoverage {
	sets := controlEvidenceSets(control)
	setCoverage := make([]EvidenceSetCoverage, 0, len(sets))
	matched := make([]string, 0, len(sets))
	for _, set := range sets {
		coverage := evaluateEvidenceSet(set, indexed)
		setCoverage = append(setCoverage, coverage)
		if coverage.Covered {
			matched = append(matched, coverage.ID)
		}
	}

	children := make([]ControlCoverage, 0, len(control.Children))
	for _, child := range control.Children {
		children = append(children, evaluateControl(child, indexed))
	}

	return ControlCoverage{
		ID:                    control.ID,
		Title:                 control.Title,
		Covered:               len(matched) > 0,
		MatchedEvidenceSetIDs: matched,
		EvidenceSets:          setCoverage,
		Children:              children,
	}
}

func evaluateEvidenceSet(set EvidenceSet, indexed []indexedRecord) EvidenceSetCoverage {
	matching := make([]string, 0, len(set.RequiredRecordTypes))
	missing := make([]string, 0, len(set.RequiredRecordTypes))
	for _, requiredType := range set.RequiredRecordTypes {
		recordID, ok := matchRecord(requiredType, set, indexed)
		if !ok {
			missing = append(missing, requiredType)
			continue
		}
		matching = append(matching, recordID)
	}
	matching = sortedUniqueStrings(matching)
	return EvidenceSetCoverage{
		ID:                  set.ID,
		Title:               set.Title,
		Covered:             len(missing) == 0,
		SourceProducts:      append([]string(nil), set.SourceProducts...),
		RequiredRecordTypes: append([]string(nil), set.RequiredRecordTypes...),
		MinimumFrequency:    set.MinimumFrequency,
		RequiredFields:      append([]string(nil), set.RequiredFields...),
		MatchingRecordIDs:   matching,
		MissingRecordTypes:  missing,
	}
}

func matchRecord(requiredType string, set EvidenceSet, indexed []indexedRecord) (string, bool) {
	requiredType = strings.TrimSpace(requiredType)
	bestRecordID := ""
	for _, candidate := range indexed {
		if candidate.record.RecordType != requiredType {
			continue
		}
		if !matchesSourceProduct(candidate.record.SourceProduct, set.SourceProducts) {
			continue
		}
		if !hasRequiredFields(candidate.raw, set.RequiredFields) {
			continue
		}
		if bestRecordID == "" || candidate.record.RecordID < bestRecordID {
			bestRecordID = candidate.record.RecordID
		}
	}
	if bestRecordID == "" {
		return "", false
	}
	return bestRecordID, true
}

func matchesSourceProduct(sourceProduct string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	sourceProduct = strings.ToLower(strings.TrimSpace(sourceProduct))
	for _, product := range allowed {
		if sourceProduct == strings.ToLower(strings.TrimSpace(product)) {
			return true
		}
	}
	return false
}

func hasRequiredFields(raw map[string]any, fields []string) bool {
	for _, field := range fields {
		value, ok := fieldValue(raw, field)
		if !ok || !presentValue(value) {
			return false
		}
	}
	return true
}

func fieldValue(raw map[string]any, path string) (any, bool) {
	current := any(raw)
	for _, part := range strings.Split(path, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, false
		}
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		next, exists := m[part]
		if !exists {
			return nil, false
		}
		current = next
	}
	return current, true
}

func presentValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}

func controlEvidenceSets(control Control) []EvidenceSet {
	if len(control.EvidenceSets) > 0 {
		out := make([]EvidenceSet, len(control.EvidenceSets))
		copy(out, control.EvidenceSets)
		return out
	}
	return []EvidenceSet{{
		ID:                  "legacy",
		Title:               control.Title,
		RequiredRecordTypes: append([]string(nil), control.RequiredRecordTypes...),
		MinimumFrequency:    control.MinimumFrequency,
		RequiredFields:      append([]string(nil), control.RequiredFields...),
	}}
}

func countCoveredControls(controls []ControlCoverage) int {
	total := 0
	for _, control := range controls {
		if control.Covered {
			total++
		}
		total += countCoveredControls(control.Children)
	}
	return total
}

func recordMap(in record.Record) (map[string]any, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func sortedUniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
