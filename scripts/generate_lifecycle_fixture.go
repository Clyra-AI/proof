//go:build ignore

// Command generate_lifecycle_fixture imports the public released Gait v1.5
// lifecycle corpus into the Proof scenario tree. It never imports private keys.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	proofrecord "github.com/Clyra-AI/proof/core/record"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type manifest struct {
	FixtureVersion string `json:"fixture_version"`
	Producer       struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"producer"`
	SourceCommit string `json:"source_commit"`
	Signing      struct {
		PublicKeyPath   string `json:"public_key_path"`
		PublicKeySHA256 string `json:"public_key_sha256"`
	} `json:"signing"`
	Bindings  map[string]any     `json:"bindings"`
	Scenarios []scenarioManifest `json:"scenarios"`
}

type scenarioManifest struct {
	ScenarioID         string `json:"scenario_id"`
	Path               string `json:"path"`
	SHA256             string `json:"sha256"`
	ExpectedValid      *bool  `json:"expected_valid"`
	ExpectedReason     string `json:"expected_reason"`
	Execution          string `json:"execution"`
	Effect             string `json:"effect"`
	Containment        string `json:"containment"`
	Compensation       string `json:"compensation"`
	Stop               string `json:"stop"`
	Revocation         string `json:"revocation"`
	Invalidation       string `json:"invalidation"`
	SyntheticExtension bool   `json:"synthetic_extension"`
	Quarantine         bool   `json:"quarantine"`
	Authoritative      *bool  `json:"authoritative"`
	BaseCommit         string `json:"base_commit"`
	GeneratorSHA256    string `json:"generator_sha256"`
	SchemaSHA256       string `json:"schema_sha256"`
	ProducerVersion    string `json:"producer_version"`
}

func digest(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func collectRefs(v any, out *[]proofrecord.RelationshipRef) {
	switch x := v.(type) {
	case map[string]any:
		id, _ := x["id"].(string)
		kind, _ := x["kind"].(string)
		schema, _ := x["schema_id"].(string)
		ver, _ := x["schema_version"].(string)
		src, _ := x["source_product"].(string)
		dig, _ := x["digest"].(string)
		if id != "" && kind != "" && schema != "" && ver != "" && src != "" && dig != "" {
			if !strings.Contains(kind, ".") {
				kind = src + "." + kind
			}
			*out = append(*out, proofrecord.RelationshipRef{ID: id, Kind: kind, Digest: dig, SchemaID: schema, SchemaVersion: ver, SourceProduct: src})
		}
		for _, child := range x {
			collectRefs(child, out)
		}
	case []any:
		for _, child := range x {
			collectRefs(child, out)
		}
	}
}

func normalizeLifecycle(life map[string]any, s scenarioManifest, m manifest, refs []proofrecord.RelationshipRef) (map[string]any, map[string]any, time.Time) {
	records, _ := life["records"].([]any)
	last := time.Date(2026, 7, 19, 1, 0, 0, 0, time.UTC)
	derived := []string{}
	ids := []string{}
	evidenceRefs := []map[string]any{}
	for _, raw := range records {
		rec, _ := raw.(map[string]any)
		if value, ok := rec["occurred_at"].(string); ok {
			if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil && parsed.After(last) {
				last = parsed
			}
		}
		if id, ok := rec["record_id"].(string); ok && id != "" {
			ids = append(ids, id)
		}
		if sig, ok := rec["signature"].(map[string]any); ok {
			if signed, ok := sig["signed_digest"].(string); ok && signed != "" {
				derived = append(derived, "sha256:"+strings.TrimPrefix(signed, "sha256:"))
			}
		}
		for field, kind := range map[string]string{"execution": "execution", "effect": "effect_event", "containment": "containment", "compensation": "compensation", "control": "control"} {
			item, ok := rec[field].(map[string]any)
			if !ok {
				continue
			}
			if digest, ok := item["canonical_content_digest"].(string); ok && digest != "" {
				derived = append(derived, digest)
			}
			if id, ok := item["evidence_id"].(string); ok {
				if digest, ok := item["canonical_content_digest"].(string); ok {
					schema, _ := item["schema_id"].(string)
					evidenceRefs = append(evidenceRefs, map[string]any{"kind": kind, "id": id, "digest": digest, "schema_id": schema, "schema_version": "1", "source_product": "gait"})
				}
			}
		}
	}
	derived = uniqueStrings(derived)
	sort.Strings(ids)
	sort.Slice(evidenceRefs, func(i, j int) bool { return evidenceRefs[i]["id"].(string) < evidenceRefs[j]["id"].(string) })
	contract, activation := findRef(refs, "action_contract"), findRef(refs, "activated_action_contract")
	expectedSuccess := s.ExpectedValid != nil && *s.ExpectedValid && s.Execution == "succeeded" && s.Effect == "validated" && s.Containment == "completed"
	reasons := []string{}
	if s.ExpectedReason != "" {
		reasons = append(reasons, s.ExpectedReason)
	}
	producerVersion := s.ProducerVersion
	if producerVersion == "" {
		producerVersion = m.Producer.Version
	}
	event := map[string]any{"test_name": "gait_lifecycle_conformance", "status": statusFor(s), "evidence_set_id": "gait_lifecycle_v1:" + strings.TrimPrefix(s.SHA256, "sha256:")[:16], "producer": m.Producer.Name, "producer_version": producerVersion, "compatibility_base_version": m.Producer.Version, "source_commit": m.SourceCommit, "translation_version": "v1", "gait_execution": s.Execution, "gait_effect": s.Effect, "containment_status": s.Containment, "source_artifact_digest": s.SHA256, "source_artifact_digests": []string{s.SHA256}, "derived_evidence_digests": derived, "reason_codes": reasons, "contract_ref": contract, "activation_ref": activation, "evidence_refs": evidenceRefs, "authoritative_success": false, "gait_fixture_expected_authoritative_success": expectedSuccess, "fixture_only": true, "quarantine": true, "authoritative": false, "synthetic_extension": s.SyntheticExtension, "scenario_id": s.ScenarioID, "source_artifact_path": s.Path, "schema_id": "https://gait.dev/schemas/v1/runtime-lifecycle-record.schema.json", "schema_version": "1"}
	if s.Compensation != "" {
		event["compensation_status"] = s.Compensation
	}
	if s.Stop != "" {
		event["stop_status"] = s.Stop
	}
	if s.Revocation != "" {
		event["revocation_status"] = s.Revocation
	}
	if s.Invalidation != "" {
		event["invalidation_status"] = s.Invalidation
	}
	metadata := map[string]any{"evidence_kind": "gait_lifecycle", "projection": "integrity_only", "gait_evidence_set_id": event["evidence_set_id"], "gait_verification_state": "verified", "gait_authoritative": false, "gait_fixture_only": true, "gait_projection": "fixture_quarantine", "gait_authoritative_success": false, "gait_producer_version": producerVersion, "gait_compatibility_base_version": m.Producer.Version, "gait_synthetic_extension": s.SyntheticExtension, "gait_source_commit": m.SourceCommit, "gait_translation": "v1", "gait_source_artifact_digest": s.SHA256, "gait_source_artifact_digests": []string{s.SHA256}, "gait_derived_evidence_digests": derived, "gait_lifecycle_record_ids": ids, "gait_reason_codes": reasons}
	if s.Effect != "" {
		metadata["gait_effect"] = s.Effect
	}
	if s.Execution != "" {
		metadata["gait_execution"] = s.Execution
	}
	if s.Containment != "" {
		metadata["gait_containment_status"] = s.Containment
	}
	if s.Compensation != "" {
		metadata["gait_compensation_status"] = s.Compensation
	}
	return event, metadata, last
}

func findRef(refs []proofrecord.RelationshipRef, kind string) map[string]any {
	for _, ref := range refs {
		if strings.HasSuffix(ref.Kind, "."+kind) || ref.Kind == kind {
			return map[string]any{"kind": ref.Kind, "id": ref.ID, "digest": ref.Digest, "schema_id": ref.SchemaID, "schema_version": ref.SchemaVersion, "source_product": ref.SourceProduct}
		}
	}
	return map[string]any{}
}
func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
func statusFor(s scenarioManifest) string {
	if s.ExpectedValid != nil && *s.ExpectedValid {
		return "passed"
	}
	return "failed"
}

func normalizedLifecycleRecord(lifeBytes []byte, s scenarioManifest, m manifest) ([]byte, error) {
	var life map[string]any
	if err := json.Unmarshal(lifeBytes, &life); err != nil {
		return nil, err
	}
	refs := []proofrecord.RelationshipRef{}
	collectRefs(life, &refs)
	seen := map[string]bool{}
	uniq := refs[:0]
	for _, r := range refs {
		k := r.Kind + "|" + r.ID + "|" + r.Digest
		if !seen[k] {
			seen[k] = true
			uniq = append(uniq, r)
		}
	}
	refs = append(uniq, proofrecord.RelationshipRef{Kind: "evidence", ID: s.ScenarioID, Digest: s.SHA256, SchemaID: "https://gait.dev/schemas/v1/runtime-lifecycle-record.schema.json", SchemaVersion: "1", SourceProduct: "gait"})
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	event, metadata, tm := normalizeLifecycle(life, s, m, refs)
	rec, err := proofrecord.New(proofrecord.RecordOpts{Timestamp: tm, Source: "gait", SourceProduct: "gait", AgentID: "gait:fixture", Type: "test_result", Event: event, Metadata: metadata, Relationship: &proofrecord.Relationship{EntityRefs: refs}})
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func digestMatches(actual, expected string) bool {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(actual)), "sha256:") == strings.TrimPrefix(strings.ToLower(strings.TrimSpace(expected)), "sha256:")
}

func compareBytes(path string, want []byte) error {
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(want) {
		return fmt.Errorf("normalized fixture drift: %s", path)
	}
	return nil
}

func main() {
	source := flag.String("source", "/Users/tr/Clyra/gait-doc-completion/testdata/action-contract-evidence/v1", "released Gait fixture source")
	dest := flag.String("dest", "scenarios/proof/action-contract-lifecycle-conformance/source/gait-v1.5.0", "Proof fixture destination")
	update := flag.Bool("update", false, "import source files")
	check := flag.Bool("check", false, "check exact generated bytes")
	flag.Parse()
	if *update == *check {
		fmt.Fprintln(os.Stderr, "exactly one of --update or --check is required")
		os.Exit(2)
	}
	if *update && strings.TrimSpace(*source) == "" {
		fmt.Fprintln(os.Stderr, "--source is required with --update")
		os.Exit(2)
	}
	if !*update {
		*source = ""
	}
	if err := run(*source, *dest, *update); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(source, dest string, update bool) error {
	manifestPath := filepath.Join(dest, "upstream-manifest.json")
	if update {
		manifestPath = filepath.Join(source, "fixture-manifest.json")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m manifest
	if err = json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m.Producer.Name != "gait" || m.Producer.Version != "v1.5.0" || m.SourceCommit == "" {
		return fmt.Errorf("unexpected Gait provenance")
	}
	if update {
		if err = os.MkdirAll(dest, 0700); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dest, "upstream-manifest.json"), raw, 0600); err != nil {
			return err
		}
	}
	pub := m.Signing.PublicKeyPath
	keyPath := filepath.Join(source, filepath.Base(pub))
	if !update {
		keyPath = filepath.Join(dest, "fixture-signing-key.public.b64")
	}
	keyBytes, e := os.ReadFile(keyPath)
	if e != nil {
		return e
	}
	if !digestMatches(digest(keyBytes), m.Signing.PublicKeySHA256) {
		return fmt.Errorf("lifecycle public key digest mismatch")
	}
	for _, s := range m.Scenarios {
		sourcePath := filepath.Join(source, s.Path)
		if !update {
			sourcePath = filepath.Join(dest, filepath.Base(filepath.Dir(s.Path)), "lifecycle.json")
		}
		b, e := os.ReadFile(sourcePath)
		if e != nil {
			return e
		}
		if !digestMatches(digest(b), s.SHA256) {
			return fmt.Errorf("lifecycle source digest mismatch: %s", s.ScenarioID)
		}
		if update {
			p := filepath.Join(dest, filepath.Base(filepath.Dir(s.Path)), "lifecycle.json")
			if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
				return e
			}
			if e = os.WriteFile(p, b, 0600); e != nil {
				return e
			}
		}
		normalized, e := normalizedLifecycleRecord(b, s, m)
		if e != nil {
			return e
		}
		np := filepath.Join(dest, "normalized", s.ScenarioID, "records.jsonl")
		if update {
			if e = os.MkdirAll(filepath.Dir(np), 0700); e != nil {
				return e
			}
			if e = os.WriteFile(np, normalized, 0600); e != nil {
				return e
			}
		} else if e = compareBytes(np, normalized); e != nil {
			return e
		}
	}
	if update {
		if e = os.WriteFile(filepath.Join(dest, "fixture-signing-key.public.b64"), keyBytes, 0600); e != nil {
			return e
		}
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		return err
	}
	var files []string
	for _, d := range entries {
		if d.IsDir() && d.Name() != "normalized" {
			p := filepath.Join(dest, d.Name(), "lifecycle.json")
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			files = append(files, fmt.Sprintf("%s|%s", d.Name(), digest(b)))
		}
	}
	sort.Strings(files)
	if len(files) != len(m.Scenarios) {
		return fmt.Errorf("scenario count drift: got %d want %d", len(files), len(m.Scenarios))
	}
	var normalized []string
	for _, s := range m.Scenarios {
		p := filepath.Join(dest, "normalized", s.ScenarioID, "records.jsonl")
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		normalized = append(normalized, fmt.Sprintf("%s|%s", s.ScenarioID, digest(b)))
	}
	sort.Strings(normalized)
	out := map[string]any{"fixture_version": "1", "producer": m.Producer.Name, "compatibility_base_version": m.Producer.Version, "source_commit": m.SourceCommit, "fixture_only": true, "quarantine": true, "authoritative": false, "upstream_manifest_sha256": digest(raw), "public_key_sha256": m.Signing.PublicKeySHA256, "scenarios": files, "normalized": normalized}
	encoded, _ := json.MarshalIndent(out, "", "  ")
	encoded = append(encoded, '\n')
	manifestOutputPath := filepath.Join(dest, "source-manifest.json")
	if update {
		if err = os.WriteFile(manifestOutputPath, encoded, 0600); err != nil {
			return err
		}
	} else {
		got, e := os.ReadFile(manifestOutputPath)
		if e != nil {
			return e
		}
		if string(got) != string(encoded) {
			return fmt.Errorf("generated manifest drift")
		}
	}
	allowed := map[string]bool{
		"upstream-manifest.json":         true,
		"source-manifest.json":           true,
		"fixture-signing-key.public.b64": true,
	}
	for _, scenario := range m.Scenarios {
		allowed[filepath.ToSlash(filepath.Join(filepath.Base(filepath.Dir(scenario.Path)), "lifecycle.json"))] = true
		allowed[filepath.ToSlash(filepath.Join("normalized", scenario.ScenarioID, "records.jsonl"))] = true
	}
	return filepath.Walk(dest, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dest, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !allowed[rel] {
			return fmt.Errorf("fixture orphan: %s", rel)
		}
		return nil
	})
}
