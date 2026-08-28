//go:build ignore

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	proofrecord "github.com/Clyra-AI/proof/core/record"
)

// Sources are always supplied explicitly for imports. Check mode reads the
// committed fixture tree and never consults a developer checkout.
const defaultDest = "scenarios/proof/action-contract-gate-conformance/source/gait-gate-v1"

type sourceManifest struct {
	FixtureVersion         string `json:"fixture_version"`
	FixtureTestOnly        bool   `json:"fixture_test_only"`
	Quarantine             bool   `json:"quarantine"`
	Authoritative          bool   `json:"authoritative"`
	BaseCommit             string `json:"base_commit"`
	GeneratorSHA256        string `json:"generator_sha256"`
	ApprovalSchemaSHA256   string `json:"approval_schema_sha256"`
	DelegationSchemaSHA256 string `json:"delegation_schema_sha256"`
	PublicKeySHA256        string `json:"public_key_sha256"`
	Files                  []struct {
		Path         string `json:"path"`
		SHA256       string `json:"sha256"`
		ExpectedCode string `json:"expected_code"`
		Signed       bool   `json:"signed"`
	} `json:"files"`
}

func main() {
	source := flag.String("source", "", "Gait gate fixture source (required with --update)")
	dest := flag.String("dest", defaultDest, "Proof fixture destination")
	update := flag.Bool("update", false, "import and regenerate")
	check := flag.Bool("check", false, "check exact bytes and orphans")
	offline := flag.Bool("offline", false, "require local source only")
	flag.Parse()
	_ = *offline
	if *update == *check {
		fatalCode(6, "exactly one of --update or --check is required")
	}
	if *update && strings.TrimSpace(*source) == "" {
		fatalCode(6, "--source is required with --update")
	}
	if !*update {
		*source = ""
	}
	if err := run(*source, *dest, *update); err != nil {
		fatal("%v", err)
	}
}
func fatalCode(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(code)
}
func fatal(format string, args ...any) { fatalCode(1, format, args...) }
func digest(raw []byte) string         { s := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(s[:]) }
func digestMatches(actual, expected string) bool {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(actual)), "sha256:") == strings.TrimPrefix(strings.ToLower(strings.TrimSpace(expected)), "sha256:")
}
func ref(kind, id, dig, schema, version, source string) proofrecord.RelationshipRef {
	if dig != "" && !strings.HasPrefix(dig, "sha256:") {
		dig = "sha256:" + dig
	}
	return proofrecord.RelationshipRef{Kind: source + "." + kind, ID: id, Digest: dig, SchemaID: schema, SchemaVersion: version, SourceProduct: source}
}
func get(m map[string]any, key string) string { v, _ := m[key].(string); return v }
func refFrom(m map[string]any, source string) proofrecord.RelationshipRef {
	kind := get(m, "kind")
	if kind == "" {
		kind = "artifact"
	}
	return ref(kind, get(m, "id"), get(m, "digest"), get(m, "schema_id"), get(m, "schema_version"), source)
}
func run(source, dest string, update bool) error {
	manifestPath := filepath.Join(source, "fixture-manifest.json")
	artifactRoot := source
	keyPath := filepath.Join(source, "fixture-signing-key.public.b64")
	if !update {
		manifestPath = filepath.Join(dest, "provenance", "upstream-manifest.json")
		artifactRoot = filepath.Join(dest, "source")
		keyPath = filepath.Join(dest, "fixture-signing-key.public.b64")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var sm sourceManifest
	if err = json.Unmarshal(raw, &sm); err != nil {
		return err
	}
	if !sm.FixtureTestOnly || !sm.Quarantine || sm.Authoritative {
		return fmt.Errorf("source authority boundary invalid")
	}
	if update {
		if err = os.MkdirAll(filepath.Join(dest, "provenance"), 0750); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dest, "provenance", "upstream-manifest.json"), raw, 0600); err != nil {
			return err
		}
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	if !digestMatches(digest(key), sm.PublicKeySHA256) {
		return fmt.Errorf("gate public key digest mismatch")
	}
	files := map[string][]byte{}
	records := []*proofrecord.Record{}
	for _, entry := range sm.Files {
		b, e := os.ReadFile(filepath.Join(artifactRoot, entry.Path))
		if e != nil {
			return e
		}
		if !digestMatches(digest(b), entry.SHA256) {
			return fmt.Errorf("gate source digest mismatch: %s", entry.Path)
		}
		files[entry.Path] = b
		var obj map[string]any
		if e = json.Unmarshal(b, &obj); e != nil {
			return e
		}
		rec, e := normalize(obj, entry, b, sm)
		if e != nil {
			return e
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].RecordID < records[j].RecordID })
	for i := range records {
		if i > 0 {
			records[i].Integrity.PreviousRecordHash = records[i-1].Integrity.RecordHash
			records[i].Integrity.RecordHash, err = proofrecord.ComputeHash(records[i])
			if err != nil {
				return err
			}
		}
	}
	for _, r := range records {
		normalized, e := json.Marshal(r)
		if e != nil {
			return e
		}
		normalized = append(normalized, '\n')
		normalizedPath := filepath.Join(dest, "normalized", r.Event["artifact_path"].(string), "records.jsonl")
		if update {
			if e := os.MkdirAll(filepath.Dir(normalizedPath), 0750); e != nil {
				return e
			}
			if e := os.WriteFile(normalizedPath, normalized, 0600); e != nil {
				return e
			}
		} else if e := compareFile(normalizedPath, normalized); e != nil {
			return e
		}
	}
	chainRaw := []byte{}
	for _, r := range records {
		line, e := json.Marshal(r)
		if e != nil {
			return e
		}
		chainRaw = append(chainRaw, line...)
		chainRaw = append(chainRaw, '\n')
	}
	manifest := map[string]any{"fixture_version": "1", "fixture_test_only": true, "quarantine": true, "authoritative": false, "upstream_manifest_sha256": digest(raw), "public_key_sha256": sm.PublicKeySHA256, "base_commit": sm.BaseCommit, "generator_sha256": sm.GeneratorSHA256, "approval_schema_sha256": sm.ApprovalSchemaSHA256, "delegation_schema_sha256": sm.DelegationSchemaSHA256, "records": map[string]any{"path": "records.jsonl", "sha256": digest(chainRaw), "count": len(records), "record_ids": recordIDs(records), "record_hashes": recordHashes(records)}, "sources": []string{"gait"}}
	manifestRaw, _ := json.MarshalIndent(manifest, "", "  ")
	manifestRaw = append(manifestRaw, '\n')
	if update {
		for path, b := range files {
			p := filepath.Join(dest, "source", path)
			if e := os.MkdirAll(filepath.Dir(p), 0750); e != nil {
				return e
			}
			if e := os.WriteFile(p, b, 0600); e != nil {
				return e
			}
		}
		if e := os.WriteFile(filepath.Join(dest, "fixture-signing-key.public.b64"), key, 0600); e != nil {
			return e
		}
		if e := os.MkdirAll(filepath.Join(dest, "normalized"), 0750); e != nil {
			return e
		}
		if e := os.WriteFile(filepath.Join(dest, "records.jsonl"), chainRaw, 0600); e != nil {
			return e
		}
		if e := os.WriteFile(filepath.Join(dest, "provenance", "source-manifest.json"), manifestRaw, 0600); e != nil {
			return e
		}
	} else {
		if e := compareFile(filepath.Join(dest, "records.jsonl"), chainRaw); e != nil {
			return e
		}
		if e := compareFile(filepath.Join(dest, "provenance", "source-manifest.json"), manifestRaw); e != nil {
			return e
		}
	}
	return orphanCheck(dest, records, files)
}
func normalize(obj map[string]any, entry struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	ExpectedCode string `json:"expected_code"`
	Signed       bool   `json:"signed"`
}, raw []byte, sm sourceManifest) (*proofrecord.Record, error) {
	kind := "delegation"
	if strings.Contains(entry.Path, "approval") {
		kind = "approval"
	}
	refs := []proofrecord.RelationshipRef{}
	if v, ok := obj["contract_id"].(string); ok && v != "" {
		refs = append(refs, ref("action_contract", v, "sha256:"+get(obj, "proposal_digest"), "https://wrkr.dev/schemas/v1/proposed-action-contract-v3.schema.json", "3", "wrkr"))
	}
	if v, ok := obj["parent_token_id"].(string); ok && v != "" {
		refs = append(refs, ref("delegation_parent", v, get(obj, "parent_token_digest"), "gait.gate.delegation_token", "1.0.0", "gait"))
	}
	if v, ok := obj["origin_authority_digest"].(string); ok && v != "" {
		refs = append(refs, ref("delegation_origin", v, v, "gait.gate.delegation_token", "1.0.0", "gait"))
	}
	refs = append(refs, ref("gate_"+kind, get(obj, "token_id"), digest(raw), get(obj, "schema_id"), get(obj, "schema_version"), "gait"))
	sort.Slice(refs, func(i, j int) bool { return refs[i].Kind+refs[i].ID < refs[j].Kind+refs[j].ID })
	ts := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	if v, ok := obj["created_at"].(string); ok {
		if t, e := time.Parse(time.RFC3339Nano, v); e == nil {
			ts = t
		}
	}
	event := map[string]any{"artifact_path": entry.Path, "artifact_kind": kind, "fixture_only": true, "quarantine": true, "authoritative": false, "evidence_kind": "gait_gate_fixture", "schema_id": get(obj, "schema_id"), "schema_version": get(obj, "schema_version"), "producer_version": get(obj, "producer_version"), "source_artifact_digest": digest(raw), "expected_code": entry.ExpectedCode, "token_id": get(obj, "token_id"), "scope": obj["scope"], "parent_token_id": obj["parent_token_id"], "origin_authority_digest": obj["origin_authority_digest"]}
	for _, relationshipRef := range refs {
		if relationshipRef.Kind == "wrkr.action_contract" {
			event["contract_ref"] = relationshipRef
			break
		}
	}
	if value := get(obj, "contract_digest"); value != "" {
		event["contract_digest"] = "sha256:" + strings.TrimPrefix(value, "sha256:")
	}
	if value := get(obj, "activation_digest"); value != "" {
		event["activation_digest"] = "sha256:" + strings.TrimPrefix(value, "sha256:")
	}
	metadata := map[string]any{"fixture_only": true, "quarantine": true, "authoritative": false, "projection": "integrity_only", "gate_artifact_kind": kind, "gate_schema_id": get(obj, "schema_id"), "gate_expected_code": entry.ExpectedCode}
	return proofrecord.New(proofrecord.RecordOpts{Timestamp: ts, Source: "gait", SourceProduct: "gait", AgentID: "gait:gate-fixture", Type: "test_result", Event: event, Metadata: metadata, Controls: proofrecord.Controls{PermissionsEnforced: false}, Relationship: &proofrecord.Relationship{EntityRefs: refs}})
}
func recordIDs(rs []*proofrecord.Record) []string {
	o := []string{}
	for _, r := range rs {
		o = append(o, r.RecordID)
	}
	return o
}
func recordHashes(rs []*proofrecord.Record) []string {
	o := []string{}
	for _, r := range rs {
		o = append(o, r.Integrity.RecordHash)
	}
	return o
}
func compareFile(path string, want []byte) error {
	got, e := os.ReadFile(path)
	if e != nil || string(got) != string(want) {
		return fmt.Errorf("fixture drift: %s", path)
	}
	return nil
}
func orphanCheck(dest string, records []*proofrecord.Record, source map[string][]byte) error {
	allowed := map[string]bool{"provenance/upstream-manifest.json": true, "provenance/source-manifest.json": true, "fixture-signing-key.public.b64": true, "records.jsonl": true}
	for path := range source {
		allowed[filepath.ToSlash(filepath.Join("source", path))] = true
	}
	for _, r := range records {
		allowed[filepath.ToSlash(filepath.Join("normalized", r.Event["artifact_path"].(string), "records.jsonl"))] = true
	}
	return filepath.Walk(dest, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dest, path)
		if !allowed[filepath.ToSlash(rel)] {
			return fmt.Errorf("fixture orphan: %s", rel)
		}
		return nil
	})
}
