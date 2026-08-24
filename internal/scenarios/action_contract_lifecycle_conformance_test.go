//go:build scenario

package scenarios_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/proof"
	proofframework "github.com/Clyra-AI/proof/core/framework"
	"github.com/Clyra-AI/proof/internal/testutil"
	"github.com/stretchr/testify/require"
)

const (
	contractDigest   = "sha256:d3a371d51af5af30c4c4b8e2694b40cb16791c4e8c469bd53a483a99fb3c88cf"
	activationDigest = "sha256:4aad73ff9f3c7e5a680dec3bc05684221f4770e6c47a58ed95bd7d6e1adbfe71"
	lifecycleDigest  = "sha256:fcb0085b5af73b8a42aa09c25c09f6510d4eb39b8c06a0eb4e16bcbded4fffa2"
)

func TestActionContractLifecycleConformanceNegatives(t *testing.T) {
	records := lifecycleFixtureRecords(t)
	require.True(t, strictLifecycleBindings(records))
	require.True(t, fixtureAuthoritySafe(records[1]))

	t.Run("source and lifecycle digest tamper breaks chain", func(t *testing.T) {
		mutated := cloneProofRecords(t, records)
		mutated[1].Event["source_artifact_digest"] = "sha256:" + strings.Repeat("a", 64)
		verification, err := proof.VerifyChain(fixtureChain(mutated))
		require.NoError(t, err)
		require.False(t, verification.Intact)
	})
	t.Run("contract full identity mismatch", func(t *testing.T) {
		mutated := cloneProofRecords(t, records)
		mutated[1].Event["contract_ref"].(map[string]any)["schema_version"] = "2"
		require.False(t, strictLifecycleBindings(mutated))
	})
	t.Run("activation full identity mismatch", func(t *testing.T) {
		mutated := cloneProofRecords(t, records)
		mutated[1].Event["activation_ref"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("b", 64)
		require.False(t, strictLifecycleBindings(mutated))
	})
	t.Run("missing relationship digest under strict cross product check", func(t *testing.T) {
		mutated := cloneProofRecords(t, records)
		mutated[1].Relationship.EntityRefs[0].Digest = ""
		require.False(t, strictLifecycleBindings(mutated))
	})
	t.Run("duplicate event evidence ref breaks bijection", func(t *testing.T) {
		mutated := cloneProofRecords(t, records)
		refs := mutated[1].Event["evidence_refs"].([]any)
		refs[len(refs)-1] = refs[0]
		require.False(t, strictLifecycleBindings(mutated))
	})
	t.Run("fixture-only cannot be authoritative", func(t *testing.T) {
		mutated := cloneProofRecord(t, records[1])
		mutated.Event["authoritative_success"] = true
		mutated.Metadata["gait_authoritative"] = true
		require.False(t, fixtureAuthoritySafe(mutated))
	})
	t.Run("reordered chain", func(t *testing.T) {
		mutated := []proof.Record{records[1], records[0], records[2]}
		verification, err := proof.VerifyChain(fixtureChain(mutated))
		require.NoError(t, err)
		require.False(t, verification.Intact)
	})
	t.Run("tampered aggregate returns CLI verification exit two", func(t *testing.T) {
		mutated := cloneProofRecords(t, records)
		mutated[1].Event["source_artifact_digest"] = "sha256:" + strings.Repeat("c", 64)
		dir := t.TempDir()
		writeJSONLRecords(t, filepath.Join(dir, "records.jsonl"), mutated)
		binary := testutil.BuildBinary(t, testutil.RepoRoot(t))
		out, code := runProof(binary, "verify", dir)
		require.Equal(t, 2, code, out)
	})
}

func TestActionContractLifecycleEvidenceSetAlternatives(t *testing.T) {
	records := lifecycleFixtureRecords(t)
	framework := &proofframework.Framework{}
	framework.Framework.ID = "action-contract-lifecycle"
	framework.Framework.Version = "1"
	framework.Controls = []proofframework.Control{{ID: "lifecycle", Title: "Lifecycle", EvidenceSets: []proofframework.EvidenceSet{
		{ID: "a_incomplete", SourceProducts: []string{"gait"}, RequiredRecordTypes: []string{"test_result", "risk_assessment"}, RequiredFields: []string{"record_id", "event.test_name"}, MinimumFrequency: "continuous"},
		{ID: "b_production", SourceProducts: []string{"gait"}, RequiredRecordTypes: []string{"test_result"}, RequiredFields: []string{"record_id", "event.test_name", "metadata.gait_production_authority_attested"}, MinimumFrequency: "continuous"},
	}}}
	fixtureCoverage, err := proof.EvaluateFrameworkCoverage(framework, records)
	require.NoError(t, err)
	require.False(t, fixtureCoverage.Controls[0].Covered)
	require.Empty(t, fixtureCoverage.Controls[0].MatchedEvidenceSetIDs)
	require.False(t, fixtureCoverage.Controls[0].EvidenceSets[0].Covered)
	require.Equal(t, []string{"risk_assessment"}, fixtureCoverage.Controls[0].EvidenceSets[0].MissingRecordTypes)

	production := cloneProofRecord(t, records[1])
	production.RecordID = "synthetic-production-gait-lifecycle"
	production.Metadata["gait_fixture_only"] = false
	production.Metadata["gait_authoritative"] = true
	production.Metadata["gait_production_authority_attested"] = true
	coverage, err := proof.EvaluateFrameworkCoverage(framework, append(records, production))
	require.NoError(t, err)
	require.Equal(t, []string{"b_production"}, coverage.Controls[0].MatchedEvidenceSetIDs)
	first, err := json.Marshal(coverage)
	require.NoError(t, err)
	reversed := []proof.Record{production, records[2], records[1], records[0]}
	secondCoverage, err := proof.EvaluateFrameworkCoverage(framework, reversed)
	require.NoError(t, err)
	second, err := json.Marshal(secondCoverage)
	require.NoError(t, err)
	require.Equal(t, string(first), string(second))

	withoutGait, err := proof.EvaluateFrameworkCoverage(framework, []proof.Record{records[0], records[2]})
	require.NoError(t, err)
	require.False(t, withoutGait.Controls[0].Covered)
	wrkrOnly, err := proof.EvaluateFrameworkCoverage(framework, []proof.Record{records[0]})
	require.NoError(t, err)
	require.False(t, wrkrOnly.Controls[0].Covered)
}

func lifecycleFixtureRecords(t *testing.T) []proof.Record {
	t.Helper()
	root := testutil.RepoRoot(t)
	return readJSONLRecords(t, filepath.Join(root, "scenarios", "proof", "action-contract-lifecycle-conformance", "records.jsonl"))
}

func cloneProofRecords(t *testing.T, records []proof.Record) []proof.Record {
	t.Helper()
	out := make([]proof.Record, len(records))
	for i := range records {
		out[i] = cloneProofRecord(t, records[i])
	}
	return out
}

func cloneProofRecord(t *testing.T, in proof.Record) proof.Record {
	t.Helper()
	raw, err := json.Marshal(in)
	require.NoError(t, err)
	var out proof.Record
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func fixtureChain(records []proof.Record) *proof.Chain {
	head := ""
	if len(records) > 0 {
		head = records[len(records)-1].Integrity.RecordHash
	}
	return &proof.Chain{ChainID: "action-contract-lifecycle-conformance", RecordCount: len(records), Records: records, HeadHash: head}
}

func writeJSONLRecords(t *testing.T, path string, records []proof.Record) {
	t.Helper()
	raw := []byte{}
	for i := range records {
		line, err := json.Marshal(records[i])
		require.NoError(t, err)
		raw = append(raw, line...)
		raw = append(raw, '\n')
	}
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

func strictLifecycleBindings(records []proof.Record) bool {
	if len(records) != 3 || records[0].SourceProduct != "wrkr" || records[1].SourceProduct != "gait" || records[2].SourceProduct != "axym" {
		return false
	}
	contract := proof.RelationshipRef{Kind: "wrkr.action_contract", ID: "pac-4b7f1402784256ce", Digest: contractDigest, SchemaID: "https://wrkr.dev/schemas/v1/proposed-action-contract-v3.schema.json", SchemaVersion: "3", SourceProduct: "wrkr"}
	activation := proof.RelationshipRef{Kind: "gait.activated_action_contract", ID: "gact-4aad73ff9f3c7e5a", Digest: activationDigest, SchemaID: "https://gait.dev/schemas/v1/activated-action-contract-artifact.schema.json", SchemaVersion: "1", SourceProduct: "gait"}
	lifecycle := proof.RelationshipRef{Kind: "gait.lifecycle_evidence", ID: "gait_lifecycle_v1:fcb0085b5af73b8a", Digest: lifecycleDigest, SchemaID: "https://gait.dev/schemas/v1/runtime-lifecycle-record.schema.json", SchemaVersion: "1", SourceProduct: "gait"}
	if !eventRefEquals(records[0], "contract_ref", contract) || records[0].Relationship == nil || len(records[0].Relationship.EntityRefs) != 1 || !sameRef(records[0].Relationship.EntityRefs[0], contract) {
		return false
	}
	if records[1].Event["evidence_set_id"] != lifecycle.ID || !eventRefEquals(records[1], "contract_ref", contract) || !eventRefEquals(records[1], "activation_ref", activation) || records[1].Event["source_artifact_digest"] != lifecycleDigest || records[1].Relationship == nil || !hasRef(records[1].Relationship.EntityRefs, contract) || !hasRef(records[1].Relationship.EntityRefs, activation) {
		return false
	}
	evidenceRefs, ok := records[1].Event["evidence_refs"].([]any)
	if !ok || len(evidenceRefs) != 6 || len(records[1].Relationship.EntityRefs) != len(evidenceRefs)+2 {
		return false
	}
	eventSet := make(map[string]struct{}, len(evidenceRefs))
	for _, value := range evidenceRefs {
		raw, err := json.Marshal(value)
		if err != nil {
			return false
		}
		var ref proof.RelationshipRef
		if json.Unmarshal(raw, &ref) != nil || ref.Kind == "" || ref.Digest == "" || ref.SchemaID == "" || ref.SchemaVersion == "" || ref.SourceProduct != "gait" {
			return false
		}
		ref.Kind = ref.SourceProduct + "." + ref.Kind
		key := refKey(ref)
		if _, duplicate := eventSet[key]; duplicate {
			return false
		}
		eventSet[key] = struct{}{}
	}
	relationshipSet := make(map[string]struct{}, len(evidenceRefs))
	for _, ref := range records[1].Relationship.EntityRefs {
		if ref.Digest == "" || ref.SchemaID == "" || ref.SchemaVersion == "" || ref.SourceProduct == "" {
			return false
		}
		if sameRef(ref, contract) || sameRef(ref, activation) {
			continue
		}
		key := refKey(ref)
		if _, duplicate := relationshipSet[key]; duplicate {
			return false
		}
		relationshipSet[key] = struct{}{}
	}
	if len(eventSet) != len(relationshipSet) {
		return false
	}
	for key := range eventSet {
		if _, ok := relationshipSet[key]; !ok {
			return false
		}
	}
	aggregate := proof.RelationshipRef{Kind: "proof.record", ID: records[1].RecordID, Digest: records[1].Integrity.RecordHash, SchemaID: "https://github.com/Clyra-AI/proof/schemas/v1/proof-record-v1.schema.json", SchemaVersion: "1.0", SourceProduct: "gait"}
	if records[2].Event["evidence_set_id"] != lifecycle.ID || !eventRefEquals(records[2], "contract_ref", contract) || !eventRefEquals(records[2], "activation_ref", activation) || !eventRefEquals(records[2], "lifecycle_ref", lifecycle) || !eventRefEquals(records[2], "gait_aggregate_record_ref", aggregate) || records[2].Relationship == nil || len(records[2].Relationship.EntityRefs) != 4 || !hasRef(records[2].Relationship.EntityRefs, contract) || !hasRef(records[2].Relationship.EntityRefs, activation) || !hasRef(records[2].Relationship.EntityRefs, lifecycle) || !hasRef(records[2].Relationship.EntityRefs, aggregate) {
		return false
	}
	return true
}

func fixtureAuthoritySafe(record proof.Record) bool {
	if record.Event["authoritative_success"] != false || record.Event["gait_fixture_expected_authoritative_success"] != true || record.Metadata["gait_fixture_only"] != true || record.Metadata["gait_authoritative"] != false || record.Metadata["gait_authoritative_success"] != false || record.Metadata["gait_projection"] != "fixture_quarantine" {
		return false
	}
	return true
}

func eventRefEquals(record proof.Record, key string, want proof.RelationshipRef) bool {
	value, ok := record.Event[key]
	if !ok {
		return false
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return false
	}
	var got proof.RelationshipRef
	return json.Unmarshal(raw, &got) == nil && sameRef(got, want)
}

func hasRef(refs []proof.RelationshipRef, want proof.RelationshipRef) bool {
	for _, ref := range refs {
		if sameRef(ref, want) {
			return true
		}
	}
	return false
}

func sameRef(left, right proof.RelationshipRef) bool {
	return left.Kind == right.Kind && left.ID == right.ID && left.Digest == right.Digest && left.SchemaID == right.SchemaID && left.SchemaVersion == right.SchemaVersion && left.SourceProduct == right.SourceProduct
}

func refKey(ref proof.RelationshipRef) string {
	return strings.Join([]string{ref.Kind, ref.ID, ref.Digest, ref.SchemaID, ref.SchemaVersion, ref.SourceProduct}, "|")
}
