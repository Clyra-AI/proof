//go:build scenario

package scenarios_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/internal/testutil"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type expectedInput struct {
	File     string `yaml:"file"`
	ExitCode int    `yaml:"exit_code"`
}

type expectedScenario struct {
	Verify        string          `yaml:"verify"`
	Count         int             `yaml:"count"`
	Chain         string          `yaml:"chain"`
	BreakPoint    int             `yaml:"break_point"`
	Sign          string          `yaml:"sign"`
	Algorithm     string          `yaml:"algorithm"`
	Total         int             `yaml:"total"`
	Sources       []string        `yaml:"sources"`
	InvalidInputs []expectedInput `yaml:"invalid_inputs"`
}

func TestScenarios(t *testing.T) {
	root := testutil.RepoRoot(t)
	scenarioDir := filepath.Join(root, "scenarios", "proof")

	entries, err := os.ReadDir(scenarioDir)
	if err != nil {
		t.Fatalf("read scenario dir: %v", err)
	}

	binary := testutil.BuildBinary(t, root)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join(scenarioDir, entry.Name())
			runScenario(t, binary, dir)
		})
	}
}

func runScenario(t *testing.T, binary, dir string) {
	t.Helper()
	expected := loadExpected(t, filepath.Join(dir, "expected.yaml"))
	name := filepath.Base(dir)

	switch name {
	case "chain-round-trip":
		require.Equal(t, "pass", expected.Verify)
		require.Equal(t, "intact", expected.Chain)
		out, code := runProof(binary, "verify", dir)
		require.Equal(t, 0, code, out)
		require.Contains(t, out, "Chain intact")
		require.Contains(t, out, strconv.Itoa(expected.Count)+" records")

	case "compiled-action-chain-round-trip":
		require.Equal(t, "pass", expected.Verify)
		require.Equal(t, "intact", expected.Chain)
		out, code := runProof(binary, "verify", dir)
		require.Equal(t, 0, code, out)
		require.Contains(t, out, "Chain intact")
		require.Contains(t, out, strconv.Itoa(expected.Count)+" records")

	case "chain-tamper-detection":
		require.Equal(t, "fail", expected.Verify)
		tempDir := t.TempDir()
		copyFile(t, filepath.Join(dir, "tamper-record-5.jsonl"), filepath.Join(tempDir, "records.jsonl"))
		out, code := runProof(binary, "verify", tempDir)
		require.Equal(t, 2, code, out)
		require.Contains(t, out, "chain verification failed at index")
		if expected.BreakPoint > 0 {
			re := regexp.MustCompile(`index ([0-9]+)`)
			match := re.FindStringSubmatch(out)
			require.Len(t, match, 2, "missing break index in output: %s", out)
			index, err := strconv.Atoi(match[1])
			require.NoError(t, err)
			require.Equal(t, expected.BreakPoint, index+1)
		}

	case "signing-verify-round-trip":
		require.Equal(t, "success", expected.Sign)
		require.Equal(t, "pass", expected.Verify)
		require.Equal(t, "ed25519", expected.Algorithm)
		recordPath := filepath.Join(dir, "input-record.json")
		r, err := proof.ReadRecord(recordPath)
		require.NoError(t, err)
		key, err := proof.GenerateSigningKey()
		require.NoError(t, err)
		_, err = proof.Sign(r, key)
		require.NoError(t, err)
		require.NotEmpty(t, r.Integrity.SigningKeyID)
		require.True(t, strings.HasPrefix(r.Integrity.Signature, "base64:"))
		signedPath := filepath.Join(t.TempDir(), "signed-record.json")
		require.NoError(t, proof.WriteRecord(signedPath, r))
		out, code := runProof(binary, "verify", "--signatures", "--public-key", hex.EncodeToString(key.Public), signedPath)
		require.Equal(t, 0, code, out)
		require.Contains(t, out, "Record verified")

	case "schema-validation-reject":
		require.NotEmpty(t, expected.InvalidInputs)
		for _, tc := range expected.InvalidInputs {
			out, code := runProof(binary, "verify", filepath.Join(dir, tc.File))
			require.Equalf(t, tc.ExitCode, code, "file=%s output=%s", tc.File, out)
		}

	case "cross-product-mixed-chain":
		require.Equal(t, "pass", expected.Verify)
		out, code := runProof(binary, "verify", dir)
		require.Equal(t, 0, code, out)
		require.Contains(t, out, "Chain intact")
		require.Contains(t, out, strconv.Itoa(expected.Total)+" records")
		foundSources := readSources(t,
			filepath.Join(dir, "axym-records.jsonl"),
			filepath.Join(dir, "gait-records.jsonl"),
			filepath.Join(dir, "wrkr-records.jsonl"),
		)
		for _, source := range expected.Sources {
			_, ok := foundSources[source]
			require.Truef(t, ok, "expected source %s not present", source)
		}

	case "action-contract-lifecycle-conformance":
		require.Equal(t, "pass", expected.Verify)
		out, code := runProof(binary, "verify", dir)
		require.Equal(t, 0, code, out)
		require.Contains(t, out, "Chain intact")
		require.Contains(t, out, strconv.Itoa(expected.Total)+" records")
		repeated, repeatedCode := runProof(binary, "verify", dir)
		require.Equal(t, code, repeatedCode)
		require.Equal(t, out, repeated)
		records := readJSONLRecords(t, filepath.Join(dir, "records.jsonl"))
		require.Len(t, records, expected.Total)
		require.Equal(t, []string{"wrkr", "gait", "axym"}, []string{records[0].Source, records[1].Source, records[2].Source})
		require.Equal(t, []string{"scan_finding", "test_result", "risk_assessment"}, []string{records[0].RecordType, records[1].RecordType, records[2].RecordType})
		require.False(t, records[0].Controls.PermissionsEnforced)
		gaitResult := records[1].Event
		require.Equal(t, "gait_lifecycle_conformance", gaitResult["test_name"])
		require.Equal(t, "gait", gaitResult["producer"])
		require.Equal(t, "passed", gaitResult["status"])
		require.Equal(t, false, gaitResult["authoritative_success"])
		require.Equal(t, true, gaitResult["gait_fixture_expected_authoritative_success"])
		require.Equal(t, "succeeded", gaitResult["gait_execution"])
		require.Equal(t, "validated", gaitResult["gait_effect"])
		require.Equal(t, "completed", gaitResult["containment_status"])
		expectedSourceDigests := []string{"sha256:fcb0085b5af73b8a42aa09c25c09f6510d4eb39b8c06a0eb4e16bcbded4fffa2"}
		expectedDerivedDigests := []string{
			"sha256:16eba08f5e0d07d87311a873bc34d61134cdc65f55caa6c5545c59a5094d01f1",
			"sha256:1b4c0014496970235536a0ff5524630a8a09fa3fe436dc988ccc1ce150299796",
			"sha256:1ca2ddf402ec82c40c669ea8c96df8a8cbe0e01502119f0f158a217360e6d5a3",
			"sha256:2175abc2005cd520280f32bb4d5fffa063e81f95d357b6ec9069fa44cd27b321",
			"sha256:238bd43efbf9567e6453a72f5680e36b11a16bccdb46d22357613819f5f8c49c",
			"sha256:2c126b9af89ef9719c325781e3b048439b0171209dd53f1324b69c442ca84873",
			"sha256:4169029f4868a9bbeb57776ea104cef9c008cea8ca3d4bd9c8aacf88bdafdff6",
			"sha256:48f30dc734a2be931d4384c9d0bc76eeb78e684a9602d7e7fc89406a406cc51d",
			"sha256:53753e5a8b409836a9d77565e0becb4bf7718c78cd2228e0aa540d8e7bf90037",
			"sha256:558793eec57b717857f9d0f02bc937b15f6cff2a069f415495dcc4cd4573a57c",
			"sha256:56341bd700fb0d357ef4d3a3280e4839d7a38802462085822d9e8a5eab7e7898",
			"sha256:63e67b832ce84478cdfa4e2280a4d8abfe8eb101d83c29ba5f418c5927116a9a",
			"sha256:68602742f8064bf50bb9fa363c21c870ce678b972ea1f891736076dc98c86471",
			"sha256:6f30424fb911e580e3c0aff3e8cc536dc423f5ca52118c7ba96cb55de7aedc56",
			"sha256:783d733f6f8dc3713a8ec5f8cbc184096029ebf054da669a3b6240bf0fa98805",
			"sha256:80a62dce6d21798114efc63fe00e60dc1341d5e159750cbc16c9393a6f849519",
			"sha256:94509c208a8751dae4512a96f2fab92fca81adbc0990e2c0db1382680973c8ab",
		}
		require.Equal(t, expectedSourceDigests, stringSlice(gaitResult["source_artifact_digests"]))
		require.Equal(t, expectedDerivedDigests, stringSlice(gaitResult["derived_evidence_digests"]))
		require.NotEmpty(t, gaitResult["evidence_refs"])
		metadata := records[1].Metadata
		require.Equal(t, "gait_lifecycle", metadata["evidence_kind"])
		require.Equal(t, false, metadata["gait_authoritative"])
		require.Equal(t, true, metadata["gait_fixture_only"])
		require.Equal(t, "verified", metadata["gait_verification_state"])
		require.Equal(t, "fixture_quarantine", metadata["gait_projection"])
		require.Equal(t, expectedSourceDigests, stringSlice(metadata["gait_source_artifact_digests"]))
		require.Equal(t, expectedDerivedDigests, stringSlice(metadata["gait_derived_evidence_digests"]))
		require.False(t, records[1].Controls.PermissionsEnforced)
		axymAssessment := records[2].Event
		require.Equal(t, "cross_product_fixture_conformance", axymAssessment["assessment"])
		require.Equal(t, "verified_fixture_only", axymAssessment["assessment_status"])
		require.Equal(t, true, axymAssessment["fixture_only"])
		require.Equal(t, false, axymAssessment["authoritative"])
		require.Equal(t, true, axymAssessment["gait_fixture_expected_authoritative_success"])
		activationRef := records[1].Event["activation_ref"].(map[string]any)
		require.Equal(t, "sha256:4aad73ff9f3c7e5a680dec3bc05684221f4770e6c47a58ed95bd7d6e1adbfe71", activationRef["digest"])
		require.Equal(t, "https://gait.dev/schemas/v1/activated-action-contract-artifact.schema.json", activationRef["schema_id"])
		require.Equal(t, "gait", activationRef["source_product"])
		require.Equal(t, "sha256:fcb0085b5af73b8a42aa09c25c09f6510d4eb39b8c06a0eb4e16bcbded4fffa2", gaitResult["source_artifact_digest"])
		manifestRaw, err := os.ReadFile(filepath.Join(dir, "provenance", "fixture-manifest.json"))
		require.NoError(t, err)
		var manifest struct {
			Axym struct {
				Commit                       string `json:"commit"`
				TranslationVersion           string `json:"translation_version"`
				LifecycleAggregateRecordID   string `json:"lifecycle_aggregate_record_id"`
				LifecycleAggregateRecordHash string `json:"lifecycle_aggregate_record_hash"`
			} `json:"axym"`
			Gait struct {
				Version                      string `json:"version"`
				Commit                       string `json:"commit"`
				FixtureManifestSHA256        string `json:"fixture_manifest_sha256"`
				LifecycleSHA256              string `json:"lifecycle_sha256"`
				ActivationSHA256             string `json:"activation_sha256"`
				FixtureOnly                  bool   `json:"fixture_only"`
				AuthoritativeSuccessExpected bool   `json:"authoritative_success_expected"`
			} `json:"gait"`
			Wrkr struct {
				Version                 string `json:"version"`
				Commit                  string `json:"commit"`
				FixtureManifestSHA256   string `json:"fixture_manifest_sha256"`
				ProposalSHA256          string `json:"proposal_sha256"`
				ProposalCanonicalDigest string `json:"proposal_canonical_digest"`
			} `json:"wrkr"`
			Records struct {
				Path         string   `json:"path"`
				Count        int      `json:"count"`
				SHA256       string   `json:"sha256"`
				RecordIDs    []string `json:"record_ids"`
				RecordHashes []string `json:"record_hashes"`
			} `json:"records"`
			EvidenceSetID             string   `json:"evidence_set_id"`
			FixtureVersion            string   `json:"fixture_version"`
			ProofCommit               string   `json:"proof_commit"`
			ProofVersion              string   `json:"proof_version"`
			RecordSchemaVersion       string   `json:"record_schema_version"`
			CorrelationProfileVersion string   `json:"correlation_profile_version"`
			FixtureOnly               bool     `json:"fixture_only"`
			Authoritative             *bool    `json:"authoritative"`
			Sources                   []string `json:"sources"`
		}
		decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
		decoder.DisallowUnknownFields()
		require.NoError(t, decoder.Decode(&manifest))
		var trailing any
		require.ErrorIs(t, decoder.Decode(&trailing), io.EOF)
		recordRaw, err := os.ReadFile(filepath.Join(dir, manifest.Records.Path))
		require.NoError(t, err)
		sum := sha256.Sum256(recordRaw)
		require.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), manifest.Records.SHA256)
		require.Equal(t, "a889ad545ddef68eaaa52edbabdbc6961e74b726", manifest.ProofCommit)
		require.Equal(t, "v0.6.1", manifest.ProofVersion)
		require.Equal(t, "1", manifest.FixtureVersion)
		require.Equal(t, "gait_lifecycle_v1:fcb0085b5af73b8a", manifest.EvidenceSetID)
		require.Equal(t, manifest.EvidenceSetID, gaitResult["evidence_set_id"])
		require.Equal(t, manifest.EvidenceSetID, axymAssessment["evidence_set_id"])
		require.Equal(t, "1.0", manifest.RecordSchemaVersion)
		require.Equal(t, "1.0", manifest.CorrelationProfileVersion)
		require.True(t, manifest.FixtureOnly)
		require.NotNil(t, manifest.Authoritative)
		require.False(t, *manifest.Authoritative)
		require.Equal(t, []string{"wrkr", "gait", "axym"}, manifest.Sources)
		require.Equal(t, len(records), manifest.Records.Count)
		require.Equal(t, "7fa4244bce22d1a4a1d0267ae05bfd01a85f7e30", manifest.Axym.Commit)
		require.Equal(t, manifest.Axym.Commit, axymAssessment["axym_commit"])
		require.Equal(t, "v1", manifest.Axym.TranslationVersion)
		require.Equal(t, records[1].RecordID, manifest.Axym.LifecycleAggregateRecordID)
		require.Equal(t, records[1].Integrity.RecordHash, manifest.Axym.LifecycleAggregateRecordHash)
		require.Equal(t, "v1.15.1", manifest.Wrkr.Version)
		require.Equal(t, "6b8db233e33f92fe502aecf250a6ddeb3c3e1497", manifest.Wrkr.Commit)
		require.Equal(t, "sha256:fe0473c17f1abc7fcadfabe041e16da3e99d01a5e8f9f5c4d4d3ffe39ae4bdba", manifest.Wrkr.FixtureManifestSHA256)
		require.Equal(t, "sha256:bfb32cdce650b2ea969059ae0816df2637f7345e70b08a67d4c23684489bf154", manifest.Wrkr.ProposalSHA256)
		require.Equal(t, "sha256:d3a371d51af5af30c4c4b8e2694b40cb16791c4e8c469bd53a483a99fb3c88cf", manifest.Wrkr.ProposalCanonicalDigest)
		require.Equal(t, manifest.Wrkr.FixtureManifestSHA256, records[0].Event["wrkr_fixture_manifest_sha256"])
		require.Equal(t, manifest.Wrkr.ProposalSHA256, records[0].Event["proposal_sha256"])
		require.Equal(t, manifest.Wrkr.ProposalCanonicalDigest, records[0].Event["proposal_canonical_digest"])
		require.Equal(t, "v1.5.0", manifest.Gait.Version)
		require.Equal(t, "10f8b91b316c30c2202a580847dfdd3509bff458", manifest.Gait.Commit)
		require.Equal(t, "sha256:b5c26f73ad82e990b7f38b6488c74bd4aa2b1ade55f898e9314251a990ae5853", manifest.Gait.FixtureManifestSHA256)
		require.Equal(t, "sha256:fcb0085b5af73b8a42aa09c25c09f6510d4eb39b8c06a0eb4e16bcbded4fffa2", manifest.Gait.LifecycleSHA256)
		require.Equal(t, "sha256:4aad73ff9f3c7e5a680dec3bc05684221f4770e6c47a58ed95bd7d6e1adbfe71", manifest.Gait.ActivationSHA256)
		require.True(t, manifest.Gait.FixtureOnly)
		require.True(t, manifest.Gait.AuthoritativeSuccessExpected)
		require.Equal(t, manifest.Gait.Version, gaitResult["producer_version"])
		require.Equal(t, manifest.Gait.Commit, gaitResult["source_commit"])
		require.Equal(t, []string{records[0].RecordID, records[1].RecordID, records[2].RecordID}, manifest.Records.RecordIDs)
		require.Equal(t, []string{records[0].Integrity.RecordHash, records[1].Integrity.RecordHash, records[2].Integrity.RecordHash}, manifest.Records.RecordHashes)

	default:
		t.Fatalf("unsupported scenario: %s", name)
	}
}

func loadExpected(t *testing.T, path string) expectedScenario {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var expected expectedScenario
	require.NoError(t, yaml.Unmarshal(raw, &expected))
	return expected
}

func runProof(binary string, args ...string) (string, int) {
	cmd := exec.Command(binary, args...) // #nosec G204 -- test harness executes fixed binary with fixture args.
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return string(out), 1
	}
	return string(out), exitErr.ExitCode()
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	require.NoError(t, err)
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()
	_, err = io.Copy(out, in)
	require.NoError(t, err)
}

func readSources(t *testing.T, paths ...string) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	for _, path := range paths {
		f, err := os.Open(path)
		require.NoError(t, err)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var record proof.Record
			require.NoError(t, json.Unmarshal([]byte(line), &record))
			out[record.Source] = struct{}{}
		}
		require.NoError(t, scanner.Err())
		_ = f.Close()
	}
	return out
}

func readJSONLRecords(t *testing.T, path string) []proof.Record {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	records := []proof.Record{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var record proof.Record
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &record))
		records = append(records, record)
	}
	require.NoError(t, scanner.Err())
	return records
}

func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			return nil
		}
		out = append(out, text)
	}
	return out
}
