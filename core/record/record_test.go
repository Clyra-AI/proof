package record

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/stretchr/testify/require"
)

func TestNewAndHash(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, r.RecordID)
	require.Contains(t, r.Integrity.RecordHash, "sha256:")

	h, err := ComputeHash(r)
	require.NoError(t, err)
	require.Equal(t, h, r.Integrity.RecordHash)
}

func TestValidateRequiredFields(t *testing.T) {
	err := Validate(&Record{})
	require.Error(t, err)
}

func TestValidateTypedError(t *testing.T) {
	err := Validate(nil)
	require.Error(t, err)
	typed, ok := coreerr.As(err)
	require.True(t, ok)
	require.Equal(t, coreerr.KindInvalidInput, typed.Kind)
	require.Equal(t, "record.nil", typed.Code)
	require.Equal(t, "record", typed.Field)
}

func TestValidateDetailedErrors(t *testing.T) {
	err := Validate(nil)
	require.ErrorContains(t, err, "record is nil")

	base := &Record{
		RecordVersion: SchemaVersion,
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		RecordType:    "decision",
		Event:         map[string]any{"action": "allow"},
	}

	r := *base
	r.RecordVersion = ""
	require.ErrorContains(t, Validate(&r), "record_version is required")

	r = *base
	r.Timestamp = time.Time{}
	require.ErrorContains(t, Validate(&r), "timestamp is required")

	r = *base
	r.Source = ""
	require.ErrorContains(t, Validate(&r), "source is required")

	r = *base
	r.SourceProduct = ""
	require.ErrorContains(t, Validate(&r), "source_product is required")

	r = *base
	r.RecordType = ""
	require.ErrorContains(t, Validate(&r), "record_type is required")

	r = *base
	r.Event = nil
	require.ErrorContains(t, Validate(&r), "event is required")
}

func TestComputeHashNil(t *testing.T) {
	_, err := ComputeHash(nil)
	require.ErrorContains(t, err, "record is nil")
}

func TestNewDefaultsAndTrim(t *testing.T) {
	r, err := New(RecordOpts{
		Source:        "  axym  ",
		SourceProduct: "  axym  ",
		Type:          "  decision  ",
		Event:         map[string]any{"action": "allow"},
	})
	require.NoError(t, err)
	require.Equal(t, SchemaVersion, r.RecordVersion)
	require.Equal(t, "axym", r.Source)
	require.Equal(t, "axym", r.SourceProduct)
	require.Equal(t, "decision", r.RecordType)
	require.True(t, strings.HasPrefix(r.RecordID, "prf-"))
}

func TestNewMarshalErrorFromEvent(t *testing.T) {
	_, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "axym",
		SourceProduct: "axym",
		Type:          "decision",
		Event:         map[string]any{"bad": make(chan int)},
	})
	require.Error(t, err)
}

func TestClone(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "scan_finding",
		Event:         map[string]any{"id": "f1"},
		Metadata:      map[string]any{"env": "prod"},
	})
	require.NoError(t, err)
	c := Clone(r)
	c.Event["id"] = "f2"
	require.Equal(t, "f1", r.Event["id"])
}

func TestNewWithRelationshipAffectsHash(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
		Relationship: &Relationship{
			ParentRef:  &RelationshipRef{Kind: "trace", ID: "trace-1"},
			EntityRefs: []RelationshipRef{{Kind: "agent", ID: "agent:a"}, {Kind: "tool", ID: "tool:t"}},
			PolicyRef: &PolicyRef{
				PolicyID:      "prod.policy",
				PolicyVersion: "v3",
				PolicyDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	})
	require.NoError(t, err)

	originalHash := r.Integrity.RecordHash
	clone := Clone(r)
	clone.Relationship.PolicyRef.PolicyVersion = "v4"

	changedHash, err := ComputeHash(clone)
	require.NoError(t, err)
	require.NotEqual(t, originalHash, changedHash)
}

func TestCloneDeepCopiesRelationship(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "scan_finding",
		Event:         map[string]any{"id": "f1"},
		Relationship: &Relationship{
			ParentRef:  &RelationshipRef{Kind: "trace", ID: "trace-1"},
			EntityRefs: []RelationshipRef{{Kind: "agent", ID: "agent:a"}},
			PolicyRef: &PolicyRef{
				PolicyID:       "security.policy",
				PolicyVersion:  "v1",
				PolicyDigest:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				MatchedRuleIDs: []string{"rule-1"},
			},
			AgentChain: []AgentChainHop{
				{Identity: "agent:a", Role: "requester"},
			},
		},
	})
	require.NoError(t, err)

	c := Clone(r)
	c.Relationship.EntityRefs[0].ID = "agent:other"
	c.Relationship.PolicyRef.PolicyVersion = "v2"
	c.Relationship.AgentChain[0].Role = "delegate"

	require.Equal(t, "agent:a", r.Relationship.EntityRefs[0].ID)
	require.Equal(t, "v1", r.Relationship.PolicyRef.PolicyVersion)
	require.Equal(t, "requester", r.Relationship.AgentChain[0].Role)
}

func TestNewNormalizesRelationshipDeterministically(t *testing.T) {
	base := RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
	}
	first := base
	first.Relationship = &Relationship{
		EntityRefs: []RelationshipRef{
			{Kind: "Tool", ID: " tool:b "},
			{Kind: "agent", ID: "agent:a"},
			{Kind: "tool", ID: "tool:b"},
		},
		PolicyRef: &PolicyRef{
			PolicyDigest:   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			MatchedRuleIDs: []string{"rule-b", "rule-a", "rule-b"},
		},
		Edges: []RelationshipEdge{
			{Kind: "Calls", From: RelationshipRef{Kind: "agent", ID: "agent:a"}, To: RelationshipRef{Kind: "tool", ID: "tool:b"}},
			{Kind: "calls", From: RelationshipRef{Kind: "agent", ID: "agent:a"}, To: RelationshipRef{Kind: "tool", ID: "tool:b"}},
		},
	}
	second := base
	second.Relationship = &Relationship{
		EntityRefs: []RelationshipRef{
			{Kind: "tool", ID: "tool:b"},
			{Kind: "agent", ID: "agent:a"},
		},
		PolicyRef: &PolicyRef{
			PolicyDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			MatchedRuleIDs: []string{"rule-a", "rule-b"},
		},
		Edges: []RelationshipEdge{
			{Kind: "calls", From: RelationshipRef{Kind: "agent", ID: "agent:a"}, To: RelationshipRef{Kind: "tool", ID: "tool:b"}},
		},
	}

	r1, err := New(first)
	require.NoError(t, err)
	r2, err := New(second)
	require.NoError(t, err)

	require.Equal(t, r1.RecordID, r2.RecordID)
	require.Equal(t, r1.Integrity.RecordHash, r2.Integrity.RecordHash)
	require.Equal(t, []string{"rule-a", "rule-b"}, r1.Relationship.PolicyRef.MatchedRuleIDs)
}

func TestFirstRelationshipSelection(t *testing.T) {
	primary := &Relationship{ParentRecordID: "primary"}
	alias := &Relations{ParentRecordID: "alias"}

	require.Equal(t, primary, firstRelationship(RecordOpts{Relationship: primary, Relations: alias}))
	require.Equal(t, alias, firstRelationship(RecordOpts{Relations: alias}))
	require.Nil(t, firstRelationship(RecordOpts{}))
}

func TestNormalizeDigestRefAndHexValidation(t *testing.T) {
	require.Equal(t, "", normalizeDigestRef(""))
	require.Equal(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", normalizeDigestRef("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	require.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", normalizeDigestRef("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	require.Equal(t, "policy-ref-v2", normalizeDigestRef("policy-ref-v2"))
	require.False(t, isLowerHexLen("nothex", 64))
	require.False(t, isLowerHexLen("abc", 64))
	require.True(t, isValidDigestRef("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	require.True(t, isValidDigestRef("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	require.False(t, isValidDigestRef(" sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
}

func TestNewNormalizesDigestBoundRelationshipRefs(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
		Relationship: &Relationship{
			EntityRefs: []RelationshipRef{
				{
					Kind:          " Vendor.Model-Card ",
					ID:            " model:alpha ",
					Digest:        " SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ",
					SchemaID:      " vendor.model-card ",
					SchemaVersion: " 2.1 ",
					SourceProduct: " vendor ",
				},
			},
			Edges: []RelationshipEdge{
				{
					Kind: " Vendor.Derived-From ",
					From: RelationshipRef{Kind: "Vendor.Model-Card", ID: "model:alpha"},
					To:   RelationshipRef{Kind: "evidence", ID: "evidence:one"},
				},
			},
		},
	})
	require.NoError(t, err)

	ref := r.Relationship.EntityRefs[0]
	require.Equal(t, "vendor.model-card", ref.Kind)
	require.Equal(t, "model:alpha", ref.ID)
	require.Equal(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ref.Digest)
	require.Equal(t, "vendor.model-card", ref.SchemaID)
	require.Equal(t, "2.1", ref.SchemaVersion)
	require.Equal(t, "vendor", ref.SourceProduct)
	require.Equal(t, "vendor.derived-from", r.Relationship.Edges[0].Kind)
}

func TestNormalizedRefsKeepsSameReferenceWithDifferentDigests(t *testing.T) {
	refs := []RelationshipRef{
		{Kind: "evidence", ID: "evidence:one", Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{Kind: "evidence", ID: "evidence:one", Digest: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{Kind: "evidence", ID: "evidence:one", Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}

	normalized := normalizedRefs(refs)
	require.Len(t, normalized, 2)
	require.Equal(t, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", normalized[0].Digest)
	require.Equal(t, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", normalized[1].Digest)
}

func TestRelationshipRefStableKeyCannotCollideOnFieldDelimiters(t *testing.T) {
	base := RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "proof",
		SourceProduct: "proof",
		Type:          "decision",
		Event:         map[string]any{"action": "allow"},
	}
	left := RelationshipRef{Kind: "vendor.entity", ID: "entity:one", SchemaID: "a\x00b", SchemaVersion: "c"}
	right := RelationshipRef{Kind: "vendor.entity", ID: "entity:one", SchemaID: "a", SchemaVersion: "b\x00c"}
	require.NotEqual(t, relationshipRefStableKey(left), relationshipRefStableKey(right))

	first := base
	first.Relationship = &Relationship{EntityRefs: []RelationshipRef{left, right}}
	second := base
	second.Relationship = &Relationship{EntityRefs: []RelationshipRef{right, left}}

	r1, err := New(first)
	require.NoError(t, err)
	r2, err := New(second)
	require.NoError(t, err)
	require.Len(t, r1.Relationship.EntityRefs, 2)
	require.Equal(t, r1.Integrity.RecordHash, r2.Integrity.RecordHash)
}

func TestValidateRelationshipKindsAndDigestsReturnsStableCodes(t *testing.T) {
	base := Record{
		RecordVersion: SchemaVersion,
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "proof",
		SourceProduct: "proof",
		RecordType:    "decision",
		Event:         map[string]any{"action": "allow"},
	}

	tests := []struct {
		name string
		rel  *Relationship
		code string
		path string
	}{
		{
			name: "invalid entity kind",
			rel:  &Relationship{EntityRefs: []RelationshipRef{{Kind: "custom_kind", ID: "x"}}},
			code: ErrorCodeRelationshipRefKindInvalid,
			path: "relationship.entity_refs[0].kind",
		},
		{
			name: "invalid edge kind",
			rel: &Relationship{Edges: []RelationshipEdge{{
				Kind: "custom_edge",
				From: RelationshipRef{Kind: "agent", ID: "a"},
				To:   RelationshipRef{Kind: "tool", ID: "b"},
			}}},
			code: ErrorCodeRelationshipEdgeKindInvalid,
			path: "relationship.edges[0].kind",
		},
		{
			name: "invalid digest",
			rel:  &Relationship{EntityRefs: []RelationshipRef{{Kind: "evidence", ID: "x", Digest: "sha256:bad"}}},
			code: ErrorCodeRelationshipRefDigestInvalid,
			path: "relationship.entity_refs[0].digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base
			r.Relationship = tt.rel
			err := Validate(&r)
			require.Error(t, err)
			typed, ok := coreerr.As(err)
			require.True(t, ok)
			require.Equal(t, coreerr.KindValidation, typed.Kind)
			require.Equal(t, tt.code, typed.Code)
			require.Equal(t, tt.path, typed.Path)
		})
	}
}

func TestValidatePreservesLegacyArbitraryEdgeEndpointKinds(t *testing.T) {
	r := &Record{
		RecordVersion: SchemaVersion,
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "proof",
		SourceProduct: "proof",
		RecordType:    "decision",
		Event:         map[string]any{"action": "allow"},
		Relationship: &Relationship{Edges: []RelationshipEdge{{
			Kind: "calls",
			From: RelationshipRef{Kind: "principal", ID: "principal:one"},
			To:   RelationshipRef{Kind: "endpoint", ID: "endpoint:one"},
		}}},
	}
	require.NoError(t, Validate(r))
}

func TestLegacyRelationshipHashRemainsStable(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		Type:          "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
		Relationship: &Relationship{
			ParentRef:  &RelationshipRef{Kind: "trace", ID: "trace-1"},
			EntityRefs: []RelationshipRef{{Kind: "agent", ID: "agent:a"}, {Kind: "tool", ID: "tool:b"}},
			Edges: []RelationshipEdge{{
				Kind: "calls",
				From: RelationshipRef{Kind: "agent", ID: "agent:a"},
				To:   RelationshipRef{Kind: "tool", ID: "tool:b"},
			}},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "sha256:26e7e8116a1fbed3b0fdef3a45c049478ca40d43c9b29a2d3f40b40376f96800", r.Integrity.RecordHash)
}

func TestUnmarshalDoesNotNormalizeAlreadyHashedRelationshipRef(t *testing.T) {
	raw := []byte(`{
	  "record_id":"prf-legacy-digest",
	  "record_version":"1.0",
	  "timestamp":"2026-02-17T12:00:00Z",
	  "source":"gait",
	  "source_product":"gait",
	  "record_type":"policy_enforcement",
	  "event":{"verdict":"allow"},
	  "controls":{},
	  "relationship":{
	    "entity_refs":[
	      {
	        "kind":"evidence",
	        "id":"evidence:legacy",
	        "digest":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	        "schema_id":"legacy.evidence",
	        "future":"preserved"
	      },
	      {
	        "kind":"evidence",
	        "id":"evidence:additive-collision",
	        "digest":null,
	        "schema_id":"",
	        "schema_version":2,
	        "source_product":{"name":"legacy"}
	      }
	    ]
	  },
	  "integrity":{"record_hash":"sha256:ae794c4d5fde13a7789228b97f5fdf6d049935bb416de62d409f298e5572a7c4"}
	}`)

	var r Record
	require.NoError(t, json.Unmarshal(raw, &r))
	require.Equal(t, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", r.Relationship.EntityRefs[0].Digest)
	require.Equal(t, `"preserved"`, string(r.Relationship.EntityRefs[0].Extra["future"]))
	legacyCollision := r.Relationship.EntityRefs[1]
	require.Empty(t, legacyCollision.Digest)
	require.Empty(t, legacyCollision.SchemaID)
	require.Empty(t, legacyCollision.SchemaVersion)
	require.Empty(t, legacyCollision.SourceProduct)
	require.Equal(t, "null", string(legacyCollision.Extra["digest"]))
	require.Equal(t, `""`, string(legacyCollision.Extra["schema_id"]))
	require.Equal(t, "2", string(legacyCollision.Extra["schema_version"]))
	require.Equal(t, `{"name":"legacy"}`, string(legacyCollision.Extra["source_product"]))

	hash, err := ComputeHash(&r)
	require.NoError(t, err)
	require.Equal(t, r.Integrity.RecordHash, hash)

	encoded, err := json.Marshal(&r)
	require.NoError(t, err)
	var roundTripped Record
	require.NoError(t, json.Unmarshal(encoded, &roundTripped))
	require.Equal(t, r.Relationship.EntityRefs[0], roundTripped.Relationship.EntityRefs[0])
	require.Equal(t, hash, mustComputeHash(t, &roundTripped))
}

func mustComputeHash(t *testing.T, r *Record) string {
	t.Helper()
	hash, err := ComputeHash(r)
	require.NoError(t, err)
	return hash
}

func TestNormalizedEdgesStableSortAndDedup(t *testing.T) {
	edges := []RelationshipEdge{
		{Kind: "calls", From: RelationshipRef{Kind: "agent", ID: "a"}, To: RelationshipRef{Kind: "tool", ID: "b"}},
		{Kind: "Calls", From: RelationshipRef{Kind: "agent", ID: "a"}, To: RelationshipRef{Kind: "tool", ID: "b"}},
		{Kind: "targets", From: RelationshipRef{Kind: "agent", ID: "a"}, To: RelationshipRef{Kind: "resource", ID: "z"}},
		{Kind: "calls", From: RelationshipRef{Kind: "agent", ID: "a"}, To: RelationshipRef{Kind: "tool", ID: "a"}},
	}
	normalized := normalizedEdges(edges)
	require.Len(t, normalized, 3)
	require.Equal(t, "calls", normalized[0].Kind)
	require.Equal(t, "a", normalized[0].To.ID)
	require.Equal(t, "calls", normalized[1].Kind)
	require.Equal(t, "b", normalized[1].To.ID)
	require.Equal(t, "targets", normalized[2].Kind)
	require.Nil(t, normalizedEdges(nil))
}

func TestNormalizedRefsKeepsDistinctAdditiveMetadata(t *testing.T) {
	refs := []RelationshipRef{
		{Kind: "agent", ID: "agent:a", Extra: map[string]json.RawMessage{"tag": json.RawMessage(`"alpha"`)}},
		{Kind: "agent", ID: "agent:a", Extra: map[string]json.RawMessage{"tag": json.RawMessage(`"beta"`)}},
		{Kind: "agent", ID: "agent:a", Extra: map[string]json.RawMessage{"tag": json.RawMessage(`"alpha"`)}},
	}
	normalized := normalizedRefs(refs)
	require.Len(t, normalized, 2)
	require.Equal(t, `"alpha"`, string(normalized[0].Extra["tag"]))
	require.Equal(t, `"beta"`, string(normalized[1].Extra["tag"]))
}

func TestNormalizedEdgesKeepsDistinctAdditiveMetadata(t *testing.T) {
	edges := []RelationshipEdge{
		{
			Kind: "calls",
			From: RelationshipRef{Kind: "agent", ID: "agent:a", Extra: map[string]json.RawMessage{"ctx": json.RawMessage(`"a"`)}},
			To:   RelationshipRef{Kind: "tool", ID: "tool:x"},
			Extra: map[string]json.RawMessage{
				"label": json.RawMessage(`"first"`),
			},
		},
		{
			Kind: "calls",
			From: RelationshipRef{Kind: "agent", ID: "agent:a", Extra: map[string]json.RawMessage{"ctx": json.RawMessage(`"b"`)}},
			To:   RelationshipRef{Kind: "tool", ID: "tool:x"},
			Extra: map[string]json.RawMessage{
				"label": json.RawMessage(`"second"`),
			},
		},
		{
			Kind: "calls",
			From: RelationshipRef{Kind: "agent", ID: "agent:a", Extra: map[string]json.RawMessage{"ctx": json.RawMessage(`"a"`)}},
			To:   RelationshipRef{Kind: "tool", ID: "tool:x"},
			Extra: map[string]json.RawMessage{
				"label": json.RawMessage(`"first"`),
			},
		},
	}
	normalized := normalizedEdges(edges)
	require.Len(t, normalized, 2)
	require.Equal(t, `"a"`, string(normalized[0].From.Extra["ctx"]))
	require.Equal(t, `"first"`, string(normalized[0].Extra["label"]))
	require.Equal(t, `"b"`, string(normalized[1].From.Extra["ctx"]))
	require.Equal(t, `"second"`, string(normalized[1].Extra["label"]))
}

func TestComputeHashIncludesRelationshipAndLegacyAlias(t *testing.T) {
	base := &Record{
		RecordID:      "prf-test",
		RecordVersion: SchemaVersion,
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "gait",
		SourceProduct: "gait",
		RecordType:    "policy_enforcement",
		Event:         map[string]any{"verdict": "allow"},
	}
	r1 := Clone(base)
	r1.Relationship = &Relationship{ParentRef: &RelationshipRef{Kind: "trace", ID: "t1"}}
	h1, err := ComputeHash(r1)
	require.NoError(t, err)

	r2 := Clone(base)
	r2.Relations = &Relations{ParentRecordID: "prf-prev"}
	h2, err := ComputeHash(r2)
	require.NoError(t, err)

	r3 := Clone(base)
	r3.Relationship = &Relationship{ParentRef: &RelationshipRef{Kind: "trace", ID: "t1"}}
	r3.Relations = &Relations{ParentRecordID: "prf-prev"}
	h3, err := ComputeHash(r3)
	require.NoError(t, err)

	require.NotEqual(t, h1, h2)
	require.NotEqual(t, h2, h3)
}

func TestComputeHashIncludesAdditiveRelationshipFields(t *testing.T) {
	raw := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-17T12:00:00Z",
	  "source":"gait",
	  "source_product":"gait",
	  "record_type":"policy_enforcement",
	  "event":{"verdict":"allow"},
	  "controls":{},
	  "relationship":{
	    "parent_ref":{"kind":"trace","id":"t1","ctx":"alpha"},
	    "future_field":{"enabled":true}
	  },
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	var rec Record
	require.NoError(t, json.Unmarshal(raw, &rec))

	h1, err := ComputeHash(&rec)
	require.NoError(t, err)

	tampered := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-17T12:00:00Z",
	  "source":"gait",
	  "source_product":"gait",
	  "record_type":"policy_enforcement",
	  "event":{"verdict":"allow"},
	  "controls":{},
	  "relationship":{
	    "parent_ref":{"kind":"trace","id":"t1","ctx":"beta"},
	    "future_field":{"enabled":true}
	  },
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	var recTampered Record
	require.NoError(t, json.Unmarshal(tampered, &recTampered))

	h2, err := ComputeHash(&recTampered)
	require.NoError(t, err)
	require.NotEqual(t, h1, h2)
}

func TestCloneDeepCopiesRelationshipExtras(t *testing.T) {
	r, err := New(RecordOpts{
		Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "scan_finding",
		Event:         map[string]any{"id": "f1"},
		Relationship: &Relationship{
			ParentRef: &RelationshipRef{
				Kind:  "trace",
				ID:    "trace-1",
				Extra: map[string]json.RawMessage{"ctx": json.RawMessage(`"alpha"`)},
			},
			Extra: map[string]json.RawMessage{"future": json.RawMessage(`{"enabled":true}`)},
		},
	})
	require.NoError(t, err)

	c := Clone(r)
	c.Relationship.Extra["future"] = json.RawMessage(`{"enabled":false}`)
	c.Relationship.ParentRef.Extra["ctx"] = json.RawMessage(`"beta"`)

	require.Equal(t, `{"enabled":true}`, string(r.Relationship.Extra["future"]))
	require.Equal(t, `"alpha"`, string(r.Relationship.ParentRef.Extra["ctx"]))
}
