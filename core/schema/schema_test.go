package schema

import (
	"os"
	"path/filepath"
	"testing"

	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/stretchr/testify/require"
)

func TestListRecordTypes(t *testing.T) {
	types := ListRecordTypes()
	require.GreaterOrEqual(t, len(types), 10)
}

func TestValidateRecord(t *testing.T) {
	raw := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-17T12:00:00Z",
	  "source":"axym",
	  "source_product":"axym",
	  "record_type":"decision",
	  "event":{"action":"allow"},
	  "controls":{},
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.NoError(t, ValidateRecord(raw, "decision"))
	require.Error(t, ValidateRecord(raw, "unknown_type"))
}

func TestValidateRecordTypedError(t *testing.T) {
	raw := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-17T12:00:00Z",
	  "source":"axym",
	  "source_product":"axym",
	  "record_type":"decision",
	  "event":{"action":"allow"},
	  "controls":{},
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	err := ValidateRecord(raw, "unknown_type")
	require.Error(t, err)
	typed, ok := coreerr.As(err)
	require.True(t, ok)
	require.Equal(t, coreerr.KindValidation, typed.Kind)
}

func TestValidateCustomSchema(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "custom.schema.json")
	raw := []byte(`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`)
	require.NoError(t, os.WriteFile(p, raw, 0o644))
	require.NoError(t, ValidateCustomSchema(p, raw))
}

func TestRegisterCustomTypeAndValidateRecord(t *testing.T) {
	ResetCustomTypes()
	t.Cleanup(ResetCustomTypes)

	customSchema := []byte(`{
	  "$schema":"http://json-schema.org/draft-07/schema#",
	  "type":"object",
	  "required":["record_type","event"],
	  "properties":{
	    "record_type":{"const":"vendor.custom_event"},
	    "event":{
	      "type":"object",
	      "required":["custom_value"],
	      "properties":{"custom_value":{"type":"string"}}
	    }
	  }
	}`)
	require.NoError(t, RegisterCustomType("vendor.custom_event", "custom.schema.json", customSchema))

	raw := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-17T12:00:00Z",
	  "source":"axym",
	  "source_product":"axym",
	  "record_type":"vendor.custom_event",
	  "event":{"custom_value":"ok"},
	  "controls":{},
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.NoError(t, ValidateRecord(raw, "vendor.custom_event"))

	invalid := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-17T12:00:00Z",
	  "source":"axym",
	  "source_product":"axym",
	  "record_type":"vendor.custom_event",
	  "event":{"wrong":"field"},
	  "controls":{},
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.Error(t, ValidateRecord(invalid, "vendor.custom_event"))
}

func TestRegisterCustomTypeRejectsBuiltinAndEmptyName(t *testing.T) {
	ResetCustomTypes()
	t.Cleanup(ResetCustomTypes)

	raw := []byte(`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`)
	require.Error(t, RegisterCustomType("", "custom.schema.json", raw))
	require.Error(t, RegisterCustomType("decision", "custom.schema.json", raw))
}

func TestValidateAgainstSchemaAndErrors(t *testing.T) {
	raw := []byte(`{"chain_id":"c1","created_at":"2026-02-17T12:00:00Z","record_count":0,"records":[]}`)
	require.NoError(t, ValidateAgainstSchema(raw, "v1/chain-v1.schema.json"))
	require.Error(t, ValidateAgainstSchema([]byte("{"), "v1/chain-v1.schema.json"))
	require.Error(t, ValidateAgainstSchema(raw, "v1/missing.schema.json"))
}

func TestValidateGovernanceEventSchema(t *testing.T) {
	valid := []byte(`{"event_id":"evt-1","timestamp":"2026-02-20T12:00:00Z","event_type":"tool_gate"}`)
	require.NoError(t, ValidateAgainstSchema(valid, "v1/governance-event-v1.schema.json"))

	invalid := []byte(`{"timestamp":"2026-02-20T12:00:00Z","event_type":"tool_gate"}`)
	require.Error(t, ValidateAgainstSchema(invalid, "v1/governance-event-v1.schema.json"))
}

func TestValidateDynamicToolDiscoverySchema(t *testing.T) {
	valid := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-22T12:00:00Z",
	  "source":"gait",
	  "source_product":"gait",
	  "record_type":"dynamic_tool_discovery",
	  "event":{
	    "tool_name":"filesystem.read",
	    "discovery_method":"webmcp",
	    "declared_annotations":{"readOnlyHint":true,"destructiveHint":false},
	    "policy_verdict":"allow"
	  },
	  "controls":{},
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.NoError(t, ValidateRecord(valid, "dynamic_tool_discovery"))

	invalid := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-22T12:00:00Z",
	  "source":"gait",
	  "source_product":"gait",
	  "record_type":"dynamic_tool_discovery",
	  "event":{
	    "tool_name":"filesystem.read",
	    "discovery_method":"webmcp",
	    "declared_annotations":{"readOnlyHint":true},
	    "policy_verdict":"allow"
	  },
	  "controls":{},
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.Error(t, ValidateRecord(invalid, "dynamic_tool_discovery"))
}

func TestValidateDelegationSchema(t *testing.T) {
	valid := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-22T12:00:00Z",
	  "source":"gait",
	  "source_product":"gait",
	  "record_type":"delegation",
	  "event":{
	    "delegator_id":"agent.lead",
	    "delegatee_id":"agent.specialist",
	    "delegation_scope":["tool:tool.write"],
	    "chain_depth":1,
	    "delegator_policy_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
	    "delegatee_policy_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222",
	    "verdict":"allow"
	  },
	  "controls":{},
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.NoError(t, ValidateRecord(valid, "delegation"))

	invalid := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-22T12:00:00Z",
	  "source":"gait",
	  "source_product":"gait",
	  "record_type":"delegation",
	  "event":{
	    "delegator_id":"agent.lead",
	    "delegatee_id":"agent.specialist",
	    "delegation_scope":["tool:tool.write"],
	    "chain_depth":-1,
	    "delegator_policy_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
	    "delegatee_policy_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222",
	    "verdict":"allow"
	  },
	  "controls":{},
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.Error(t, ValidateRecord(invalid, "delegation"))
}

func TestValidateRecordWithRelationship(t *testing.T) {
	valid := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-22T12:00:00Z",
	  "source":"wrkr",
	  "source_product":"wrkr",
	  "record_type":"scan_finding",
	  "event":{
	    "entity_id":"tool:filesystem.write",
	    "relationships":[{"relation":"installed_by","target_id":"user:alice","target_kind":"user"}]
	  },
	  "controls":{},
	  "relationship":{
	    "parent_ref":{"kind":"trace","id":"trace-1"},
	    "entity_refs":[
	      {"kind":"agent","id":"agent:scanner"},
	      {"kind":"resource","id":"pipeline:nightly"}
	    ],
	    "edges":[
	      {"kind":"calls","from":{"kind":"agent","id":"agent:scanner"},"to":{"kind":"tool","id":"tool:filesystem.write"}}
	    ],
	    "policy_ref":{
	      "policy_id":"security.tool-access",
	      "policy_version":"v2",
	      "policy_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	      "matched_rule_ids":["rule-1"]
	    },
	    "agent_chain":[{"identity":"agent:scanner","role":"requester"}]
	  },
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.NoError(t, ValidateRecord(valid, "scan_finding"))
}

func TestValidateRecordWithRelationshipAllowsAdditiveFields(t *testing.T) {
	valid := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-22T12:00:00Z",
	  "source":"wrkr",
	  "source_product":"wrkr",
	  "record_type":"scan_finding",
	  "event":{"entity_id":"tool:filesystem.write"},
	  "controls":{},
	  "relationship":{
	    "parent_ref":{"kind":"trace","id":"trace-1","extra":"nope"},
	    "future_field":{"enabled":true}
	  },
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.NoError(t, ValidateRecord(valid, "scan_finding"))
}

func TestValidateRecordWithLegacyRelationsAlias(t *testing.T) {
	valid := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-22T12:00:00Z",
	  "source":"wrkr",
	  "source_product":"wrkr",
	  "record_type":"scan_finding",
	  "event":{"entity_id":"tool:filesystem.write"},
	  "controls":{},
	  "relations":{
	    "parent_record_id":"prf-prev",
	    "related_entity_ids":["agent:scanner"]
	  },
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.NoError(t, ValidateRecord(valid, "scan_finding"))
}

func TestValidateRecordWithRelationshipRejectsInvalidPolicyDigest(t *testing.T) {
	invalid := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-22T12:00:00Z",
	  "source":"gait",
	  "source_product":"gait",
	  "record_type":"policy_enforcement",
	  "event":{
	    "policy_id":"security.tool-access",
	    "policy_version":"v2",
	    "policy_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	    "applied_to_entity_id":"agent:assistant",
	    "evaluation_context_id":"ctx-1",
	    "trigger_record_ids":["prf-a","prf-b"]
	  },
	  "controls":{},
	  "relationship":{
	    "policy_ref":{
	      "policy_id":"security.tool-access",
	      "policy_version":"v2",
	      "policy_digest":"sha256:not-a-valid-digest"
	    }
	  },
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.Error(t, ValidateRecord(invalid, "policy_enforcement"))
}

func TestValidatePolicyEnforcementAllowsOpaqueDigestReference(t *testing.T) {
	valid := []byte(`{
	  "record_id":"prf-test",
	  "record_version":"1.0",
	  "timestamp":"2026-02-22T12:00:00Z",
	  "source":"gait",
	  "source_product":"gait",
	  "record_type":"policy_enforcement",
	  "event":{
	    "policy_id":"security.tool-access",
	    "policy_version":"v2",
	    "policy_digest":""
	  },
	  "controls":{},
	  "integrity":{"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}`)
	require.NoError(t, ValidateRecord(valid, "policy_enforcement"))
}

func TestValidateRelationshipEnvelopeSchema(t *testing.T) {
	valid := []byte(`{
	  "parent_ref":{"kind":"trace","id":"trace-1"},
	  "entity_refs":[{"kind":"agent","id":"agent:a"}],
	  "policy_ref":{"policy_id":"p1","policy_version":"v2","policy_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","matched_rule_ids":["r1","r2"]},
	  "agent_chain":[{"identity":"agent:a","role":"requester"}],
	  "edges":[{"kind":"calls","from":{"kind":"agent","id":"agent:a"},"to":{"kind":"tool","id":"tool:b"}}]
	}`)
	require.NoError(t, ValidateAgainstSchema(valid, "v1/relationship_envelope.schema.json"))
}
