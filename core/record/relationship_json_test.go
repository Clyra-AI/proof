package record

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRelationshipRefJSONRoundTripPreservesExtras(t *testing.T) {
	raw := []byte(`{"kind":"agent","id":"agent:a","future":"x"}`)
	var ref RelationshipRef
	require.NoError(t, json.Unmarshal(raw, &ref))
	require.Equal(t, "agent", ref.Kind)
	require.Equal(t, "agent:a", ref.ID)
	require.Equal(t, `"x"`, string(ref.Extra["future"]))

	ref.Extra["kind"] = json.RawMessage(`"ignored"`)
	out, err := json.Marshal(ref)
	require.NoError(t, err)

	var obj map[string]any
	require.NoError(t, json.Unmarshal(out, &obj))
	require.Equal(t, "agent", obj["kind"])
	require.Equal(t, "agent:a", obj["id"])
	require.Equal(t, "x", obj["future"])
}

func TestRelationshipEdgeJSONRoundTripPreservesExtras(t *testing.T) {
	raw := []byte(`{
	  "kind":"calls",
	  "from":{"kind":"agent","id":"agent:a","from_extra":"z"},
	  "to":{"kind":"tool","id":"tool:b","to_extra":"q"},
	  "edge_extra":{"enabled":true}
	}`)
	var edge RelationshipEdge
	require.NoError(t, json.Unmarshal(raw, &edge))
	require.Equal(t, "calls", edge.Kind)
	require.Equal(t, `"z"`, string(edge.From.Extra["from_extra"]))
	require.Equal(t, `"q"`, string(edge.To.Extra["to_extra"]))
	require.Equal(t, `{"enabled":true}`, string(edge.Extra["edge_extra"]))

	out, err := json.Marshal(edge)
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(out, &obj))
	require.Contains(t, obj, "edge_extra")
}

func TestAgentChainHopJSONRoundTripPreservesExtras(t *testing.T) {
	raw := []byte(`{"identity":"agent:a","role":"requester","future":"x"}`)
	var hop AgentChainHop
	require.NoError(t, json.Unmarshal(raw, &hop))
	require.Equal(t, "agent:a", hop.Identity)
	require.Equal(t, "requester", hop.Role)
	require.Equal(t, `"x"`, string(hop.Extra["future"]))

	out, err := json.Marshal(hop)
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(out, &obj))
	require.Equal(t, "x", obj["future"])
}

func TestPolicyRefJSONRoundTripPreservesExtras(t *testing.T) {
	raw := []byte(`{
	  "policy_id":"p1",
	  "policy_version":"v2",
	  "policy_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	  "matched_rule_ids":["r1"],
	  "future":{"k":"v"}
	}`)
	var policy PolicyRef
	require.NoError(t, json.Unmarshal(raw, &policy))
	require.Equal(t, "p1", policy.PolicyID)
	require.Equal(t, "v2", policy.PolicyVersion)
	require.Equal(t, `{"k":"v"}`, string(policy.Extra["future"]))

	out, err := json.Marshal(policy)
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(out, &obj))
	require.Contains(t, obj, "future")
}

func TestAgentLineageHopJSONRoundTripPreservesExtras(t *testing.T) {
	raw := []byte(`{
	  "agent_id":"agent:a",
	  "delegated_by":"agent:b",
	  "delegation_record_id":"prf-1",
	  "future":"x"
	}`)
	var hop AgentLineageHop
	require.NoError(t, json.Unmarshal(raw, &hop))
	require.Equal(t, "agent:a", hop.AgentID)
	require.Equal(t, `"x"`, string(hop.Extra["future"]))

	out, err := json.Marshal(hop)
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(out, &obj))
	require.Equal(t, "x", obj["future"])
}

func TestRelationshipJSONRoundTripAndInvalidInput(t *testing.T) {
	raw := []byte(`{
	  "parent_ref":{"kind":"trace","id":"trace-1","ctx":"alpha"},
	  "entity_refs":[{"kind":"agent","id":"agent:a","tag":"x"}],
	  "policy_ref":{"policy_id":"p1","future":"k"},
	  "agent_chain":[{"identity":"agent:a","role":"delegator","meta":"m"}],
	  "edges":[{"kind":"calls","from":{"kind":"agent","id":"agent:a"},"to":{"kind":"tool","id":"tool:b"},"note":"n"}],
	  "agent_lineage":[{"agent_id":"agent:a","trace":"t"}],
	  "future_field":{"enabled":true}
	}`)
	var rel Relationship
	require.NoError(t, json.Unmarshal(raw, &rel))
	require.Equal(t, `{"enabled":true}`, string(rel.Extra["future_field"]))
	require.Equal(t, `"alpha"`, string(rel.ParentRef.Extra["ctx"]))

	out, err := json.Marshal(rel)
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(out, &obj))
	require.Contains(t, obj, "future_field")

	var bad Relationship
	require.Error(t, json.Unmarshal([]byte("{"), &bad))
}
