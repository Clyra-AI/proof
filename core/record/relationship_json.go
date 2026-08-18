package record

import "encoding/json"

func (r Relationship) MarshalJSON() ([]byte, error) {
	out := map[string]any{}
	if r.ParentRef != nil {
		out["parent_ref"] = r.ParentRef
	}
	if len(r.EntityRefs) > 0 {
		out["entity_refs"] = r.EntityRefs
	}
	if r.PolicyRef != nil {
		out["policy_ref"] = r.PolicyRef
	}
	if len(r.AgentChain) > 0 {
		out["agent_chain"] = r.AgentChain
	}
	if len(r.Edges) > 0 {
		out["edges"] = r.Edges
	}
	if r.ParentRecordID != "" {
		out["parent_record_id"] = r.ParentRecordID
	}
	if len(r.RelatedRecordIDs) > 0 {
		out["related_record_ids"] = r.RelatedRecordIDs
	}
	if len(r.RelatedEntityIDs) > 0 {
		out["related_entity_ids"] = r.RelatedEntityIDs
	}
	if len(r.AgentLineage) > 0 {
		out["agent_lineage"] = r.AgentLineage
	}
	mergeExtraRaw(out, r.Extra)
	return json.Marshal(out)
}

func (r *Relationship) UnmarshalJSON(data []byte) error {
	type alias struct {
		ParentRef        *RelationshipRef   `json:"parent_ref,omitempty"`
		EntityRefs       []RelationshipRef  `json:"entity_refs,omitempty"`
		PolicyRef        *PolicyRef         `json:"policy_ref,omitempty"`
		AgentChain       []AgentChainHop    `json:"agent_chain,omitempty"`
		Edges            []RelationshipEdge `json:"edges,omitempty"`
		ParentRecordID   string             `json:"parent_record_id,omitempty"`
		RelatedRecordIDs []string           `json:"related_record_ids,omitempty"`
		RelatedEntityIDs []string           `json:"related_entity_ids,omitempty"`
		AgentLineage     []AgentLineageHop  `json:"agent_lineage,omitempty"`
	}
	var v alias
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	r.ParentRef = v.ParentRef
	r.EntityRefs = v.EntityRefs
	r.PolicyRef = v.PolicyRef
	r.AgentChain = v.AgentChain
	r.Edges = v.Edges
	r.ParentRecordID = v.ParentRecordID
	r.RelatedRecordIDs = v.RelatedRecordIDs
	r.RelatedEntityIDs = v.RelatedEntityIDs
	r.AgentLineage = v.AgentLineage

	extra, err := extractExtraRaw(data,
		"parent_ref",
		"entity_refs",
		"policy_ref",
		"agent_chain",
		"edges",
		"parent_record_id",
		"related_record_ids",
		"related_entity_ids",
		"agent_lineage",
	)
	if err != nil {
		return err
	}
	r.Extra = extra
	return nil
}

func (r RelationshipRef) MarshalJSON() ([]byte, error) {
	out := map[string]any{
		"kind": r.Kind,
		"id":   r.ID,
	}
	if r.Digest != "" {
		out["digest"] = r.Digest
	}
	if r.SchemaID != "" {
		out["schema_id"] = r.SchemaID
	}
	if r.SchemaVersion != "" {
		out["schema_version"] = r.SchemaVersion
	}
	if r.SourceProduct != "" {
		out["source_product"] = r.SourceProduct
	}
	mergeExtraRaw(out, r.Extra)
	return json.Marshal(out)
}

func (r *RelationshipRef) UnmarshalJSON(data []byte) error {
	type alias struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	var v alias
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	r.Kind = v.Kind
	r.ID = v.ID
	r.Digest = ""
	r.SchemaID = ""
	r.SchemaVersion = ""
	r.SourceProduct = ""
	extra, err := extractExtraRaw(data, "kind", "id")
	if err != nil {
		return err
	}
	promoteRelationshipRefString(extra, "digest", &r.Digest, isValidDigestRef)
	promoteRelationshipRefString(extra, "schema_id", &r.SchemaID, nil)
	promoteRelationshipRefString(extra, "schema_version", &r.SchemaVersion, nil)
	promoteRelationshipRefString(extra, "source_product", &r.SourceProduct, nil)
	if len(extra) == 0 {
		extra = nil
	}
	r.Extra = extra
	return nil
}

func promoteRelationshipRefString(extra map[string]json.RawMessage, key string, dst *string, valid func(string) bool) {
	raw, ok := extra[key]
	if !ok {
		return
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" || (valid != nil && !valid(value)) {
		return
	}
	*dst = value
	delete(extra, key)
}

func (e RelationshipEdge) MarshalJSON() ([]byte, error) {
	out := map[string]any{
		"kind": e.Kind,
		"from": e.From,
		"to":   e.To,
	}
	mergeExtraRaw(out, e.Extra)
	return json.Marshal(out)
}

func (e *RelationshipEdge) UnmarshalJSON(data []byte) error {
	type alias struct {
		Kind string          `json:"kind"`
		From RelationshipRef `json:"from"`
		To   RelationshipRef `json:"to"`
	}
	var v alias
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	e.Kind = v.Kind
	e.From = v.From
	e.To = v.To
	extra, err := extractExtraRaw(data, "kind", "from", "to")
	if err != nil {
		return err
	}
	e.Extra = extra
	return nil
}

func (h AgentChainHop) MarshalJSON() ([]byte, error) {
	out := map[string]any{
		"identity": h.Identity,
		"role":     h.Role,
	}
	mergeExtraRaw(out, h.Extra)
	return json.Marshal(out)
}

func (h *AgentChainHop) UnmarshalJSON(data []byte) error {
	type alias struct {
		Identity string `json:"identity"`
		Role     string `json:"role"`
	}
	var v alias
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	h.Identity = v.Identity
	h.Role = v.Role
	extra, err := extractExtraRaw(data, "identity", "role")
	if err != nil {
		return err
	}
	h.Extra = extra
	return nil
}

func (p PolicyRef) MarshalJSON() ([]byte, error) {
	out := map[string]any{}
	if p.PolicyID != "" {
		out["policy_id"] = p.PolicyID
	}
	if p.PolicyVersion != "" {
		out["policy_version"] = p.PolicyVersion
	}
	if p.PolicyDigest != "" {
		out["policy_digest"] = p.PolicyDigest
	}
	if len(p.MatchedRuleIDs) > 0 {
		out["matched_rule_ids"] = p.MatchedRuleIDs
	}
	mergeExtraRaw(out, p.Extra)
	return json.Marshal(out)
}

func (p *PolicyRef) UnmarshalJSON(data []byte) error {
	type alias struct {
		PolicyID       string   `json:"policy_id,omitempty"`
		PolicyVersion  string   `json:"policy_version,omitempty"`
		PolicyDigest   string   `json:"policy_digest,omitempty"`
		MatchedRuleIDs []string `json:"matched_rule_ids,omitempty"`
	}
	var v alias
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	p.PolicyID = v.PolicyID
	p.PolicyVersion = v.PolicyVersion
	p.PolicyDigest = v.PolicyDigest
	p.MatchedRuleIDs = v.MatchedRuleIDs
	extra, err := extractExtraRaw(data, "policy_id", "policy_version", "policy_digest", "matched_rule_ids")
	if err != nil {
		return err
	}
	p.Extra = extra
	return nil
}

func (h AgentLineageHop) MarshalJSON() ([]byte, error) {
	out := map[string]any{
		"agent_id": h.AgentID,
	}
	if h.DelegatedBy != "" {
		out["delegated_by"] = h.DelegatedBy
	}
	if h.DelegationRecordID != "" {
		out["delegation_record_id"] = h.DelegationRecordID
	}
	mergeExtraRaw(out, h.Extra)
	return json.Marshal(out)
}

func (h *AgentLineageHop) UnmarshalJSON(data []byte) error {
	type alias struct {
		AgentID            string `json:"agent_id"`
		DelegatedBy        string `json:"delegated_by,omitempty"`
		DelegationRecordID string `json:"delegation_record_id,omitempty"`
	}
	var v alias
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	h.AgentID = v.AgentID
	h.DelegatedBy = v.DelegatedBy
	h.DelegationRecordID = v.DelegationRecordID
	extra, err := extractExtraRaw(data, "agent_id", "delegated_by", "delegation_record_id")
	if err != nil {
		return err
	}
	h.Extra = extra
	return nil
}

func extractExtraRaw(data []byte, knownKeys ...string) (map[string]json.RawMessage, error) {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	for i := range knownKeys {
		delete(raw, knownKeys[i])
	}
	if len(raw) == 0 {
		return nil, nil
	}
	return cloneRawMessages(raw), nil
}

func mergeExtraRaw(dst map[string]any, extra map[string]json.RawMessage) {
	for k, v := range extra {
		if _, exists := dst[k]; exists {
			continue
		}
		dst[k] = v
	}
}
