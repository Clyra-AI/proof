package record

import "time"

type Record struct {
	RecordID      string         `json:"record_id"`
	RecordVersion string         `json:"record_version"`
	Timestamp     time.Time      `json:"timestamp"`
	Source        string         `json:"source"`
	SourceProduct string         `json:"source_product"`
	AgentID       string         `json:"agent_id,omitempty"`
	RecordType    string         `json:"record_type"`
	Event         map[string]any `json:"event"`
	Controls      Controls       `json:"controls"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	Relations     *Relations     `json:"relations,omitempty"`
	Integrity     Integrity      `json:"integrity"`
}

type Relations struct {
	ParentRecordID   string            `json:"parent_record_id,omitempty"`
	RelatedRecordIDs []string          `json:"related_record_ids,omitempty"`
	RelatedEntityIDs []string          `json:"related_entity_ids,omitempty"`
	PolicyRef        *PolicyRef        `json:"policy_ref,omitempty"`
	AgentLineage     []AgentLineageHop `json:"agent_lineage,omitempty"`
}

type PolicyRef struct {
	PolicyID      string `json:"policy_id,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
	PolicyDigest  string `json:"policy_digest,omitempty"`
}

type AgentLineageHop struct {
	AgentID            string `json:"agent_id"`
	DelegatedBy        string `json:"delegated_by,omitempty"`
	DelegationRecordID string `json:"delegation_record_id,omitempty"`
}

type Controls struct {
	PermissionsEnforced bool              `json:"permissions_enforced"`
	ApprovedScope       string            `json:"approved_scope,omitempty"`
	WithinScope         *bool             `json:"within_scope,omitempty"`
	GuardrailsActive    []GuardrailStatus `json:"guardrails_active,omitempty"`
	HumanOversight      *HumanOversight   `json:"human_oversight,omitempty"`
}

type GuardrailStatus struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Triggered bool   `json:"triggered"`
}

type HumanOversight struct {
	ApprovalRequired bool   `json:"approval_required"`
	LastReview       string `json:"last_review,omitempty"`
	Reviewer         string `json:"reviewer,omitempty"`
}

type Integrity struct {
	RecordHash         string `json:"record_hash"`
	PreviousRecordHash string `json:"previous_record_hash,omitempty"`
	SigningKeyID       string `json:"signing_key_id,omitempty"`
	Signature          string `json:"signature,omitempty"`
}

type RecordOpts struct {
	RecordVersion string
	Timestamp     time.Time
	Source        string
	SourceProduct string
	AgentID       string
	Type          string
	Event         map[string]any
	Controls      Controls
	Metadata      map[string]any
	Relations     *Relations
}
