package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Clyra-AI/proof/core/canon"
	coreerr "github.com/Clyra-AI/proof/core/errors"
)

const (
	ControlContainmentTelemetryProfileVersion = "1.0"
	BindingModeIdentifierOnly                 = "identifier_only"
	BindingModeDigestBound                    = "digest_bound"
)

// ControlContainmentTelemetryProfile is a product-neutral correlation
// envelope. It records references and telemetry identifiers without claiming
// that a product enforced a policy, contained an action, or authenticated a
// telemetry exporter.
type ControlContainmentTelemetryProfile struct {
	ProfileVersion     string             `json:"profile_version"`
	EventRef           *RelationshipRef   `json:"event_ref,omitempty"`
	ActionRef          *RelationshipRef   `json:"action_ref,omitempty"`
	ContractRef        *RelationshipRef   `json:"contract_ref,omitempty"`
	RunRef             *RelationshipRef   `json:"run_ref,omitempty"`
	SessionRef         *RelationshipRef   `json:"session_ref,omitempty"`
	PolicyRef          *RelationshipRef   `json:"policy_ref,omitempty"`
	DecisionRef        *RelationshipRef   `json:"decision_ref,omitempty"`
	ProofRef           *RelationshipRef   `json:"proof_ref,omitempty"`
	CausalRef          *RelationshipRef   `json:"causal_ref,omitempty"`
	ContainmentRef     *RelationshipRef   `json:"containment_ref,omitempty"`
	BoundaryRef        *RelationshipRef   `json:"boundary_ref,omitempty"`
	RevocationRef      *RelationshipRef   `json:"revocation_ref,omitempty"`
	AcknowledgementRef *RelationshipRef   `json:"acknowledgement_ref,omitempty"`
	TraceID            string             `json:"trace_id,omitempty"`
	SpanID             string             `json:"span_id,omitempty"`
	ParentSpanID       string             `json:"parent_span_id,omitempty"`
	ContentDigest      string             `json:"content_digest,omitempty"`
	Redaction          *RedactionMetadata `json:"redaction,omitempty"`
	RedactionMetadata  *RedactionMetadata `json:"redaction_metadata,omitempty"`
	BindingMode        string             `json:"binding_mode"`
}

// ControlContainmentTelemetry is a short alias for the public profile type.
type ControlContainmentTelemetry = ControlContainmentTelemetryProfile

// ControlContainmentTelemetryRef reuses the digest-bound RelationshipRef
// contract so profile references remain interoperable with record relations.
type ControlContainmentTelemetryRef = RelationshipRef
type CorrelationRef = RelationshipRef

type RedactionMetadata struct {
	Applied bool     `json:"applied"`
	Fields  []string `json:"fields,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Method  string   `json:"method,omitempty"`
}

var (
	otelTraceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	otelSpanIDPattern  = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// Validate checks profile version, OpenTelemetry identifier shapes, digest
// syntax, and binding-mode semantics. Identifier-only mode intentionally
// carries no content binding: it proves only that identifiers were recorded.
func (p *ControlContainmentTelemetryProfile) Validate() error {
	if p == nil {
		return coreerr.New(coreerr.KindInvalidInput, "record.profile.nil", "control containment telemetry profile is nil")
	}
	if p.ProfileVersion == "" {
		return coreerr.New(coreerr.KindValidation, "record.profile.version_required", "profile_version is required", coreerr.WithField("profile_version"))
	}
	if p.ProfileVersion != "1" && p.ProfileVersion != ControlContainmentTelemetryProfileVersion {
		return coreerr.New(coreerr.KindValidation, "record.profile.version_unsupported", fmt.Sprintf("unsupported profile version: %s", p.ProfileVersion), coreerr.WithField("profile_version"))
	}
	switch p.BindingMode {
	case BindingModeIdentifierOnly:
		if p.ContentDigest != "" || profileHasReferenceDigest(p) {
			return coreerr.New(coreerr.KindValidation, "record.profile.identifier_only_digest", "identifier_only profiles cannot carry digest bindings", coreerr.WithField("binding_mode"))
		}
	case BindingModeDigestBound:
		if p.ContentDigest == "" && !profileHasReferenceDigest(p) {
			return coreerr.New(coreerr.KindValidation, "record.profile.digest_required", "digest_bound profiles require a content or reference digest", coreerr.WithField("binding_mode"))
		}
	default:
		return coreerr.New(coreerr.KindValidation, "record.profile.binding_mode_invalid", fmt.Sprintf("unsupported binding mode: %s", p.BindingMode), coreerr.WithField("binding_mode"))
	}
	if p.TraceID != "" && (!otelTraceIDPattern.MatchString(p.TraceID) || allZero(p.TraceID)) {
		return coreerr.New(coreerr.KindValidation, "record.profile.trace_id_invalid", "trace_id must be a lowercase non-zero OpenTelemetry trace identifier", coreerr.WithField("trace_id"))
	}
	if p.SpanID != "" && (!otelSpanIDPattern.MatchString(p.SpanID) || allZero(p.SpanID)) {
		return coreerr.New(coreerr.KindValidation, "record.profile.span_id_invalid", "span_id must be a lowercase non-zero OpenTelemetry span identifier", coreerr.WithField("span_id"))
	}
	if p.ParentSpanID != "" && (!otelSpanIDPattern.MatchString(p.ParentSpanID) || allZero(p.ParentSpanID)) {
		return coreerr.New(coreerr.KindValidation, "record.profile.parent_span_id_invalid", "parent_span_id must be a lowercase non-zero OpenTelemetry span identifier", coreerr.WithField("parent_span_id"))
	}
	if p.ContentDigest != "" && normalizeProfileDigest(p.ContentDigest) == "" {
		return coreerr.New(coreerr.KindValidation, "record.profile.content_digest_invalid", "content_digest must be a SHA-256 digest", coreerr.WithField("content_digest"))
	}
	for field, ref := range p.references() {
		if ref == nil {
			continue
		}
		if strings.TrimSpace(ref.Kind) == "" || strings.TrimSpace(ref.ID) == "" {
			return coreerr.New(coreerr.KindValidation, "record.profile.reference_invalid", fmt.Sprintf("%s must contain kind and id", field), coreerr.WithField(field))
		}
		if ref.Digest != "" && normalizeProfileDigest(ref.Digest) == "" {
			return coreerr.New(coreerr.KindValidation, "record.profile.reference_digest_invalid", fmt.Sprintf("%s digest must be a SHA-256 digest", field), coreerr.WithField(field))
		}
	}
	for _, redaction := range []*RedactionMetadata{p.Redaction, p.RedactionMetadata} {
		if redaction == nil {
			continue
		}
		seenFields := make(map[string]struct{}, len(redaction.Fields))
		for i, field := range redaction.Fields {
			field = strings.TrimSpace(field)
			if field == "" {
				return coreerr.New(coreerr.KindValidation, "record.profile.redaction_field_invalid", fmt.Sprintf("redaction field %d is empty", i), coreerr.WithField("redaction.fields"))
			}
			if _, seen := seenFields[field]; seen {
				return coreerr.New(coreerr.KindValidation, "record.profile.redaction_field_duplicate", fmt.Sprintf("redaction field %d is duplicated", i), coreerr.WithField("redaction.fields"))
			}
			seenFields[field] = struct{}{}
		}
	}
	return nil
}

func ValidateControlContainmentTelemetryProfile(p *ControlContainmentTelemetryProfile) error {
	return p.Validate()
}

func ValidateControlContainmentTelemetry(p *ControlContainmentTelemetryProfile) error {
	return p.Validate()
}

// CanonicalJSON validates and RFC 8785 canonicalizes the profile.
func (p *ControlContainmentTelemetryProfile) CanonicalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, coreerr.Wrap(coreerr.KindInternal, "record.profile.marshal_failed", "marshal control containment telemetry profile", err)
	}
	return canon.Canonicalize(raw, canon.DomainJSON)
}

func CanonicalizeControlContainmentTelemetry(p *ControlContainmentTelemetryProfile) ([]byte, error) {
	return p.CanonicalJSON()
}

func (p *ControlContainmentTelemetryProfile) references() map[string]*RelationshipRef {
	return map[string]*RelationshipRef{
		"event_ref": p.EventRef, "action_ref": p.ActionRef, "contract_ref": p.ContractRef,
		"run_ref": p.RunRef, "session_ref": p.SessionRef, "policy_ref": p.PolicyRef,
		"decision_ref": p.DecisionRef, "proof_ref": p.ProofRef, "causal_ref": p.CausalRef,
		"containment_ref": p.ContainmentRef, "boundary_ref": p.BoundaryRef,
		"revocation_ref": p.RevocationRef, "acknowledgement_ref": p.AcknowledgementRef,
	}
}

func profileHasReferenceDigest(p *ControlContainmentTelemetryProfile) bool {
	for _, ref := range p.references() {
		if ref != nil && ref.Digest != "" {
			return true
		}
	}
	return false
}

func normalizeProfileDigest(value string) string {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "sha256:")
	if len(value) != sha256.Size*2 {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	return value
}

func allZero(value string) bool {
	for _, char := range value {
		if char != '0' {
			return false
		}
	}
	return true
}
