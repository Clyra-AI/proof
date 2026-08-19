package record

import (
	"encoding/json"
	"testing"

	coreschema "github.com/Clyra-AI/proof/core/schema"
	"github.com/stretchr/testify/require"
)

func TestControlContainmentTelemetryIdentifierOnlyAndCanonical(t *testing.T) {
	p := &ControlContainmentTelemetryProfile{
		ProfileVersion: ControlContainmentTelemetryProfileVersion,
		EventRef:       &RelationshipRef{Kind: "event", ID: "event:1"},
		TraceID:        "0123456789abcdef0123456789abcdef",
		SpanID:         "0123456789abcdef",
		ParentSpanID:   "fedcba9876543210",
		BindingMode:    BindingModeIdentifierOnly,
	}
	first, err := p.CanonicalJSON()
	require.NoError(t, err)
	second, err := p.CanonicalJSON()
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Contains(t, string(first), `"binding_mode":"identifier_only"`)
	require.NoError(t, coreschema.ValidateAgainstSchema(first, "v1/control-containment-telemetry-v1.schema.json"))
	require.NoError(t, ValidateControlContainmentTelemetryProfile(p))
	require.NoError(t, ValidateControlContainmentTelemetry(p))
	canonical, err := CanonicalizeControlContainmentTelemetry(p)
	require.NoError(t, err)
	require.Equal(t, first, canonical)
}

func TestControlContainmentTelemetryPreservesRelationshipExtras(t *testing.T) {
	p := &ControlContainmentTelemetryProfile{
		ProfileVersion: ControlContainmentTelemetryProfileVersion,
		EventRef: &RelationshipRef{Kind: "event", ID: "event:1", Extra: map[string]json.RawMessage{
			"vendor_context": json.RawMessage(`{"tenant":"demo"}`),
		}},
		BindingMode: BindingModeIdentifierOnly,
	}
	raw, err := p.CanonicalJSON()
	require.NoError(t, err)
	require.NoError(t, coreschema.ValidateAgainstSchema(raw, "v1/control-containment-telemetry-v1.schema.json"))
	require.Contains(t, string(raw), "vendor_context")
}

func TestControlContainmentTelemetryDigestBinding(t *testing.T) {
	p := &ControlContainmentTelemetryProfile{
		ProfileVersion: ControlContainmentTelemetryProfileVersion,
		ProofRef:       &RelationshipRef{Kind: "proof", ID: "proof:1", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		ContentDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		BindingMode:    BindingModeDigestBound,
	}
	require.NoError(t, p.Validate())

	withoutDigest := *p
	withoutDigest.ProofRef = &RelationshipRef{Kind: "proof", ID: "proof:1"}
	withoutDigest.ContentDigest = ""
	require.ErrorContains(t, withoutDigest.Validate(), "require a content or reference digest")

	identifier := *p
	identifier.BindingMode = BindingModeIdentifierOnly
	require.ErrorContains(t, identifier.Validate(), "cannot carry digest bindings")
}

func TestControlContainmentTelemetryRejectsInvalidOTelIdentifiers(t *testing.T) {
	missing := &ControlContainmentTelemetryProfile{BindingMode: BindingModeIdentifierOnly}
	require.ErrorContains(t, missing.Validate(), "profile_version is required")
	p := &ControlContainmentTelemetryProfile{ProfileVersion: "1.0", TraceID: "00000000000000000000000000000000", BindingMode: BindingModeIdentifierOnly}
	require.ErrorContains(t, p.Validate(), "trace_id")
	p.TraceID = "ABCDEF0123456789ABCDEF0123456789"
	require.ErrorContains(t, p.Validate(), "trace_id")
	p.TraceID = "0123456789abcdef0123456789abcdef"
	p.SpanID = "0000000000000000"
	require.ErrorContains(t, p.Validate(), "span_id")
	p.SpanID = "0123456789abcdef"
	p.ParentSpanID = "0000000000000000"
	require.ErrorContains(t, p.Validate(), "parent_span_id")
	p.ParentSpanID = "0123456789abcdef"
	p.ProfileVersion = "2"
	require.ErrorContains(t, p.Validate(), "unsupported profile version")
	p.ProfileVersion = "1.0"
	p.BindingMode = "other"
	require.ErrorContains(t, p.Validate(), "unsupported binding mode")
	p.BindingMode = BindingModeIdentifierOnly
	p.ContentDigest = "not-a-digest"
	require.ErrorContains(t, p.Validate(), "identifier_only")
	p.ContentDigest = ""
	p.EventRef = &RelationshipRef{Kind: "event", ID: ""}
	require.ErrorContains(t, p.Validate(), "must contain kind and id")
	p.EventRef = &RelationshipRef{Kind: "event", ID: "event:1", Digest: "bad"}
	p.BindingMode = BindingModeDigestBound
	require.ErrorContains(t, p.Validate(), "digest must be a SHA-256")
	p.BindingMode = BindingModeIdentifierOnly
	p.EventRef = nil
	p.Redaction = &RedactionMetadata{Applied: true, Fields: []string{"value", "value"}}
	require.ErrorContains(t, p.Validate(), "duplicated")
}

func TestControlContainmentTelemetrySchemaRejectsBadDigestAndMode(t *testing.T) {
	valid := map[string]any{
		"profile_version": "1.0",
		"binding_mode":    "identifier_only",
		"event_ref":       map[string]any{"kind": "event", "id": "event:1"},
	}
	raw, err := json.Marshal(valid)
	require.NoError(t, err)
	require.NoError(t, coreschema.ValidateAgainstSchema(raw, "v1/control-containment-telemetry-v1.schema.json"))
	valid["binding_mode"] = "other"
	raw, err = json.Marshal(valid)
	require.NoError(t, err)
	require.Error(t, coreschema.ValidateAgainstSchema(raw, "v1/control-containment-telemetry-v1.schema.json"))
	valid["binding_mode"] = "digest_bound"
	valid["content_digest"] = "sha256:not-a-digest"
	raw, err = json.Marshal(valid)
	require.NoError(t, err)
	require.Error(t, coreschema.ValidateAgainstSchema(raw, "v1/control-containment-telemetry-v1.schema.json"))
	valid["binding_mode"] = "identifier_only"
	valid["content_digest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	raw, err = json.Marshal(valid)
	require.NoError(t, err)
	require.Error(t, coreschema.ValidateAgainstSchema(raw, "v1/control-containment-telemetry-v1.schema.json"))
	delete(valid, "content_digest")
	valid["binding_mode"] = "digest_bound"
	raw, err = json.Marshal(valid)
	require.NoError(t, err)
	require.Error(t, coreschema.ValidateAgainstSchema(raw, "v1/control-containment-telemetry-v1.schema.json"))
}

func TestControlContainmentTelemetrySchemaRejectsZeroIDsAndMatchesAlias(t *testing.T) {
	invalid := map[string]any{
		"profile_version": "1.0",
		"binding_mode":    BindingModeIdentifierOnly,
		"trace_id":        "00000000000000000000000000000000",
		"event_ref":       map[string]any{"kind": "event", "id": "event:1"},
	}
	raw, err := json.Marshal(invalid)
	require.NoError(t, err)
	require.Error(t, coreschema.ValidateAgainstSchema(raw, "v1/control-containment-telemetry-v1.schema.json"))
	require.Error(t, coreschema.ValidateAgainstSchema(raw, "v1/control-containment-telemetry-profile-v1.schema.json"))

	invalid["trace_id"] = "0123456789abcdef0123456789abcdef"
	invalid["redaction"] = map[string]any{"applied": true, "reason": ""}
	raw, err = json.Marshal(invalid)
	require.NoError(t, err)
	require.Error(t, coreschema.ValidateAgainstSchema(raw, "v1/control-containment-telemetry-v1.schema.json"))

	uppercase := &ControlContainmentTelemetryProfile{ProfileVersion: "1.0", BindingMode: BindingModeDigestBound, ContentDigest: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	require.ErrorContains(t, uppercase.Validate(), "SHA-256")

	badMetadata := &ControlContainmentTelemetryProfile{ProfileVersion: "1.0", BindingMode: BindingModeIdentifierOnly, EventRef: &RelationshipRef{Kind: "event", ID: "event:1", SchemaID: " "}}
	require.ErrorContains(t, badMetadata.Validate(), "schema_id")
}

func TestControlContainmentTelemetryValidationErrorsUseFixedReferenceOrder(t *testing.T) {
	p := &ControlContainmentTelemetryProfile{
		ProfileVersion: "1.0", BindingMode: BindingModeIdentifierOnly,
		ProofRef: &RelationshipRef{Kind: "", ID: ""},
		EventRef: &RelationshipRef{Kind: "", ID: ""},
	}
	first := p.Validate()
	require.Error(t, first)
	for i := 0; i < 20; i++ {
		require.EqualError(t, p.Validate(), first.Error())
	}
}
