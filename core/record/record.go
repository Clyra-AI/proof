package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Clyra-AI/proof/core/canon"
	coreerr "github.com/Clyra-AI/proof/core/errors"
)

const SchemaVersion = "1.0"

const (
	ErrorCodeRelationshipRefIDRequired    = "record.relationship_ref.id_required"
	ErrorCodeRelationshipRefKindInvalid   = "record.relationship_ref.kind_invalid"
	ErrorCodeRelationshipRefDigestInvalid = "record.relationship_ref.digest_invalid"
	ErrorCodeRelationshipEdgeKindInvalid  = "record.relationship_edge.kind_invalid"
)

var (
	namespacedRelationshipKindPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*)+$`)
	parentRefKinds                    = map[string]struct{}{
		"trace": {}, "run": {}, "session": {}, "intent": {}, "policy": {}, "agent": {}, "evidence": {},
	}
	entityRefKinds = map[string]struct{}{
		"agent": {}, "tool": {}, "resource": {}, "policy": {}, "run": {}, "trace": {}, "delegation": {}, "evidence": {},
	}
	edgeKinds = map[string]struct{}{
		"delegates_to": {}, "calls": {}, "governed_by": {}, "targets": {}, "derived_from": {}, "emits_evidence": {},
	}
)

func New(opts RecordOpts) (*Record, error) {
	if opts.Timestamp.IsZero() {
		opts.Timestamp = time.Now().UTC().Truncate(time.Second)
	}
	if opts.RecordVersion == "" {
		opts.RecordVersion = SchemaVersion
	}
	r := &Record{
		RecordVersion: opts.RecordVersion,
		Timestamp:     opts.Timestamp.UTC(),
		Source:        strings.TrimSpace(opts.Source),
		SourceProduct: strings.TrimSpace(opts.SourceProduct),
		AgentID:       strings.TrimSpace(opts.AgentID),
		RecordType:    strings.TrimSpace(opts.Type),
		Event:         opts.Event,
		Controls:      opts.Controls,
		Metadata:      opts.Metadata,
		Relationship:  normalizeRelationship(cloneRelationship(opts.Relationship)),
		Relations:     normalizeRelationship(cloneRelationship(opts.Relations)),
		Integrity:     Integrity{},
	}
	if err := Validate(r); err != nil {
		return nil, err
	}
	id, err := deterministicID(r)
	if err != nil {
		return nil, err
	}
	r.RecordID = id
	hash, err := ComputeHash(r)
	if err != nil {
		return nil, err
	}
	r.Integrity.RecordHash = hash
	return r, nil
}

func Validate(r *Record) error {
	if r == nil {
		return coreerr.New(coreerr.KindInvalidInput, "record.nil", "record is nil", coreerr.WithField("record"))
	}
	if strings.TrimSpace(r.RecordVersion) == "" {
		return coreerr.New(coreerr.KindValidation, "record.record_version_required", "record_version is required", coreerr.WithField("record_version"))
	}
	if r.Timestamp.IsZero() {
		return coreerr.New(coreerr.KindValidation, "record.timestamp_required", "timestamp is required", coreerr.WithField("timestamp"))
	}
	if strings.TrimSpace(r.Source) == "" {
		return coreerr.New(coreerr.KindValidation, "record.source_required", "source is required", coreerr.WithField("source"))
	}
	if strings.TrimSpace(r.SourceProduct) == "" {
		return coreerr.New(coreerr.KindValidation, "record.source_product_required", "source_product is required", coreerr.WithField("source_product"))
	}
	if strings.TrimSpace(r.RecordType) == "" {
		return coreerr.New(coreerr.KindValidation, "record.record_type_required", "record_type is required", coreerr.WithField("record_type"))
	}
	if r.Event == nil {
		return coreerr.New(coreerr.KindValidation, "record.event_required", "event is required", coreerr.WithField("event"))
	}
	if err := validateRelationship(r.Relationship, "relationship"); err != nil {
		return err
	}
	if err := validateRelationship(r.Relations, "relations"); err != nil {
		return err
	}
	return nil
}

func ComputeHash(r *Record) (string, error) {
	if r == nil {
		return "", coreerr.New(coreerr.KindInvalidInput, "record.nil", "record is nil", coreerr.WithField("record"))
	}
	payload := map[string]any{
		"record_id":      r.RecordID,
		"record_version": r.RecordVersion,
		"timestamp":      r.Timestamp.UTC().Format(time.RFC3339),
		"source":         r.Source,
		"source_product": r.SourceProduct,
		"agent_id":       r.AgentID,
		"record_type":    r.RecordType,
		"event":          r.Event,
		"controls":       r.Controls,
		"metadata":       r.Metadata,
		"integrity": map[string]any{
			"previous_record_hash": r.Integrity.PreviousRecordHash,
		},
	}
	if r.Relations != nil {
		payload["relations"] = r.Relations
	}
	if r.Relationship != nil {
		payload["relationship"] = r.Relationship
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", coreerr.Wrap(coreerr.KindInternal, "record.compute_hash_marshal_payload", "marshal payload", err)
	}
	canonical, err := canon.Canonicalize(raw, canon.DomainJSON)
	if err != nil {
		return "", coreerr.Wrap(coreerr.KindInternal, "record.compute_hash_canonicalize_payload", "canonicalize payload", err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func deterministicID(r *Record) (string, error) {
	raw, err := json.Marshal(map[string]any{
		"timestamp":      r.Timestamp.UTC().Format(time.RFC3339),
		"source":         r.Source,
		"source_product": r.SourceProduct,
		"agent_id":       r.AgentID,
		"record_type":    r.RecordType,
		"event":          r.Event,
	})
	if err != nil {
		return "", coreerr.Wrap(coreerr.KindInternal, "record.deterministic_id_marshal_payload", "marshal deterministic id payload", err)
	}
	canonical, err := canon.Canonicalize(raw, canon.DomainJSON)
	if err != nil {
		return "", coreerr.Wrap(coreerr.KindInternal, "record.deterministic_id_canonicalize_payload", "canonicalize deterministic id payload", err)
	}
	sum := sha256.Sum256(canonical)
	prefix := hex.EncodeToString(sum[:])[:8]
	return fmt.Sprintf("prf-%s-%s", r.Timestamp.UTC().Format(time.RFC3339), prefix), nil
}

func Clone(r *Record) *Record {
	if r == nil {
		return nil
	}
	out := *r
	if r.Event != nil {
		out.Event = map[string]any{}
		for k, v := range r.Event {
			out.Event[k] = v
		}
	}
	if r.Metadata != nil {
		out.Metadata = map[string]any{}
		for k, v := range r.Metadata {
			out.Metadata[k] = v
		}
	}
	if r.Relations != nil {
		out.Relations = cloneRelationship(r.Relations)
	}
	if r.Relationship != nil {
		out.Relationship = cloneRelationship(r.Relationship)
	}
	return &out
}

func firstRelationship(opts RecordOpts) *Relationship {
	if opts.Relationship != nil {
		return opts.Relationship
	}
	if opts.Relations != nil {
		return opts.Relations
	}
	return nil
}

func normalizeRelationship(in *Relationship) *Relationship {
	if in == nil {
		return nil
	}
	out := *in
	out.Extra = cloneRawMessages(in.Extra)
	if in.ParentRef != nil {
		parent := normalizeRelationshipRef(*in.ParentRef)
		out.ParentRef = &parent
	}
	out.EntityRefs = normalizedRefs(in.EntityRefs)
	if in.PolicyRef != nil {
		policy := *in.PolicyRef
		policy.PolicyID = strings.TrimSpace(policy.PolicyID)
		policy.PolicyVersion = strings.TrimSpace(policy.PolicyVersion)
		policy.PolicyDigest = normalizeDigestRef(policy.PolicyDigest)
		policy.MatchedRuleIDs = uniqueSortedStrings(policy.MatchedRuleIDs)
		policy.Extra = cloneRawMessages(in.PolicyRef.Extra)
		out.PolicyRef = &policy
	}
	out.AgentChain = make([]AgentChainHop, len(in.AgentChain))
	for i := range in.AgentChain {
		out.AgentChain[i] = AgentChainHop{
			Identity: strings.TrimSpace(in.AgentChain[i].Identity),
			Role:     strings.ToLower(strings.TrimSpace(in.AgentChain[i].Role)),
			Extra:    cloneRawMessages(in.AgentChain[i].Extra),
		}
	}
	out.Edges = normalizedEdges(in.Edges)

	// Legacy fields remain normalized for deterministic compatibility.
	out.ParentRecordID = strings.TrimSpace(in.ParentRecordID)
	out.RelatedRecordIDs = uniqueSortedStrings(in.RelatedRecordIDs)
	out.RelatedEntityIDs = uniqueSortedStrings(in.RelatedEntityIDs)
	out.AgentLineage = make([]AgentLineageHop, len(in.AgentLineage))
	for i := range in.AgentLineage {
		out.AgentLineage[i] = AgentLineageHop{
			AgentID:            strings.TrimSpace(in.AgentLineage[i].AgentID),
			DelegatedBy:        strings.TrimSpace(in.AgentLineage[i].DelegatedBy),
			DelegationRecordID: strings.TrimSpace(in.AgentLineage[i].DelegationRecordID),
			Extra:              cloneRawMessages(in.AgentLineage[i].Extra),
		}
	}

	return &out
}

func normalizedRefs(in []RelationshipRef) []RelationshipRef {
	if len(in) == 0 {
		return nil
	}
	type keyedRef struct {
		key string
		ref RelationshipRef
	}
	seen := map[string]struct{}{}
	refs := make([]keyedRef, 0, len(in))
	for i := range in {
		ref := normalizeRelationshipRef(in[i])
		key := relationshipRefStableKey(ref)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, keyedRef{key: key, ref: ref})
	}
	sort.SliceStable(refs, func(i, j int) bool {
		return relationshipRefLess(refs[i].ref, refs[j].ref)
	})
	out := make([]RelationshipRef, 0, len(refs))
	for i := range refs {
		out = append(out, refs[i].ref)
	}
	return out
}

func normalizedEdges(in []RelationshipEdge) []RelationshipEdge {
	if len(in) == 0 {
		return nil
	}
	type keyedEdge struct {
		key  string
		edge RelationshipEdge
	}
	seen := map[string]struct{}{}
	edges := make([]keyedEdge, 0, len(in))
	for i := range in {
		edge := RelationshipEdge{
			Kind:  strings.ToLower(strings.TrimSpace(in[i].Kind)),
			From:  normalizeRelationshipRef(in[i].From),
			To:    normalizeRelationshipRef(in[i].To),
			Extra: cloneRawMessages(in[i].Extra),
		}
		key := stableTuple(edge.Kind, relationshipRefStableKey(edge.From), relationshipRefStableKey(edge.To), rawMapCollisionFreeKey(edge.Extra))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		edges = append(edges, keyedEdge{key: key, edge: edge})
	}
	sort.SliceStable(edges, func(i, j int) bool {
		left, right := edges[i].edge, edges[j].edge
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if relationshipRefStableKey(left.From) != relationshipRefStableKey(right.From) {
			return relationshipRefLess(left.From, right.From)
		}
		if relationshipRefStableKey(left.To) != relationshipRefStableKey(right.To) {
			return relationshipRefLess(left.To, right.To)
		}
		return rawMapLess(left.Extra, right.Extra)
	})
	out := make([]RelationshipEdge, 0, len(edges))
	for i := range edges {
		out = append(out, edges[i].edge)
	}
	return out
}

func uniqueSortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for i := range in {
		v := strings.TrimSpace(in[i])
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func normalizeDigestRef(in string) string {
	v := strings.TrimSpace(in)
	if v == "" {
		return ""
	}
	l := strings.ToLower(v)
	if strings.HasPrefix(l, "sha256:") {
		digest := l[len("sha256:"):]
		if isLowerHexLen(digest, 64) {
			return "sha256:" + digest
		}
		return v
	}
	if isLowerHexLen(l, 64) {
		return l
	}
	return v
}

func normalizeRelationshipRef(in RelationshipRef) RelationshipRef {
	return RelationshipRef{
		Kind:          strings.ToLower(strings.TrimSpace(in.Kind)),
		ID:            strings.TrimSpace(in.ID),
		Digest:        normalizeDigestRef(in.Digest),
		SchemaID:      strings.TrimSpace(in.SchemaID),
		SchemaVersion: strings.TrimSpace(in.SchemaVersion),
		SourceProduct: strings.TrimSpace(in.SourceProduct),
		Extra:         cloneRawMessages(in.Extra),
	}
}

func relationshipRefStableKey(ref RelationshipRef) string {
	return stableTuple(
		ref.Kind,
		ref.ID,
		ref.Digest,
		ref.SchemaID,
		ref.SchemaVersion,
		ref.SourceProduct,
		rawMapCollisionFreeKey(ref.Extra),
	)
}

func relationshipRefLess(left, right RelationshipRef) bool {
	leftFields := []string{left.Kind, left.ID, left.Digest, left.SchemaID, left.SchemaVersion, left.SourceProduct}
	rightFields := []string{right.Kind, right.ID, right.Digest, right.SchemaID, right.SchemaVersion, right.SourceProduct}
	for i := range leftFields {
		if leftFields[i] != rightFields[i] {
			return leftFields[i] < rightFields[i]
		}
	}
	return rawMapLess(left.Extra, right.Extra)
}

func validateRelationship(in *Relationship, path string) error {
	if in == nil {
		return nil
	}
	if in.ParentRef != nil {
		if err := validateRelationshipRef(*in.ParentRef, path+".parent_ref", parentRefKinds); err != nil {
			return err
		}
	}
	for i := range in.EntityRefs {
		if err := validateRelationshipRef(in.EntityRefs[i], fmt.Sprintf("%s.entity_refs[%d]", path, i), entityRefKinds); err != nil {
			return err
		}
	}
	for i := range in.Edges {
		edgePath := fmt.Sprintf("%s.edges[%d]", path, i)
		if !isKnownOrNamespacedKind(in.Edges[i].Kind, edgeKinds) {
			return coreerr.New(
				coreerr.KindValidation,
				ErrorCodeRelationshipEdgeKindInvalid,
				fmt.Sprintf("relationship edge kind %q is not a built-in or valid namespaced kind", in.Edges[i].Kind),
				coreerr.WithField("kind"),
				coreerr.WithPath(edgePath+".kind"),
			)
		}
		if err := validateRelationshipRef(in.Edges[i].From, edgePath+".from", nil); err != nil {
			return err
		}
		if err := validateRelationshipRef(in.Edges[i].To, edgePath+".to", nil); err != nil {
			return err
		}
	}
	return nil
}

func validateRelationshipRef(ref RelationshipRef, path string, builtins map[string]struct{}) error {
	if ref.ID == "" {
		return coreerr.New(
			coreerr.KindValidation,
			ErrorCodeRelationshipRefIDRequired,
			"relationship reference id is required",
			coreerr.WithField("id"),
			coreerr.WithPath(path+".id"),
		)
	}
	if !isKnownOrNamespacedKind(ref.Kind, builtins) {
		return coreerr.New(
			coreerr.KindValidation,
			ErrorCodeRelationshipRefKindInvalid,
			fmt.Sprintf("relationship reference kind %q is not a built-in or valid namespaced kind", ref.Kind),
			coreerr.WithField("kind"),
			coreerr.WithPath(path+".kind"),
		)
	}
	if ref.Digest != "" && !isValidDigestRef(ref.Digest) {
		return coreerr.New(
			coreerr.KindValidation,
			ErrorCodeRelationshipRefDigestInvalid,
			"relationship reference digest must be a SHA-256 digest",
			coreerr.WithField("digest"),
			coreerr.WithPath(path+".digest"),
		)
	}
	return nil
}

func isKnownOrNamespacedKind(kind string, builtins map[string]struct{}) bool {
	if builtins == nil {
		return kind != ""
	}
	if _, ok := builtins[kind]; ok {
		return true
	}
	return namespacedRelationshipKindPattern.MatchString(kind)
}

func isValidDigestRef(in string) bool {
	if in == "" || in != strings.TrimSpace(in) {
		return false
	}
	v := strings.ToLower(in)
	v = strings.TrimPrefix(v, "sha256:")
	return isLowerHexLen(v, 64)
}

func isLowerHexLen(v string, n int) bool {
	if len(v) != n {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

func cloneRelationship(in *Relationship) *Relationship {
	if in == nil {
		return nil
	}
	out := *in
	out.Extra = cloneRawMessages(in.Extra)
	if in.ParentRef != nil {
		parent := cloneRelationshipRef(*in.ParentRef)
		out.ParentRef = &parent
	}
	if in.EntityRefs != nil {
		out.EntityRefs = make([]RelationshipRef, len(in.EntityRefs))
		for i := range in.EntityRefs {
			out.EntityRefs[i] = cloneRelationshipRef(in.EntityRefs[i])
		}
	}
	if in.PolicyRef != nil {
		policy := *in.PolicyRef
		if in.PolicyRef.MatchedRuleIDs != nil {
			policy.MatchedRuleIDs = append([]string(nil), in.PolicyRef.MatchedRuleIDs...)
		}
		policy.Extra = cloneRawMessages(in.PolicyRef.Extra)
		out.PolicyRef = &policy
	}
	if in.AgentChain != nil {
		out.AgentChain = make([]AgentChainHop, len(in.AgentChain))
		for i := range in.AgentChain {
			out.AgentChain[i] = AgentChainHop{
				Identity: in.AgentChain[i].Identity,
				Role:     in.AgentChain[i].Role,
				Extra:    cloneRawMessages(in.AgentChain[i].Extra),
			}
		}
	}
	if in.Edges != nil {
		out.Edges = make([]RelationshipEdge, len(in.Edges))
		for i := range in.Edges {
			out.Edges[i] = RelationshipEdge{
				Kind:  in.Edges[i].Kind,
				From:  cloneRelationshipRef(in.Edges[i].From),
				To:    cloneRelationshipRef(in.Edges[i].To),
				Extra: cloneRawMessages(in.Edges[i].Extra),
			}
		}
	}
	if in.RelatedRecordIDs != nil {
		out.RelatedRecordIDs = append([]string(nil), in.RelatedRecordIDs...)
	}
	if in.RelatedEntityIDs != nil {
		out.RelatedEntityIDs = append([]string(nil), in.RelatedEntityIDs...)
	}
	if in.AgentLineage != nil {
		out.AgentLineage = make([]AgentLineageHop, len(in.AgentLineage))
		for i := range in.AgentLineage {
			out.AgentLineage[i] = AgentLineageHop{
				AgentID:            in.AgentLineage[i].AgentID,
				DelegatedBy:        in.AgentLineage[i].DelegatedBy,
				DelegationRecordID: in.AgentLineage[i].DelegationRecordID,
				Extra:              cloneRawMessages(in.AgentLineage[i].Extra),
			}
		}
	}
	return &out
}

func cloneRelationshipRef(in RelationshipRef) RelationshipRef {
	out := in
	out.Extra = cloneRawMessages(in.Extra)
	return out
}

func cloneRawMessages(in map[string]json.RawMessage) map[string]json.RawMessage {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		out[k] = append(json.RawMessage(nil), v...)
	}
	return out
}

func rawMapStableKey(in map[string]json.RawMessage) string {
	if len(in) == 0 {
		return ""
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i := range keys {
		key := keys[i]
		val := in[key]
		canonical := val
		if len(val) > 0 {
			if normalized, err := canon.Canonicalize(val, canon.DomainJSON); err == nil {
				canonical = normalized
			}
		}
		b.WriteString(key)
		b.WriteByte('\x1f')
		b.Write(canonical)
		b.WriteByte('\x1e')
	}
	return b.String()
}

func rawMapLess(left, right map[string]json.RawMessage) bool {
	leftLegacy, rightLegacy := rawMapStableKey(left), rawMapStableKey(right)
	if leftLegacy != rightLegacy {
		return leftLegacy < rightLegacy
	}
	return rawMapCollisionFreeKey(left) < rawMapCollisionFreeKey(right)
}

func rawMapCollisionFreeKey(in map[string]json.RawMessage) string {
	if len(in) == 0 {
		return ""
	}
	raw, err := json.Marshal(in)
	if err == nil {
		if canonical, canonicalErr := canon.Canonicalize(raw, canon.DomainJSON); canonicalErr == nil {
			return string(canonical)
		}
		return string(raw)
	}

	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		parts = append(parts, key, string(in[key]))
	}
	return stableTuple(parts...)
}

func stableTuple(parts ...string) string {
	var b strings.Builder
	for _, part := range parts {
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
	}
	return b.String()
}
