package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/proof/core/canon"
)

const SchemaVersion = "1.0"

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
		return errors.New("record is nil")
	}
	if strings.TrimSpace(r.RecordVersion) == "" {
		return errors.New("record_version is required")
	}
	if r.Timestamp.IsZero() {
		return errors.New("timestamp is required")
	}
	if strings.TrimSpace(r.Source) == "" {
		return errors.New("source is required")
	}
	if strings.TrimSpace(r.SourceProduct) == "" {
		return errors.New("source_product is required")
	}
	if strings.TrimSpace(r.RecordType) == "" {
		return errors.New("record_type is required")
	}
	if r.Event == nil {
		return errors.New("event is required")
	}
	return nil
}

func ComputeHash(r *Record) (string, error) {
	if r == nil {
		return "", errors.New("record is nil")
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
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	canonical, err := canon.Canonicalize(raw, canon.DomainJSON)
	if err != nil {
		return "", fmt.Errorf("canonicalize payload: %w", err)
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
		return "", err
	}
	canonical, err := canon.Canonicalize(raw, canon.DomainJSON)
	if err != nil {
		return "", err
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
		parent := *in.ParentRef
		parent.Kind = strings.ToLower(strings.TrimSpace(parent.Kind))
		parent.ID = strings.TrimSpace(parent.ID)
		parent.Extra = cloneRawMessages(in.ParentRef.Extra)
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
		ref := RelationshipRef{
			Kind:  strings.ToLower(strings.TrimSpace(in[i].Kind)),
			ID:    strings.TrimSpace(in[i].ID),
			Extra: cloneRawMessages(in[i].Extra),
		}
		extraKey := rawMapStableKey(ref.Extra)
		key := ref.Kind + "\x00" + ref.ID + "\x00" + extraKey
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, keyedRef{key: key, ref: ref})
	}
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].ref.Kind == refs[j].ref.Kind {
			if refs[i].ref.ID == refs[j].ref.ID {
				return rawMapStableKey(refs[i].ref.Extra) < rawMapStableKey(refs[j].ref.Extra)
			}
			return refs[i].ref.ID < refs[j].ref.ID
		}
		return refs[i].ref.Kind < refs[j].ref.Kind
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
			Kind: strings.ToLower(strings.TrimSpace(in[i].Kind)),
			From: RelationshipRef{
				Kind:  strings.ToLower(strings.TrimSpace(in[i].From.Kind)),
				ID:    strings.TrimSpace(in[i].From.ID),
				Extra: cloneRawMessages(in[i].From.Extra),
			},
			To: RelationshipRef{
				Kind:  strings.ToLower(strings.TrimSpace(in[i].To.Kind)),
				ID:    strings.TrimSpace(in[i].To.ID),
				Extra: cloneRawMessages(in[i].To.Extra),
			},
			Extra: cloneRawMessages(in[i].Extra),
		}
		fromExtraKey := rawMapStableKey(edge.From.Extra)
		toExtraKey := rawMapStableKey(edge.To.Extra)
		edgeExtraKey := rawMapStableKey(edge.Extra)
		key := edge.Kind + "\x00" + edge.From.Kind + "\x00" + edge.From.ID + "\x00" + fromExtraKey + "\x00" + edge.To.Kind + "\x00" + edge.To.ID + "\x00" + toExtraKey + "\x00" + edgeExtraKey
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		edges = append(edges, keyedEdge{key: key, edge: edge})
	}
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].edge.Kind != edges[j].edge.Kind {
			return edges[i].edge.Kind < edges[j].edge.Kind
		}
		if edges[i].edge.From.Kind != edges[j].edge.From.Kind {
			return edges[i].edge.From.Kind < edges[j].edge.From.Kind
		}
		if edges[i].edge.From.ID != edges[j].edge.From.ID {
			return edges[i].edge.From.ID < edges[j].edge.From.ID
		}
		if left, right := rawMapStableKey(edges[i].edge.From.Extra), rawMapStableKey(edges[j].edge.From.Extra); left != right {
			return left < right
		}
		if edges[i].edge.To.Kind != edges[j].edge.To.Kind {
			return edges[i].edge.To.Kind < edges[j].edge.To.Kind
		}
		if edges[i].edge.To.ID != edges[j].edge.To.ID {
			return edges[i].edge.To.ID < edges[j].edge.To.ID
		}
		if left, right := rawMapStableKey(edges[i].edge.To.Extra), rawMapStableKey(edges[j].edge.To.Extra); left != right {
			return left < right
		}
		return rawMapStableKey(edges[i].edge.Extra) < rawMapStableKey(edges[j].edge.Extra)
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
		parent := *in.ParentRef
		parent.Extra = cloneRawMessages(in.ParentRef.Extra)
		out.ParentRef = &parent
	}
	if in.EntityRefs != nil {
		out.EntityRefs = make([]RelationshipRef, len(in.EntityRefs))
		for i := range in.EntityRefs {
			out.EntityRefs[i] = RelationshipRef{
				Kind:  in.EntityRefs[i].Kind,
				ID:    in.EntityRefs[i].ID,
				Extra: cloneRawMessages(in.EntityRefs[i].Extra),
			}
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
				Kind: in.Edges[i].Kind,
				From: RelationshipRef{
					Kind:  in.Edges[i].From.Kind,
					ID:    in.Edges[i].From.ID,
					Extra: cloneRawMessages(in.Edges[i].From.Extra),
				},
				To: RelationshipRef{
					Kind:  in.Edges[i].To.Kind,
					ID:    in.Edges[i].To.ID,
					Extra: cloneRawMessages(in.Edges[i].To.Extra),
				},
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
