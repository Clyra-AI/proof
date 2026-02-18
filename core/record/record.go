package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	return &out
}
