package chain

import (
	"errors"
	"fmt"
	"time"

	"github.com/Clyra-AI/proof/core/record"
	"github.com/Clyra-AI/proof/core/signing"
)

type Chain struct {
	ChainID     string              `json:"chain_id"`
	CreatedAt   time.Time           `json:"created_at"`
	RecordCount int                 `json:"record_count"`
	HeadHash    string              `json:"head_hash,omitempty"`
	Records     []record.Record     `json:"records"`
	Signatures  []signing.Signature `json:"signatures,omitempty"`
}

type Verification struct {
	Intact     bool   `json:"intact"`
	Count      int    `json:"count"`
	BreakPoint string `json:"break_point,omitempty"`
	BreakIndex int    `json:"break_index,omitempty"`
	HeadHash   string `json:"head_hash,omitempty"`
}

func New(chainID string, createdAt time.Time) *Chain {
	if createdAt.IsZero() {
		createdAt = time.Now().UTC().Truncate(time.Second)
	}
	return &Chain{ChainID: chainID, CreatedAt: createdAt, Records: []record.Record{}}
}

func Append(c *Chain, r *record.Record) error {
	if c == nil {
		return errors.New("chain is nil")
	}
	if r == nil {
		return errors.New("record is nil")
	}
	if err := record.Validate(r); err != nil {
		return err
	}
	copy := record.Clone(r)
	if copy.Integrity.PreviousRecordHash == "" {
		copy.Integrity.PreviousRecordHash = c.HeadHash
	}
	if copy.Integrity.PreviousRecordHash != c.HeadHash {
		return fmt.Errorf("previous_record_hash mismatch: expected %s got %s", c.HeadHash, copy.Integrity.PreviousRecordHash)
	}
	h, err := record.ComputeHash(copy)
	if err != nil {
		return err
	}
	if copy.Integrity.Signature != "" && copy.Integrity.RecordHash != h {
		return errors.New("signed record hash does not match computed chain hash; append before signing or pre-link correctly")
	}
	copy.Integrity.RecordHash = h
	c.Records = append(c.Records, *copy)
	c.HeadHash = h
	c.RecordCount = len(c.Records)
	return nil
}

func Verify(c *Chain) (*Verification, error) {
	if c == nil {
		return nil, errors.New("chain is nil")
	}
	verification := &Verification{Intact: true, Count: len(c.Records), HeadHash: c.HeadHash}
	prev := ""
	for i := range c.Records {
		r := c.Records[i]
		if r.Integrity.PreviousRecordHash != prev {
			verification.Intact = false
			verification.BreakIndex = i
			verification.BreakPoint = r.RecordID
			return verification, nil
		}
		expected, err := record.ComputeHash(&r)
		if err != nil {
			return nil, err
		}
		if expected != r.Integrity.RecordHash {
			verification.Intact = false
			verification.BreakIndex = i
			verification.BreakPoint = r.RecordID
			return verification, nil
		}
		prev = r.Integrity.RecordHash
	}
	if c.HeadHash != prev {
		verification.Intact = false
		verification.BreakIndex = len(c.Records) - 1
		verification.BreakPoint = fmt.Sprintf("head_hash mismatch: expected %s got %s", prev, c.HeadHash)
	}
	verification.HeadHash = prev
	return verification, nil
}

func VerifyRange(c *Chain, from, to time.Time) (*Verification, error) {
	if from.IsZero() && to.IsZero() {
		return Verify(c)
	}
	if c == nil {
		return nil, errors.New("chain is nil")
	}
	v, err := Verify(c)
	if err != nil {
		return nil, err
	}
	if !v.Intact {
		return v, nil
	}
	count := 0
	for _, r := range c.Records {
		ts := r.Timestamp.UTC()
		if !from.IsZero() && ts.Before(from.UTC()) {
			continue
		}
		if !to.IsZero() && ts.After(to.UTC()) {
			continue
		}
		count++
	}
	if count == 0 {
		return &Verification{Intact: true, Count: 0}, nil
	}
	return &Verification{Intact: true, Count: count, HeadHash: c.HeadHash}, nil
}
