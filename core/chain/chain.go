package chain

import (
	"errors"
	"fmt"
	"time"

	"github.com/Clyra-AI/proof/core/record"
)

type Chain struct {
	ChainID     string          `json:"chain_id"`
	CreatedAt   time.Time       `json:"created_at"`
	RecordCount int             `json:"record_count"`
	HeadHash    string          `json:"head_hash,omitempty"`
	Records     []record.Record `json:"records"`
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
	if r.Integrity.Signature != "" {
		return errors.New("record is already signed; append before signing")
	}
	copy := record.Clone(r)
	copy.Integrity.PreviousRecordHash = c.HeadHash
	h, err := record.ComputeHash(copy)
	if err != nil {
		return err
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
	sub := &Chain{ChainID: c.ChainID, CreatedAt: c.CreatedAt}
	for _, r := range c.Records {
		ts := r.Timestamp.UTC()
		if !from.IsZero() && ts.Before(from.UTC()) {
			continue
		}
		if !to.IsZero() && ts.After(to.UTC()) {
			continue
		}
		sub.Records = append(sub.Records, r)
	}
	if len(sub.Records) == 0 {
		return &Verification{Intact: true, Count: 0}, nil
	}
	for i := range sub.Records {
		if i == 0 {
			continue
		}
		sub.Records[i].Integrity.PreviousRecordHash = sub.Records[i-1].Integrity.RecordHash
	}
	sub.HeadHash = sub.Records[len(sub.Records)-1].Integrity.RecordHash
	return Verify(sub)
}
