package proof

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Clyra-AI/proof/core/canon"
	"github.com/Clyra-AI/proof/core/chain"
	"github.com/Clyra-AI/proof/core/framework"
	"github.com/Clyra-AI/proof/core/record"
	"github.com/Clyra-AI/proof/core/schema"
	"github.com/Clyra-AI/proof/core/signing"
)

type Record = record.Record
type RecordOpts = record.RecordOpts
type Controls = record.Controls
type Chain = chain.Chain
type ChainVerification = chain.Verification
type SigningKey = signing.SigningKey
type PublicKey = signing.PublicKey
type Framework = framework.Framework
type RecordType = schema.RecordType
type CanonDomain = canon.Domain

const (
	DomainJSON   = canon.DomainJSON
	DomainSQL    = canon.DomainSQL
	DomainURL    = canon.DomainURL
	DomainText   = canon.DomainText
	DomainPrompt = canon.DomainPrompt
)

func NewRecord(opts RecordOpts) (*Record, error) {
	r, err := record.New(opts)
	if err != nil {
		return nil, err
	}
	if err := ValidateRecord(r); err != nil {
		return nil, err
	}
	return r, nil
}

func Sign(r *Record, key SigningKey) (*Record, error) {
	return signing.Sign(r, key)
}

func Verify(r *Record, publicKey PublicKey) error {
	return signing.Verify(r, publicKey)
}

func AppendToChain(c *Chain, r *Record) error {
	return chain.Append(c, r)
}

func VerifyChain(c *Chain) (*ChainVerification, error) {
	return chain.Verify(c)
}

func Canonicalize(input []byte, domain CanonDomain) ([]byte, error) {
	return canon.Canonicalize(input, domain)
}

func LoadFramework(pathOrID string) (*Framework, error) {
	return framework.Load(pathOrID)
}

func ListRecordTypes() []RecordType {
	return schema.ListRecordTypes()
}

func ValidateRecord(r *Record) error {
	if err := record.Validate(r); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return schema.ValidateRecord(raw, r.RecordType)
}

func ComputeRecordHash(r *Record) (string, error) {
	return record.ComputeHash(r)
}

func NewChain(id string) *Chain {
	return chain.New(id, time.Now().UTC())
}

func VerifyChainRange(c *Chain, from, to time.Time) (*ChainVerification, error) {
	return chain.VerifyRange(c, from, to)
}

func GenerateSigningKey() (SigningKey, error) {
	return signing.GenerateKey()
}

func WriteRecord(path string, r *Record) error {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func ReadRecord(path string) (*Record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func ValidateCustomTypeSchema(schemaPath string) error {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		return err
	}
	if err := schema.ValidateCustomSchema(schemaPath, raw); err != nil {
		return fmt.Errorf("invalid schema: %w", err)
	}
	return nil
}
