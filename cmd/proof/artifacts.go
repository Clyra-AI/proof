package main

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/chain"
	"github.com/Clyra-AI/proof/core/gait"
)

type artifactKind string

const (
	artifactRecord         artifactKind = "record"
	artifactChain          artifactKind = "chain"
	artifactBundle         artifactKind = "bundle"
	artifactGaitPack       artifactKind = "gait_pack"
	artifactGaitRunpack    artifactKind = "gait_runpack"
	artifactGaitSignedJSON artifactKind = "gait_signed_json"
)

func detectArtifact(path string) (artifactKind, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		if _, err := os.Stat(filepath.Join(path, "manifest.json")); err == nil {
			return artifactBundle, nil
		}
		return artifactChain, nil
	}
	if strings.EqualFold(filepath.Ext(path), ".zip") {
		if zipHasFile(path, "pack_manifest.json") {
			return artifactGaitPack, nil
		}
		if zipHasFile(path, "manifest.json") {
			return artifactGaitRunpack, nil
		}
	}
	// #nosec G304 -- CLI accepts explicit local artifact paths.
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", err
	}
	if _, ok := obj["records"]; ok {
		return artifactChain, nil
	}
	if _, ok := obj["record_id"]; ok {
		return artifactRecord, nil
	}
	if _, ok := obj["pack_id"]; ok {
		return artifactGaitSignedJSON, nil
	}
	if sigAny, ok := obj["signature"]; ok {
		if _, ok := sigAny.(map[string]any); ok {
			return artifactGaitSignedJSON, nil
		}
	}
	return "", errors.New("unsupported artifact type")
}

func loadRecord(path string) (*proof.Record, error) {
	return proof.ReadRecord(path)
}

func loadChain(path string) (*proof.Chain, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		// #nosec G304 -- CLI accepts explicit local artifact paths.
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var c proof.Chain
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		return &c, nil
	}

	files, err := filepath.Glob(filepath.Join(path, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	c := chain.New(filepath.Base(path), time.Now().UTC())
	for _, f := range files {
		base := filepath.Base(f)
		if base == "manifest.json" || base == "chain.json" {
			continue
		}
		r, err := loadRecord(f)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", base, err)
		}
		c.Records = append(c.Records, *r)
		c.RecordCount = len(c.Records)
		c.HeadHash = r.Integrity.RecordHash
	}
	// Support JSONL proof record streams in chain directories.
	jsonlFiles, err := filepath.Glob(filepath.Join(path, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(jsonlFiles)
	for _, f := range jsonlFiles {
		if err := appendJSONLRecords(c, f); err != nil {
			return nil, err
		}
	}
	if len(c.Records) == 0 {
		chainPath := filepath.Join(path, "chain.json")
		// #nosec G304 -- CLI accepts explicit local artifact paths.
		raw, err := os.ReadFile(chainPath)
		if err != nil {
			return c, nil
		}
		if err := json.Unmarshal(raw, c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func verifyBundle(path string, verifySignatures bool, publicKey string, cosignOpts proof.CosignVerifyOpts) error {
	var pub proof.PublicKey
	if strings.TrimSpace(publicKey) != "" {
		decoded, err := decodePublicKey(publicKey)
		if err != nil {
			return err
		}
		pub = decoded
	}
	_, err := proof.VerifyBundle(path, proof.BundleVerifyOpts{
		VerifySignatures: verifySignatures,
		PublicKey:        pub,
		Cosign:           cosignOpts,
	})
	return err
}

func appendJSONLRecords(c *proof.Chain, path string) error {
	// #nosec G304 -- CLI accepts explicit local artifact paths.
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r proof.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return fmt.Errorf("parse %s: %w", filepath.Base(path), err)
		}
		c.Records = append(c.Records, r)
		c.RecordCount = len(c.Records)
		c.HeadHash = r.Integrity.RecordHash
	}
	return scanner.Err()
}

func verifyGaitPack(path string, verifySignatures bool, publicKey string, cosignOpts proof.CosignVerifyOpts) (*gait.Result, error) {
	var pubKey []byte
	if verifySignatures {
		if strings.TrimSpace(publicKey) != "" {
			pub, err := decodePublicKeyValue(publicKey)
			if err != nil {
				return nil, err
			}
			pubKey = pub
		}
		if len(pubKey) == 0 && strings.TrimSpace(cosignOpts.KeyPath) == "" && strings.TrimSpace(cosignOpts.CertificatePath) == "" {
			return nil, fmt.Errorf("--public-key is required for gait pack signature verification")
		}
	}
	return gait.VerifyPackWithOptions(path, gait.VerifyOpts{
		VerifySignatures: verifySignatures,
		PublicKey:        pubKey,
		Cosign:           cosignOpts,
	})
}

func verifyGaitRunpack(path string, verifySignatures bool, publicKey string, _ proof.CosignVerifyOpts) (*gait.RunpackResult, error) {
	var pubKey []byte
	if verifySignatures {
		if strings.TrimSpace(publicKey) == "" {
			return nil, fmt.Errorf("--public-key is required for gait runpack signature verification")
		}
		pub, err := decodePublicKeyValue(publicKey)
		if err != nil {
			return nil, err
		}
		pubKey = pub
	}
	return gait.VerifyRunpackWithOptions(path, gait.VerifyOpts{
		VerifySignatures: verifySignatures,
		PublicKey:        pubKey,
	})
}

func verifyGaitSignedJSON(path, publicKey string) error {
	if strings.TrimSpace(publicKey) == "" {
		return fmt.Errorf("--public-key is required for gait signed JSON verification")
	}
	pub, err := decodePublicKeyValue(publicKey)
	if err != nil {
		return err
	}
	// #nosec G304 -- CLI accepts explicit local artifact paths.
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return gait.VerifyEmbeddedSignedJSON(raw, pub)
}

func zipHasFile(path, name string) bool {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return false
	}
	defer func() { _ = zr.Close() }()
	for _, f := range zr.File {
		if filepath.Clean(f.Name) == filepath.Clean(name) {
			return true
		}
	}
	return false
}
