package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

type KeyMode string

const (
	ModeDev  KeyMode = "dev"
	ModeProd KeyMode = "prod"
)

const DevKeyWarning = "dev mode: ephemeral keypair generated; signatures will not verify across machines"

type KeyConfig struct {
	Mode           KeyMode
	PrivateKeyPath string
	PublicKeyPath  string
	PrivateKeyEnv  string
	PublicKeyEnv   string
}

func LoadSigningKey(cfg KeyConfig) (KeyPair, []string, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeProd
	}
	switch mode {
	case ModeDev:
		if cfg.hasAnyKeySource() {
			return KeyPair{}, nil, fmt.Errorf("dev mode does not accept explicit key sources")
		}
		kp, err := GenerateKeyPair()
		if err != nil {
			return KeyPair{}, nil, err
		}
		return kp, []string{DevKeyWarning}, nil
	case ModeProd:
		if !cfg.hasPrivateSource() {
			return KeyPair{}, nil, fmt.Errorf("prod mode requires a private key source")
		}
		priv, err := loadPrivateKey(cfg)
		if err != nil {
			return KeyPair{}, nil, err
		}
		pub := priv.Public().(ed25519.PublicKey)
		if cfg.hasPublicSource() {
			loaded, err := loadPublicKey(cfg)
			if err != nil {
				return KeyPair{}, nil, err
			}
			if !loaded.Equal(pub) {
				return KeyPair{}, nil, fmt.Errorf("public key does not match private key")
			}
			pub = loaded
		}
		return KeyPair{Public: pub, Private: priv}, nil, nil
	default:
		return KeyPair{}, nil, fmt.Errorf("unsupported key mode: %q", cfg.Mode)
	}
}

func LoadVerifyKey(cfg KeyConfig) (ed25519.PublicKey, error) {
	if cfg.PublicKeyPath != "" && cfg.PublicKeyEnv != "" {
		return nil, fmt.Errorf("public key source: set either path or env")
	}
	if cfg.PrivateKeyPath != "" && cfg.PrivateKeyEnv != "" {
		return nil, fmt.Errorf("private key source: set either path or env")
	}
	if cfg.hasPublicSource() {
		return loadPublicKey(cfg)
	}
	if cfg.hasPrivateSource() {
		priv, err := loadPrivateKey(cfg)
		if err != nil {
			return nil, err
		}
		return priv.Public().(ed25519.PublicKey), nil
	}
	return nil, fmt.Errorf("public key not configured")
}

func LoadPrivateKeyBase64(path string) (ed25519.PrivateKey, error) {
	// #nosec G304 -- caller supplies local key path by design.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	return ParsePrivateKeyBase64(string(trimSpaceBytes(b)))
}

func LoadPublicKeyBase64(path string) (ed25519.PublicKey, error) {
	// #nosec G304 -- caller supplies local key path by design.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	return ParsePublicKeyBase64(string(trimSpaceBytes(b)))
}

func ParsePrivateKeyBase64(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if l := len(raw); l != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: %d", l)
	}
	return ed25519.PrivateKey(raw), nil
}

func ParsePublicKeyBase64(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if l := len(raw); l != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", l)
	}
	return ed25519.PublicKey(raw), nil
}

func (cfg KeyConfig) hasPrivateSource() bool {
	return cfg.PrivateKeyPath != "" || cfg.PrivateKeyEnv != ""
}

func (cfg KeyConfig) hasPublicSource() bool {
	return cfg.PublicKeyPath != "" || cfg.PublicKeyEnv != ""
}

func (cfg KeyConfig) hasAnyKeySource() bool {
	return cfg.hasPrivateSource() || cfg.hasPublicSource()
}

func loadPrivateKey(cfg KeyConfig) (ed25519.PrivateKey, error) {
	if cfg.PrivateKeyPath != "" && cfg.PrivateKeyEnv != "" {
		return nil, fmt.Errorf("private key source: set either path or env")
	}
	if cfg.PrivateKeyPath != "" {
		return LoadPrivateKeyBase64(cfg.PrivateKeyPath)
	}
	if cfg.PrivateKeyEnv != "" {
		encoded, ok := readEnvValue(cfg.PrivateKeyEnv)
		if !ok {
			return nil, fmt.Errorf("private key env not set: %s", cfg.PrivateKeyEnv)
		}
		return ParsePrivateKeyBase64(encoded)
	}
	return nil, fmt.Errorf("private key not configured")
}

func loadPublicKey(cfg KeyConfig) (ed25519.PublicKey, error) {
	if cfg.PublicKeyPath != "" && cfg.PublicKeyEnv != "" {
		return nil, fmt.Errorf("public key source: set either path or env")
	}
	if cfg.PublicKeyPath != "" {
		return LoadPublicKeyBase64(cfg.PublicKeyPath)
	}
	if cfg.PublicKeyEnv != "" {
		encoded, ok := readEnvValue(cfg.PublicKeyEnv)
		if !ok {
			return nil, fmt.Errorf("public key env not set: %s", cfg.PublicKeyEnv)
		}
		return ParsePublicKeyBase64(encoded)
	}
	return nil, fmt.Errorf("public key not configured")
}

func readEnvValue(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	return value, true
}

func trimSpaceBytes(b []byte) []byte {
	i := 0
	j := len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}
