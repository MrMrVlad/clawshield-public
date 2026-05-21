// Package keyprovider resolves audit encryption keys from env, files, or external KMS.
package keyprovider

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/crypto"
)

// Provider supplies a 32-byte AES key for audit encryption.
type Provider interface {
	GetKey() ([]byte, error)
	Name() string
}

// Resolve creates a provider from CLAWSHIELD_KEY_PROVIDER (env|file|vault|aws).
// Default: env (CLAWSHIELD_AUDIT_ENCRYPTION_KEY).
func Resolve() (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CLAWSHIELD_KEY_PROVIDER"))) {
	case "", "env":
		return &EnvProvider{}, nil
	case "file":
		return &FileProvider{Path: os.Getenv("CLAWSHIELD_AUDIT_KEY_FILE")}, nil
	case "vault":
		return NewVaultProviderFromEnv()
	case "aws":
		return NewAWSProviderFromEnv()
	default:
		return nil, fmt.Errorf("unknown CLAWSHIELD_KEY_PROVIDER")
	}
}

// EnvProvider reads hex key from CLAWSHIELD_AUDIT_ENCRYPTION_KEY.
type EnvProvider struct{}

func (e *EnvProvider) Name() string { return "env" }

func (e *EnvProvider) GetKey() ([]byte, error) {
	hexKey := strings.TrimSpace(os.Getenv(crypto.EnvKeyName))
	if hexKey == "" {
		return nil, fmt.Errorf("%s not set", crypto.EnvKeyName)
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(key) != crypto.KeySize {
		return nil, crypto.ErrInvalidKeySize
	}
	return key, nil
}

// FileProvider reads hex key from a root-only file (0600).
type FileProvider struct {
	Path string
}

func (f *FileProvider) Name() string { return "file" }

func (f *FileProvider) GetKey() ([]byte, error) {
	path := f.Path
	if path == "" {
		path = "/var/lib/clawshield/audit-encryption.key"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	hexKey := strings.TrimSpace(string(data))
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(key) != crypto.KeySize {
		return nil, crypto.ErrInvalidKeySize
	}
	return key, nil
}

// NewFieldEncryptorFromProvider builds encryptor from configured provider.
func NewFieldEncryptorFromProvider() (*crypto.FieldEncryptor, error) {
	p, err := Resolve()
	if err != nil {
		return nil, err
	}
	key, err := p.GetKey()
	if err != nil {
		return nil, fmt.Errorf("provider %s: %w", p.Name(), err)
	}
	return crypto.NewFieldEncryptor(key)
}
