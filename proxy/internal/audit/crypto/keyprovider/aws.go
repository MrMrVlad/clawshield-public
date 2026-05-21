package keyprovider

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/crypto"
)

// AWSProvider loads a data encryption key from environment/file envelope.
// Full AWS KMS SDK integration is deferred; operators set CLAWSHIELD_AWS_DEK_HEX
// after decrypting KMS ciphertext out-of-band (e.g. aws kms decrypt in CI).
//
// SECURITY TRADE-OFF: avoids aws-sdk dependency in proxy binary (smaller attack
// surface) at cost of manual envelope step. See docs/security-decisions.md.
type AWSProvider struct {
	DEKHex string
}

// NewAWSProviderFromEnv reads CLAWSHIELD_AWS_DEK_HEX (64 hex chars).
func NewAWSProviderFromEnv() (*AWSProvider, error) {
	dek := strings.TrimSpace(os.Getenv("CLAWSHIELD_AWS_DEK_HEX"))
	if dek == "" {
		return nil, fmt.Errorf("aws provider requires CLAWSHIELD_AWS_DEK_HEX (KMS-decrypted DEK)")
	}
	if len(dek) != 64 {
		return nil, fmt.Errorf("CLAWSHIELD_AWS_DEK_HEX must be 64 hex characters")
	}
	return &AWSProvider{DEKHex: dek}, nil
}

func (a *AWSProvider) Name() string { return "aws-envelope" }

func (a *AWSProvider) GetKey() ([]byte, error) {
	key, err := hex.DecodeString(a.DEKHex)
	if err != nil {
		return nil, err
	}
	if len(key) != crypto.KeySize {
		return nil, crypto.ErrInvalidKeySize
	}
	return key, nil
}
