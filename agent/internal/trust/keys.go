// Package trust loads Hub signing and release verification keys from PEM files.
package trust

import (
	"crypto/rsa"
	"fmt"
	"os"

	sharedpolicy "github.com/SleuthCo/clawshield/shared/policy"
)

// LoadRSAPublicKeyPEM reads an RSA public key from a PEM file. Empty path returns nil, nil.
func LoadRSAPublicKeyPEM(path string) (*rsa.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", path, err)
	}
	pub, err := sharedpolicy.PublicKeyFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parse public key %s: %w", path, err)
	}
	return pub, nil
}
