// Package release provides binary release signature verification helpers.
package release

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// VerifyBinaryHashSignature verifies an RSA-SHA256 PKCS1v15 signature over the binary hash string.
func VerifyBinaryHashSignature(binaryHash, signature string, publicKey *rsa.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("release public key not configured")
	}
	if signature == "" {
		return fmt.Errorf("binary signature required but not provided")
	}
	hash := sha256.Sum256([]byte(binaryHash))
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sig); err != nil {
		return fmt.Errorf("verify binary signature: %w", err)
	}
	return nil
}
