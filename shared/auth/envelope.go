package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const (
	// MasterKeySize is the hub master key length for at-rest DEK encryption.
	MasterKeySize = 32
	// WrappedPrefix marks agent-wrapped key material in rotate_encryption_key payloads.
	WrappedPrefix = "wrap1:"
)

// ParseMasterKey decodes a 64-char hex hub master key from env/config.
func ParseMasterKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, fmt.Errorf("decode master key: %w", err)
	}
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("master key must be %d bytes", MasterKeySize)
	}
	return key, nil
}

func deriveKeyMaterial(master []byte, context string) []byte {
	h := sha256.Sum256(append(append([]byte(context+":"), master...), 0))
	return h[:]
}

func seal(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

func open(key []byte, blob string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("decode blob: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
}

// SealDEKForStorage encrypts a DEK for hub database storage using the master key.
func SealDEKForStorage(dekHex string, masterKey []byte) (string, error) {
	if len(masterKey) != MasterKeySize {
		return "", fmt.Errorf("invalid master key size")
	}
	key := deriveKeyMaterial(masterKey, "hub-dek-storage")
	return seal(key, []byte(dekHex))
}

// OpenDEKFromStorage decrypts a DEK from hub database storage.
func OpenDEKFromStorage(blob string, masterKey []byte) (string, error) {
	if len(masterKey) != MasterKeySize {
		return "", fmt.Errorf("invalid master key size")
	}
	key := deriveKeyMaterial(masterKey, "hub-dek-storage")
	plain, err := open(key, blob)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// WrapDEKForAgent wraps a DEK for delivery to an agent using its check-in secret.
func WrapDEKForAgent(dekHex string, agentSecret []byte) (string, error) {
	if len(agentSecret) != AgentSecretSize {
		return "", fmt.Errorf("invalid agent secret size")
	}
	key := deriveKeyMaterial(agentSecret, "agent-dek-wrap")
	blob, err := seal(key, []byte(dekHex))
	if err != nil {
		return "", err
	}
	return WrappedPrefix + blob, nil
}

// UnwrapDEKForAgent unwraps key material from a rotate_encryption_key action.
func UnwrapDEKForAgent(material string, agentSecret []byte) (string, error) {
	material = strings.TrimSpace(material)
	if strings.HasPrefix(material, WrappedPrefix) {
		if len(agentSecret) != AgentSecretSize {
			return "", fmt.Errorf("invalid agent secret size")
		}
		key := deriveKeyMaterial(agentSecret, "agent-dek-wrap")
		plain, err := open(key, material[len(WrappedPrefix):])
		if err != nil {
			return "", err
		}
		out := strings.TrimSpace(string(plain))
		if len(out) != 64 {
			return "", fmt.Errorf("unwrapped DEK must be 64 hex chars")
		}
		return out, nil
	}
	// Legacy plaintext hex (dev migration only — reject when agent secret is configured).
	if len(material) == 64 {
		return "", fmt.Errorf("plaintext key material rejected: re-enroll agent or rotate keys")
	}
	return "", fmt.Errorf("unsupported key material format")
}

// SealAgentSecret encrypts an agent secret for hub storage.
func SealAgentSecret(secret, masterKey []byte) (string, error) {
	if len(secret) != AgentSecretSize || len(masterKey) != MasterKeySize {
		return "", fmt.Errorf("invalid secret or master key size")
	}
	key := deriveKeyMaterial(masterKey, "agent-secret-storage")
	return seal(key, secret)
}

// OpenAgentSecret decrypts an agent secret from hub storage.
func OpenAgentSecret(blob string, masterKey []byte) ([]byte, error) {
	if len(masterKey) != MasterKeySize {
		return nil, fmt.Errorf("invalid master key size")
	}
	key := deriveKeyMaterial(masterKey, "agent-secret-storage")
	plain, err := open(key, blob)
	if err != nil {
		return nil, err
	}
	if len(plain) != AgentSecretSize {
		return nil, fmt.Errorf("invalid stored agent secret length")
	}
	return plain, nil
}
