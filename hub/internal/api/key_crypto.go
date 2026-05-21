package api

import (
	"fmt"
	"strings"

	"github.com/SleuthCo/clawshield/shared/auth"
)

func (h *Hub) unwrapStoredDEK(stored string) (string, error) {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return "", fmt.Errorf("empty key material")
	}
	if len(stored) == 64 && isHexString(stored) {
		return strings.ToLower(stored), nil
	}
	if len(h.MasterKey) != auth.MasterKeySize {
		return "", fmt.Errorf("hub master key required to unwrap stored DEK")
	}
	return auth.OpenDEKFromStorage(stored, h.MasterKey)
}

func isHexString(s string) bool {
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

func (h *Hub) agentSecretFor(agentID string) ([]byte, error) {
	enc, err := h.Store.GetAgentSecretEnc(agentID)
	if err != nil {
		return nil, err
	}
	if enc == "" {
		return nil, fmt.Errorf("agent has no check-in secret")
	}
	return auth.OpenAgentSecret(enc, h.MasterKey)
}

// SealDEKForStorage encrypts a DEK before persisting in encryption_keys.encrypted_key.
func (h *Hub) SealDEKForStorage(dekHex string) (string, error) {
	if len(h.MasterKey) != auth.MasterKeySize {
		return "", fmt.Errorf("hub master key not configured")
	}
	return auth.SealDEKForStorage(dekHex, h.MasterKey)
}
