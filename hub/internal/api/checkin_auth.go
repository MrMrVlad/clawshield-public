package api

import (
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/SleuthCo/clawshield/shared/auth"
)

func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

func (h *Hub) verifyCheckinAuth(r *http.Request, agentID string, body []byte) error {
	if len(h.MasterKey) != auth.MasterKeySize {
		return fmt.Errorf("hub master key not configured")
	}
	headerAgentID, timestamp, signature, err := auth.ParseAuthorizationHeader(r.Header.Get("Authorization"))
	if err != nil {
		return err
	}
	if headerAgentID != agentID {
		return fmt.Errorf("agent id mismatch")
	}
	secretEnc, err := h.Store.GetAgentSecretEnc(agentID)
	if err != nil {
		return err
	}
	if secretEnc == "" {
		return fmt.Errorf("agent not enrolled with check-in secret")
	}
	secret, err := auth.OpenAgentSecret(secretEnc, h.MasterKey)
	if err != nil {
		return err
	}
	return auth.VerifyCheckin(secret, agentID, timestamp, body, signature)
}
