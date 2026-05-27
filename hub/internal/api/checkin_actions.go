package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/SleuthCo/clawshield/hub/internal/models"
	sharedmodels "github.com/SleuthCo/clawshield/shared/models"
)

// BuildCheckinActions returns all pending actions for an agent (policy, keys, updates, lockdown).
func (h *Hub) BuildCheckinActions(req *models.CheckinRequest) []models.Action {
	var actions []models.Action

	actions = append(actions, h.BuildPolicyActions(req)...)

	if keyAction := h.buildKeyRotationAction(req); keyAction != nil {
		actions = append(actions, *keyAction)
	}

	if updateAction := h.buildBinaryUpdateAction(req); updateAction != nil {
		actions = append(actions, *updateAction)
	}

	if lockdownAction := h.buildLockdownAction(req); lockdownAction != nil {
		actions = append(actions, *lockdownAction)
	}

	return actions
}

func (h *Hub) buildKeyRotationAction(req *models.CheckinRequest) *models.Action {
	agent, err := h.Store.GetAgent(req.AgentID)
	if err != nil || agent == nil || agent.PolicyGroupID == "" {
		return nil
	}
	active, err := h.Store.GetActiveKeyForGroup(agent.PolicyGroupID)
	if err != nil || active == nil {
		return nil
	}
	if req.EncryptionKeyID == active.KeyID {
		return nil
	}
	// EncryptedKey stores hex-encoded 32-byte key for distribution (TLS in transit).
	// SECURITY: Production should wrap with Hub KMS; see docs/security-decisions.md.
	material := strings.TrimSpace(active.EncryptedKey)
	if len(material) != 64 {
		log.Printf("skip key rotation for agent %s: active key material invalid length", req.AgentID)
		return nil
	}
	payload, _ := json.Marshal(sharedmodels.KeyRotateAction{
		KeyID:       active.KeyID,
		KeyMaterial: material,
	})
	return &models.Action{Type: "rotate_encryption_key", Payload: payload}
}

func (h *Hub) buildBinaryUpdateAction(req *models.CheckinRequest) *models.Action {
	task, err := h.Store.GetPendingUpdateForAgent(req.AgentID)
	if err != nil || task == nil {
		return nil
	}
	if !validateReleaseVersion(task.TargetVersion) {
		log.Printf("skip binary update for agent %s: invalid target version %q", req.AgentID, task.TargetVersion)
		return nil
	}
	downloadURL := fmt.Sprintf("%s/api/v1/releases/%s/binary", strings.TrimRight(h.hubBaseURL(), "/"), task.TargetVersion)
	payload, _ := json.Marshal(sharedmodels.UpdateBinaryAction{
		Version:     task.TargetVersion,
		BinaryHash:  task.BinaryHash,
		Signature:   task.Signature,
		DownloadURL: downloadURL,
	})
	return &models.Action{Type: "update_binary", Payload: payload}
}

func (h *Hub) buildLockdownAction(req *models.CheckinRequest) *models.Action {
	enabled, err := h.Store.GetEmergencyLockdown(req.AgentID)
	if err != nil || !enabled {
		return nil
	}
	payload, _ := json.Marshal(sharedmodels.EmergencyLockdownAction{
		Enabled: true,
		Reason:  "hub emergency lockdown active",
	})
	return &models.Action{Type: "emergency_lockdown", Payload: payload}
}

// hubBaseURL returns configured public hub URL for binary downloads.
func (h *Hub) hubBaseURL() string {
	if h.PublicBaseURL != "" {
		return h.PublicBaseURL
	}
	return "https://localhost:18800"
}

// SetEmergencyLockdown enables or disables lockdown for an agent (management API).
func (h *Hub) SetEmergencyLockdown(agentID string, enabled bool) error {
	if !validateID(agentID) {
		return fmt.Errorf("invalid agent ID")
	}
	return h.Store.SetEmergencyLockdown(agentID, enabled)
}

// ValidatePublicHubURL ensures binary download base URL is https.
func ValidatePublicHubURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		return fmt.Errorf("public hub URL must be https (or http localhost for dev)")
	}
	return nil
}

func validateReleaseVersion(version string) bool {
	if version == "" || len(version) > 64 {
		return false
	}
	for _, r := range version {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
