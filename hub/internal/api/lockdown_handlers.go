package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// HandleAgentLockdown enables or disables emergency lockdown for an agent.
// POST /api/v1/agents/{id}/lockdown
func (h *Hub) HandleAgentLockdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	agentID := r.PathValue("id")
	if agentID == "" {
		// Fallback for older path parsing
		const prefix = "/api/v1/agents/"
		const suffix = "/lockdown"
		path := r.URL.Path
		if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, suffix) {
			agentID = strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
		}
	}
	if !validateID(agentID) {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	var req struct {
		Enabled bool   `json:"enabled"`
		Reason  string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if err := h.SetEmergencyLockdown(agentID, req.Enabled); err != nil {
		log.Printf("lockdown agent %s: %v", agentID, err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_id": agentID,
		"enabled":  req.Enabled,
	})
}
