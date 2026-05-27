package api

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/SleuthCo/clawshield/shared/auth"
)

const maxReleaseBinaryBytes = 256 << 20 // 256 MiB

// HandleDownloadReleaseBinary serves a release artifact to authenticated agents.
// GET /api/v1/releases/{version}/binary
func (h *Hub) HandleDownloadReleaseBinary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	const prefix = "/api/v1/releases/"
	const suffix = "/binary"
	path := r.URL.Path
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}
	version := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if !auth.ValidateReleaseVersion(version) {
		writeError(w, http.StatusBadRequest, "invalid version")
		return
	}

	headerAgentID, timestamp, signature, err := auth.ParseAuthorizationHeader(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing or invalid authorization")
		return
	}
	if !validateID(headerAgentID) {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	if err := h.verifyGETAuth(headerAgentID, timestamp, signature, path); err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	release, err := h.Store.GetReleaseByVersion(version)
	if err != nil {
		log.Printf("release lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if release == nil {
		writeError(w, http.StatusNotFound, "release not found")
		return
	}

	artifactPath := h.releaseArtifactPath(version)
	if artifactPath == "" {
		writeError(w, http.StatusNotFound, "release binary not available")
		return
	}
	info, err := os.Stat(artifactPath)
	if err != nil || info.IsDir() {
		writeError(w, http.StatusNotFound, "release binary not found")
		return
	}
	if info.Size() > maxReleaseBinaryBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "release binary too large")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Release-Version", version)
	w.Header().Set("X-Binary-Hash", release.BinaryHash)
	if release.Signature != "" {
		w.Header().Set("X-Binary-Signature", release.Signature)
	}
	f, err := os.Open(artifactPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "release binary not found")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	if _, err := io.Copy(w, io.LimitReader(f, maxReleaseBinaryBytes)); err != nil {
		log.Printf("release download: %v", err)
	}
}

func (h *Hub) verifyGETAuth(agentID string, timestamp int64, signature, path string) error {
	if len(h.MasterKey) != auth.MasterKeySize {
		return fmt.Errorf("hub master key not configured")
	}
	secretEnc, err := h.Store.GetAgentSecretEnc(agentID)
	if err != nil || secretEnc == "" {
		return fmt.Errorf("missing agent secret")
	}
	secret, err := auth.OpenAgentSecret(secretEnc, h.MasterKey)
	if err != nil {
		return err
	}
	return auth.VerifyGETRequest(secret, agentID, timestamp, path, signature)
}

func (h *Hub) releaseArtifactPath(version string) string {
	if h.ReleasesDir == "" {
		return ""
	}
	return filepath.Join(h.ReleasesDir, version, "clawshield-proxy")
}
