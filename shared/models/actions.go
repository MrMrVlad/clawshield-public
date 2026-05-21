package models

// PolicyUpdateAction is the payload for update_policy from the Hub.
type PolicyUpdateAction struct {
	VersionID  string `json:"version_id"`
	PolicyYAML string `json:"policy_yaml"`
	Signature  string `json:"signature,omitempty"`
	PolicyHash string `json:"policy_hash"`
}

// KeyRotateAction is the payload for rotate_encryption_key from the Hub.
type KeyRotateAction struct {
	KeyID       string `json:"key_id"`
	KeyMaterial string `json:"key_material"` // 64-char hex; deliver only over TLS
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// UpdateBinaryAction is the payload for update_binary from the Hub.
type UpdateBinaryAction struct {
	Version     string `json:"version"`
	BinaryHash  string `json:"binary_hash"`
	Signature   string `json:"signature"`
	DownloadURL string `json:"download_url"`
}

// EmergencyLockdownAction is the payload for emergency_lockdown from the Hub.
type EmergencyLockdownAction struct {
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason,omitempty"`
}
