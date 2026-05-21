package config

import (
	"log"
	"os"
	"strings"
)

// ShadowModeEnabled returns true when policy shadow/canary evaluation is on.
func ShadowModeEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("CLAWSHIELD_POLICY_SHADOW")))
	return v == "1" || v == "true" || v == "yes"
}

// LogShadowDecision logs a shadow evaluation outcome (never enforced).
func LogShadowDecision(version, decision, reason, method string) {
	log.Printf("shadow: version=%s decision=%s method=%s reason=%s", version, decision, method, reason)
}
