// Package auth provides fleet check-in authentication and key wrapping helpers.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxClockSkew is the allowed difference between client timestamp and server time.
	MaxClockSkew = 5 * time.Minute
	// AgentSecretSize is the raw length of per-agent secrets.
	AgentSecretSize = 32
	// CheckinAuthScheme is the Authorization scheme for signed check-ins.
	CheckinAuthScheme = "Clawshield"
)

// GenerateAgentSecret returns a cryptographically random 32-byte agent secret.
func GenerateAgentSecret() ([]byte, error) {
	secret := make([]byte, AgentSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate agent secret: %w", err)
	}
	return secret, nil
}

// SignCheckin computes HMAC-SHA256 over agentID|timestamp|body.
func SignCheckin(secret []byte, agentID string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(agentID))
	mac.Write([]byte("|"))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("|"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyCheckin validates the signature and timestamp window.
func VerifyCheckin(secret []byte, agentID string, timestamp int64, body []byte, signature string) error {
	if len(secret) != AgentSecretSize {
		return fmt.Errorf("invalid agent secret length")
	}
	now := time.Now().UTC().Unix()
	if timestamp < now-int64(MaxClockSkew.Seconds()) || timestamp > now+int64(MaxClockSkew.Seconds()) {
		return fmt.Errorf("check-in timestamp outside allowed window")
	}
	expected := SignCheckin(secret, agentID, timestamp, body)
	sig := strings.TrimSpace(signature)
	if len(sig) != 64 {
		return fmt.Errorf("invalid signature length")
	}
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return fmt.Errorf("check-in signature mismatch")
	}
	return nil
}

// SignGETRequest signs a GET request for release downloads (no JSON body).
func SignGETRequest(secret []byte, agentID string, timestamp int64, path string) string {
	payload := []byte("GET|" + agentID + "|" + strconv.FormatInt(timestamp, 10) + "|" + path)
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyGETRequest validates a GET request signature.
func VerifyGETRequest(secret []byte, agentID string, timestamp int64, path, signature string) error {
	if len(secret) != AgentSecretSize {
		return fmt.Errorf("invalid agent secret length")
	}
	now := time.Now().UTC().Unix()
	if timestamp < now-int64(MaxClockSkew.Seconds()) || timestamp > now+int64(MaxClockSkew.Seconds()) {
		return fmt.Errorf("check-in timestamp outside allowed window")
	}
	expected := SignGETRequest(secret, agentID, timestamp, path)
	sig := strings.TrimSpace(signature)
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return fmt.Errorf("GET signature mismatch")
	}
	return nil
}

// FormatAuthorizationHeader builds "Clawshield <agent_id>:<ts>:<sig>".
func FormatAuthorizationHeader(agentID string, timestamp int64, signature string) string {
	return fmt.Sprintf("%s %s:%d:%s", CheckinAuthScheme, agentID, timestamp, signature)
}

// ParseAuthorizationHeader parses a Clawshield authorization header.
func ParseAuthorizationHeader(header string) (agentID string, timestamp int64, signature string, err error) {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, CheckinAuthScheme+" ") {
		return "", 0, "", fmt.Errorf("missing %s scheme", CheckinAuthScheme)
	}
	rest := strings.TrimPrefix(header, CheckinAuthScheme+" ")
	parts := strings.Split(rest, ":")
	if len(parts) != 3 {
		return "", 0, "", fmt.Errorf("invalid authorization format")
	}
	agentID = parts[0]
	timestamp, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", 0, "", fmt.Errorf("invalid timestamp")
	}
	return agentID, timestamp, parts[2], nil
}
