package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/SleuthCo/clawshield/agent/internal/actions"
	"github.com/SleuthCo/clawshield/agent/internal/checkin"
	"github.com/SleuthCo/clawshield/agent/internal/collector"
	"github.com/SleuthCo/clawshield/agent/internal/trust"
	"github.com/SleuthCo/clawshield/shared/models"
)

const agentVersion = "1.1.0"

func main() {
	hubURL := flag.String("hub-url", "", "URL of the ClawShield Management Hub (required)")
	enrollmentToken := flag.String("enrollment-token", "", "Enrollment token for first-time registration")
	proxyURL := flag.String("proxy-url", "http://localhost:18789", "URL of the local ClawShield proxy")
	auditDBPath := flag.String("audit-db-path", "/var/lib/clawshield/audit.db", "Path to the audit database file")
	policyPath := flag.String("policy-path", "/var/lib/clawshield/policy.yaml", "Path to policy.yaml for Hub updates")
	proxyBinary := flag.String("proxy-binary", "/usr/local/bin/clawshield-proxy", "Path to clawshield-proxy binary for updates")
	checkinInterval := flag.Duration("checkin-interval", 60*time.Second, "Interval between check-ins to the Hub")
	agentIDFile := flag.String("agent-id-file", "/var/lib/clawshield/agent-id", "File to store the agent ID")
	agentSecretFile := flag.String("agent-secret-file", "/var/lib/clawshield/agent-secret", "File to store the agent check-in secret (0600)")
	encryptionKeyPath := flag.String("encryption-key-path", "/var/lib/clawshield/audit-encryption.key", "Path for audit encryption key material")
	policyPubKeyPath := flag.String("policy-pubkey", os.Getenv("CLAWSHIELD_POLICY_PUBLIC_KEY"), "PEM file with Hub policy signing public key")
	releasePubKeyPath := flag.String("release-pubkey", os.Getenv("CLAWSHIELD_RELEASE_PUBLIC_KEY"), "PEM file with release binary signing public key")

	flag.Parse()

	if *hubURL == "" {
		log.Fatal("--hub-url is required")
	}
	if err := actions.RequireTLSHub(*hubURL); err != nil {
		log.Fatalf("hub URL security: %v", err)
	}

	agentIDDir := filepath.Dir(*agentIDFile)
	if agentIDDir != "." && agentIDDir != "" {
		if err := os.MkdirAll(agentIDDir, 0750); err != nil {
			log.Fatalf("failed to create directory for agent ID file: %v", err)
		}
	}

	hubClient := checkin.NewClient(*hubURL)
	agentID, err := getOrEnrollAgent(hubClient, *enrollmentToken, *agentIDFile, *agentSecretFile)
	if err != nil {
		log.Fatalf("failed to get or create agent ID: %v", err)
	}
	hubClient.SetAgentCredentials(agentID, hubClient.AgentSecret)

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	policyPub, err := trust.LoadRSAPublicKeyPEM(*policyPubKeyPath)
	if err != nil {
		log.Fatalf("policy public key: %v", err)
	}
	if policyPub == nil {
		log.Fatal("policy public key required: set --policy-pubkey or CLAWSHIELD_POLICY_PUBLIC_KEY")
	}
	releasePub, err := trust.LoadRSAPublicKeyPEM(*releasePubKeyPath)
	if err != nil {
		log.Fatalf("release public key: %v", err)
	}

	coll := collector.NewCollector(*proxyURL, *auditDBPath)

	dispatcher, err := actions.NewDispatcher(actions.Config{
		PolicyPath:        *policyPath,
		EncryptionKeyPath: *encryptionKeyPath,
		ProxyBinaryPath:   *proxyBinary,
		HubURL:            *hubURL,
		PolicyPublicKey:   policyPub,
		ReleasePublicKey:  releasePub,
		HubClient:         hubClient,
	})
	if err != nil {
		log.Fatalf("dispatcher: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(*checkinInterval)
	defer ticker.Stop()

	log.Printf("ClawShield agent %s starting (agent_id=%s)", agentVersion, agentID)

	for {
		select {
		case <-sigChan:
			log.Println("shutdown signal received")
			return

		case <-ticker.C:
			status := coll.Collect()

			health := models.AgentHealth{
				Status:           "healthy",
				AuditDBSizeBytes: status.AuditDBSize,
			}
			if !status.ProxyReachable {
				health.Status = "degraded"
			}

			clawVersion := "unknown"
			if status.ProxyStatus != nil && status.ProxyStatus.Version != "" {
				clawVersion = status.ProxyStatus.Version
			}

			req := &models.CheckinRequest{
				AgentID:           agentID,
				Hostname:          hostname,
				ClawshieldVersion: clawVersion,
				AgentVersion:      agentVersion,
				Health:            health,
			}

			if status.ProxyStatus != nil {
				req.PolicyHash = status.ProxyStatus.PolicyHash
				req.PolicyVersion = status.ProxyStatus.PolicyVersion
				req.UptimeSeconds = status.ProxyStatus.Uptime
				req.EncryptionKeyID = readEncryptionKeyID(*encryptionKeyPath)
			}

			resp, err := hubClient.Checkin(req)
			if err != nil {
				log.Printf("check-in failed: %v", err)
				continue
			}

			log.Printf("check-in ok: actions=%d next=%ds", len(resp.Actions), resp.NextCheckinSeconds)

			if err := dispatcher.ApplyAll(resp.Actions); err != nil {
				log.Printf("apply actions: %v", err)
			}
		}
	}
}

func readEncryptionKeyID(path string) string {
	if path == "" {
		path = os.Getenv("CLAWSHIELD_AUDIT_ENCRYPTION_KEY_FILE")
	}
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	hexKey := strings.TrimSpace(string(data))
	if len(hexKey) >= 8 {
		return "local-" + hexKey[:8]
	}
	return ""
}

func getOrEnrollAgent(hubClient *checkin.Client, enrollmentToken, agentIDFile, agentSecretFile string) (string, error) {
	if data, err := os.ReadFile(agentIDFile); err == nil {
		agentID := strings.TrimSpace(string(data))
		secretHex, err := os.ReadFile(agentSecretFile)
		if err != nil {
			return "", fmt.Errorf("agent ID present but secret file missing (%s): enroll again or restore secret", agentSecretFile)
		}
		if err := hubClient.SetAgentSecretHex(strings.TrimSpace(string(secretHex))); err != nil {
			return "", err
		}
		log.Printf("using existing agent ID from %s", agentIDFile)
		return agentID, nil
	}

	if enrollmentToken == "" {
		return "", fmt.Errorf("agent ID not found and no --enrollment-token provided")
	}

	log.Println("enrolling with Hub...")
	hostname, _ := os.Hostname()
	resp, err := hubClient.Enroll(enrollmentToken, hostname, []string{})
	if err != nil {
		return "", fmt.Errorf("enrollment failed: %w", err)
	}

	if err := os.WriteFile(agentIDFile, []byte(resp.AgentID), 0600); err != nil {
		return "", fmt.Errorf("save agent ID: %w", err)
	}
	if resp.AgentSecret == "" {
		return "", fmt.Errorf("hub did not return agent_secret")
	}
	if err := os.WriteFile(agentSecretFile, []byte(resp.AgentSecret), 0600); err != nil {
		return "", fmt.Errorf("save agent secret: %w", err)
	}
	if _, err := hex.DecodeString(resp.AgentSecret); err != nil {
		return "", fmt.Errorf("invalid agent secret from hub: %w", err)
	}
	log.Printf("enrolled agent_id=%s", resp.AgentID)
	return resp.AgentID, nil
}
