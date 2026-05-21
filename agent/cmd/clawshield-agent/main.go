package main

import (
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
	encryptionKeyPath := flag.String("encryption-key-path", "/var/lib/clawshield/audit-encryption.key", "Path for audit encryption key material")

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

	agentID, err := getOrEnrollAgent(*hubURL, *enrollmentToken, *agentIDFile)
	if err != nil {
		log.Fatalf("failed to get or create agent ID: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	coll := collector.NewCollector(*proxyURL, *auditDBPath)
	hubClient := checkin.NewClient(*hubURL)

	dispatcher, err := actions.NewDispatcher(actions.Config{
		PolicyPath:        *policyPath,
		EncryptionKeyPath: *encryptionKeyPath,
		ProxyBinaryPath:   *proxyBinary,
		HubURL:            *hubURL,
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

			req := &models.CheckinRequest{
				AgentID:           agentID,
				Hostname:          hostname,
				ClawshieldVersion: status.ProxyVersion(),
				AgentVersion:      agentVersion,
				Health:            health,
				MetricsSummary:    status.MetricsSummary,
			}

			if status.ProxyStatus != nil {
				req.PolicyHash = status.ProxyStatus.PolicyHash
				req.PolicyVersion = status.ProxyStatus.PolicyVersion
				req.UptimeSeconds = status.ProxyStatus.Uptime
				req.EncryptionKeyID = status.EncryptionKeyID
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

func getOrEnrollAgent(hubURL, enrollmentToken, agentIDFile string) (string, error) {
	if data, err := os.ReadFile(agentIDFile); err == nil {
		agentID := strings.TrimSpace(string(data))
		log.Printf("using existing agent ID from %s", agentIDFile)
		return agentID, nil
	}

	if enrollmentToken == "" {
		return "", fmt.Errorf("agent ID not found and no --enrollment-token provided")
	}

	log.Println("enrolling with Hub...")
	hostname, _ := os.Hostname()
	hubClient := checkin.NewClient(hubURL)
	resp, err := hubClient.Enroll(enrollmentToken, hostname, []string{})
	if err != nil {
		return "", fmt.Errorf("enrollment failed: %w", err)
	}

	if err := os.WriteFile(agentIDFile, []byte(resp.AgentID), 0600); err != nil {
		return "", fmt.Errorf("save agent ID: %w", err)
	}
	log.Printf("enrolled agent_id=%s", resp.AgentID)
	return resp.AgentID, nil
}
