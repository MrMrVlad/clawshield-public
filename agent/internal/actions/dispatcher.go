// Package actions applies Hub-issued fleet commands with defense-in-depth validation.
package actions

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/SleuthCo/clawshield/agent/internal/checkin"
	"github.com/SleuthCo/clawshield/agent/internal/policy"
	"github.com/SleuthCo/clawshield/agent/internal/updater"
	"github.com/SleuthCo/clawshield/shared/auth"
	"github.com/SleuthCo/clawshield/shared/models"
	"github.com/SleuthCo/clawshield/shared/release"
)

// Config holds paths and trust material for the action dispatcher.
type Config struct {
	PolicyPath          string
	EncryptionKeyPath   string // file receiving CLAWSHIELD_AUDIT_ENCRYPTION_KEY (0600)
	EmergencyPolicyPath string // written on lockdown
	ProxyBinaryPath     string
	HubURL              string
	PolicyPublicKey      *rsa.PublicKey
	ReleasePublicKey     *rsa.PublicKey
	AllowedDownloadHosts []string // optional; empty = hub host only
	HubClient            *checkin.Client // signed release downloads
}

// Dispatcher applies Hub actions sequentially; stops on first hard failure.
type Dispatcher struct {
	cfg     Config
	applier *policy.Applier
	binary  *updater.Updater
}

// NewDispatcher creates a dispatcher with validated configuration.
func NewDispatcher(cfg Config) (*Dispatcher, error) {
	if cfg.PolicyPath == "" {
		return nil, fmt.Errorf("policy path required")
	}
	if cfg.EncryptionKeyPath == "" {
		cfg.EncryptionKeyPath = "/var/lib/clawshield/audit-encryption.key"
	}
	if cfg.EmergencyPolicyPath == "" {
		cfg.EmergencyPolicyPath = filepath.Join(filepath.Dir(cfg.PolicyPath), "policy.emergency.yaml")
	}
	if cfg.ProxyBinaryPath == "" {
		return nil, fmt.Errorf("proxy binary path required")
	}
	if cfg.HubURL == "" {
		return nil, fmt.Errorf("hub URL required")
	}
	if _, err := url.Parse(cfg.HubURL); err != nil {
		return nil, fmt.Errorf("invalid hub URL: %w", err)
	}
	return &Dispatcher{
		cfg:     cfg,
		applier: policy.NewApplier(cfg.PolicyPath, cfg.PolicyPublicKey),
		binary:  updater.NewUpdater(cfg.ProxyBinaryPath),
	}, nil
}

// ApplyAll executes actions in a fixed security-prioritized order.
func (d *Dispatcher) ApplyAll(actions []models.Action) error {
	ordered := prioritize(actions)
	var errs []string
	for _, a := range ordered {
		if err := d.Apply(a); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", a.Type, err))
			log.Printf("action failed type=%s err=%v", a.Type, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("actions: %s", strings.Join(errs, "; "))
	}
	return nil
}

func prioritize(actions []models.Action) []models.Action {
	order := map[string]int{
		"emergency_lockdown":      0,
		"rotate_encryption_key":   1,
		"update_policy":           2,
		"update_binary":           3,
	}
	out := make([]models.Action, len(actions))
	copy(out, actions)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if order[out[j].Type] < order[out[i].Type] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Apply executes a single Hub action after validation.
func (d *Dispatcher) Apply(action models.Action) error {
	switch action.Type {
	case "update_policy":
		return d.applyPolicy(action.Payload)
	case "rotate_encryption_key":
		return d.applyKeyRotation(action.Payload)
	case "update_binary":
		return d.applyBinaryUpdate(action.Payload)
	case "emergency_lockdown":
		return d.applyLockdown(action.Payload)
	default:
		return fmt.Errorf("unsupported action type %q", action.Type)
	}
}

func (d *Dispatcher) applyPolicy(payload json.RawMessage) error {
	var p models.PolicyUpdateAction // shared/models
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("decode policy action: %w", err)
	}
	if len(p.PolicyYAML) > 2*1024*1024 {
		return fmt.Errorf("policy YAML exceeds 2MiB limit")
	}
	if p.PolicyHash != "" {
		if h, err := d.applier.CurrentHash(); err == nil && h != "" && h == p.PolicyHash {
			log.Printf("policy already at hash %s, skipping write", p.PolicyHash)
			return nil
		}
	}
	return d.applier.Apply(p.PolicyYAML, p.Signature)
}

func (d *Dispatcher) applyKeyRotation(payload json.RawMessage) error {
	var k models.KeyRotateAction
	if err := json.Unmarshal(payload, &k); err != nil {
		return fmt.Errorf("decode key action: %w", err)
	}
	if d.cfg.HubClient == nil || len(d.cfg.HubClient.AgentSecret) != auth.AgentSecretSize {
		return fmt.Errorf("agent secret required to unwrap key material")
	}
	keyHex, err := auth.UnwrapDEKForAgent(k.KeyMaterial, d.cfg.HubClient.AgentSecret)
	if err != nil {
		return fmt.Errorf("unwrap key material: %w", err)
	}
	if len(keyHex) != 64 {
		return fmt.Errorf("key material must be 64 hex chars (32 bytes), got %d", len(keyHex))
	}
	for _, c := range keyHex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return fmt.Errorf("key material must be hexadecimal")
		}
	}
	dir := filepath.Dir(d.cfg.EncryptionKeyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	tmp := d.cfg.EncryptionKeyPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(keyHex+"\n"), 0600); err != nil {
		return fmt.Errorf("write key temp: %w", err)
	}
	if err := os.Rename(tmp, d.cfg.EncryptionKeyPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install key: %w", err)
	}
	log.Printf("encryption key rotated key_id=%s (restart proxy to load)", k.KeyID)
	return nil
}

func (d *Dispatcher) applyBinaryUpdate(payload json.RawMessage) error {
	var u models.UpdateBinaryAction
	if err := json.Unmarshal(payload, &u); err != nil {
		return fmt.Errorf("decode update action: %w", err)
	}
	if u.DownloadURL == "" || u.BinaryHash == "" {
		return fmt.Errorf("download_url and binary_hash required")
	}
	if err := d.validateDownloadURL(u.DownloadURL); err != nil {
		return err
	}
	if d.cfg.ReleasePublicKey != nil {
		if err := release.VerifyBinaryHashSignature(u.BinaryHash, u.Signature, d.cfg.ReleasePublicKey); err != nil {
			return err
		}
	}
	tmpPath := d.cfg.ProxyBinaryPath + ".download"
	defer os.Remove(tmpPath)
	if err := d.downloadBinary(u.DownloadURL, tmpPath); err != nil {
		return err
	}
	if err := d.binary.Apply(tmpPath, u.BinaryHash); err != nil {
		_ = d.binary.Rollback()
		return err
	}
	log.Printf("binary updated to version %s", u.Version)
	return nil
}

func (d *Dispatcher) applyLockdown(payload json.RawMessage) error {
	var l models.EmergencyLockdownAction
	if err := json.Unmarshal(payload, &l); err != nil {
		return fmt.Errorf("decode lockdown action: %w", err)
	}
	if !l.Enabled {
		if err := os.Remove(d.cfg.EmergencyPolicyPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear emergency policy: %w", err)
		}
		log.Printf("emergency lockdown cleared")
		return nil
	}
	emergencyYAML := []byte(`# ClawShield emergency lockdown — Hub-issued
default_action: deny
evaluation_timeout_ms: 50
max_message_bytes: 65536
denylist: []
allowlist: []
`)
	dir := filepath.Dir(d.cfg.EmergencyPolicyPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("emergency policy dir: %w", err)
	}
	tmp := d.cfg.EmergencyPolicyPath + ".tmp"
	if err := os.WriteFile(tmp, emergencyYAML, 0640); err != nil {
		return fmt.Errorf("write emergency policy: %w", err)
	}
	if err := os.Rename(tmp, d.cfg.EmergencyPolicyPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install emergency policy: %w", err)
	}
	log.Printf("emergency lockdown enabled reason=%q", l.Reason)
	return nil
}

func (d *Dispatcher) validateDownloadURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid download URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("download URL must use https, got %q", u.Scheme)
	}
	hub, _ := url.Parse(d.cfg.HubURL)
	allowed := map[string]struct{}{}
	if hub != nil && hub.Host != "" {
		allowed[hub.Host] = struct{}{}
	}
	for _, h := range d.cfg.AllowedDownloadHosts {
		allowed[h] = struct{}{}
	}
	if len(allowed) > 0 {
		if _, ok := allowed[u.Host]; !ok {
			return fmt.Errorf("download host %q not in allowlist", u.Host)
		}
	}
	return nil
}

// RequireTLSHub returns an error if hubURL is not https (except localhost dev).
func RequireTLSHub(hubURL string) error {
	u, err := url.Parse(hubURL)
	if err != nil {
		return err
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost") {
		log.Printf("WARNING: Hub URL uses HTTP on localhost — not for production")
		return nil
	}
	return fmt.Errorf("hub URL must use https in production, got %q", u.Scheme)
}

func (d *Dispatcher) downloadBinary(downloadURL, destPath string) error {
	if d.cfg.HubClient != nil && len(d.cfg.HubClient.AgentSecret) == auth.AgentSecretSize {
		u, err := url.Parse(downloadURL)
		if err != nil {
			return err
		}
		req, err := d.cfg.HubClient.NewAuthenticatedGET(downloadURL, u.Path)
		if err != nil {
			return err
		}
		return d.binary.DownloadRequest(req, destPath)
	}
	return d.binary.Download(downloadURL, destPath)
}

// VerifyHubTLSConfig performs a TLS handshake with default certificate verification.
func VerifyHubTLSConfig(hubURL string) error {
	u, err := url.Parse(hubURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return nil
	}
	conn, err := tls.Dial("tcp", u.Host, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: u.Hostname(),
	})
	if err != nil {
		return err
	}
	return conn.Close()
}
