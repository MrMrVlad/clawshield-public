package actions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SleuthCo/clawshield/shared/models"
)

func TestApplyLockdown(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDispatcher(Config{
		PolicyPath:          filepath.Join(dir, "policy.yaml"),
		EmergencyPolicyPath: filepath.Join(dir, "emergency.yaml"),
		ProxyBinaryPath:     filepath.Join(dir, "proxy"),
		HubURL:              "https://127.0.0.1:18800",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(models.EmergencyLockdownAction{Enabled: true, Reason: "test"})
	if err := d.Apply(models.Action{Type: "emergency_lockdown", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "emergency.yaml")); err != nil {
		t.Fatal("emergency policy not written")
	}
}

func TestValidateDownloadURLRejectsHTTP(t *testing.T) {
	d, _ := NewDispatcher(Config{
		PolicyPath:        filepath.Join(t.TempDir(), "p.yaml"),
		ProxyBinaryPath:   filepath.Join(t.TempDir(), "bin"),
		HubURL:            "https://hub.example.com",
	})
	err := d.validateDownloadURL("http://evil.example/binary")
	if err == nil {
		t.Fatal("expected https-only error")
	}
}
