package collector

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SleuthCo/clawshield/shared/models"
)

// ProxyStatus represents the status returned by the ClawShield proxy.
type ProxyStatus struct {
	Version       string `json:"version"`
	PolicyHash    string `json:"policy_hash"`
	PolicyVersion string `json:"policy_version"`
	Status        string `json:"status"`
	Uptime        int64  `json:"uptime_seconds"`
}

// LocalStatus contains all locally-collected status information.
type LocalStatus struct {
	ProxyStatus      *ProxyStatus
	AuditDBSize      int64
	ProxyReachable   bool
	CollectedAt      time.Time
	MetricsSummary   models.MetricsSummary
	EncryptionKeyID  string
}

// Collector gathers status from the local ClawShield proxy.
type Collector struct {
	ProxyURL          string
	AuditDBPath       string
	EncryptionKeyPath string
	Client            *http.Client
}

// NewCollector creates a collector with sensible defaults.
func NewCollector(proxyURL, auditDBPath string) *Collector {
	return &Collector{
		ProxyURL:    proxyURL,
		AuditDBPath: auditDBPath,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Collect gathers all locally-available status information.
func (c *Collector) Collect() *LocalStatus {
	status := &LocalStatus{
		CollectedAt: time.Now(),
		MetricsSummary: models.MetricsSummary{
			PeriodSeconds: 60,
		},
	}

	proxyStatus, err := c.collectProxyStatus()
	if err == nil {
		status.ProxyStatus = proxyStatus
		status.ProxyReachable = true
	}

	status.AuditDBSize = c.collectAuditDBSize()
	status.MetricsSummary = c.collectMetricsFromProxy()
	status.EncryptionKeyID = c.collectEncryptionKeyID()

	return status
}

// ProxyVersion returns proxy version string or empty.
func (s *LocalStatus) ProxyVersion() string {
	if s.ProxyStatus != nil {
		return s.ProxyStatus.Version
	}
	return ""
}

func (c *Collector) collectProxyStatus() (*ProxyStatus, error) {
	url := c.ProxyURL + "/api/v1/status"
	resp, err := c.Client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to reach proxy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned status %d", resp.StatusCode)
	}

	var status ProxyStatus
	limitedBody := io.LimitReader(resp.Body, 64*1024)
	if err := json.NewDecoder(limitedBody).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to parse proxy response: %w", err)
	}
	return &status, nil
}

func (c *Collector) collectMetricsFromProxy() models.MetricsSummary {
	summary := models.MetricsSummary{
		PeriodSeconds:     60,
		ScannerDetections: make(map[string]int),
	}
	resp, err := c.Client.Get(c.ProxyURL + "/metrics")
	if err != nil {
		return summary
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return summary
	}
	body := io.LimitReader(resp.Body, 512*1024)
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsePrometheusLine(line, &summary)
	}
	return summary
}

func parsePrometheusLine(line string, summary *models.MetricsSummary) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	name := parts[0]
	if idx := strings.Index(name, "{"); idx > 0 {
		name = name[:idx]
	}
	val, err := strconv.ParseFloat(parts[len(parts)-1], 64)
	if err != nil {
		return
	}
	n := int(val)
	switch name {
	case "clawshield_requests_total":
		summary.DecisionsTotal = n
	case "clawshield_decisions_denied_total":
		summary.DecisionsDenied = n
	case "clawshield_scanner_detections_total":
		// Labeled lines handled below via full line parse
		if strings.Contains(line, "scanner=\"") {
			scanner := extractLabel(line, "scanner")
			if scanner != "" {
				summary.ScannerDetections[scanner] += n
			}
		}
	}
}

func extractLabel(line, key string) string {
	needle := key + "=\""
	i := strings.Index(line, needle)
	if i < 0 {
		return ""
	}
	start := i + len(needle)
	end := strings.Index(line[start:], "\"")
	if end < 0 {
		return ""
	}
	return line[start : start+end]
}

func (c *Collector) collectEncryptionKeyID() string {
	path := c.EncryptionKeyPath
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

func (c *Collector) collectAuditDBSize() int64 {
	info, err := os.Stat(c.AuditDBPath)
	if err != nil {
		return 0
	}
	return info.Size()
}
