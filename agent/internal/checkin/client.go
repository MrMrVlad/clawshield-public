package checkin

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/SleuthCo/clawshield/shared/auth"
	"github.com/SleuthCo/clawshield/shared/models"
)

// Client communicates with the ClawShield Management Hub.
type Client struct {
	HubURL      string
	HTTPClient  *http.Client
	AgentID     string
	AgentSecret []byte // 32-byte secret from enrollment; required for check-in
}

// NewClient creates a new Hub client.
func NewClient(hubURL string) *Client {
	return &Client{
		HubURL: hubURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetAgentCredentials configures agent ID and HMAC secret for signed requests.
func (c *Client) SetAgentCredentials(agentID string, secret []byte) {
	c.AgentID = agentID
	c.AgentSecret = secret
}

// SetAgentSecretHex configures the secret from a hex string returned at enrollment.
func (c *Client) SetAgentSecretHex(hexSecret string) error {
	secret, err := hex.DecodeString(hexSecret)
	if err != nil {
		return fmt.Errorf("decode agent secret: %w", err)
	}
	if len(secret) != auth.AgentSecretSize {
		return fmt.Errorf("agent secret must be %d bytes", auth.AgentSecretSize)
	}
	c.AgentSecret = secret
	return nil
}

// Enroll sends an enrollment request to the Hub and returns the enrollment response.
func (c *Client) Enroll(token, hostname string, tags []string) (*models.EnrollmentResponse, error) {
	req := &models.EnrollmentRequest{
		Token:    token,
		Hostname: hostname,
		Tags:     tags,
	}
	result := &models.EnrollmentResponse{}
	if err := c.doPost("/api/v1/enroll", req, result, false, ""); err != nil {
		return nil, err
	}
	if result.AgentSecret != "" {
		if err := c.SetAgentSecretHex(result.AgentSecret); err != nil {
			return nil, err
		}
	}
	c.AgentID = result.AgentID
	return result, nil
}

// Checkin sends a check-in request to the Hub and returns the check-in response.
func (c *Client) Checkin(req *models.CheckinRequest) (*models.CheckinResponse, error) {
	result := &models.CheckinResponse{}
	if err := c.doPost("/api/v1/checkin", req, result, true, req.AgentID); err != nil {
		return nil, err
	}
	return result, nil
}

// NewAuthenticatedGET creates an HTTP GET request signed with the agent secret.
func (c *Client) NewAuthenticatedGET(url string, path string) (*http.Request, error) {
	if len(c.AgentSecret) != auth.AgentSecretSize || c.AgentID == "" {
		return nil, fmt.Errorf("agent credentials not configured")
	}
	ts := time.Now().UTC().Unix()
	sig := auth.SignGETRequest(c.AgentSecret, c.AgentID, ts, path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", auth.FormatAuthorizationHeader(c.AgentID, ts, sig))
	return req, nil
}

func (c *Client) doPost(path string, body interface{}, result interface{}, sign bool, agentID string) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	fullURL := c.HubURL + path
	httpReq, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if sign {
		if len(c.AgentSecret) != auth.AgentSecretSize {
			return fmt.Errorf("agent secret not configured for signed check-in")
		}
		if agentID == "" {
			return fmt.Errorf("agent id required for signed check-in")
		}
		ts := time.Now().UTC().Unix()
		sig := auth.SignCheckin(c.AgentSecret, agentID, ts, bodyBytes)
		httpReq.Header.Set("Authorization", auth.FormatAuthorizationHeader(agentID, ts, sig))
	}

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		limitedBody := io.LimitReader(resp.Body, 1024)
		respBody, _ := io.ReadAll(limitedBody)
		return fmt.Errorf("hub returned status %d: %s", resp.StatusCode, string(respBody))
	}

	limitedBody := io.LimitReader(resp.Body, 10*1024*1024)
	if err := json.NewDecoder(limitedBody).Decode(result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	return nil
}
