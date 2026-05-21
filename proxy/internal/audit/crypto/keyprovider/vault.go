package keyprovider

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/crypto"
)

// VaultProvider reads a hex DEK from HashiCorp Vault KV v2 (HTTPS + token).
type VaultProvider struct {
	Addr   string
	Token  string
	Path   string // e.g. secret/data/clawshield/audit-key
	Client *http.Client
}

// NewVaultProviderFromEnv configures Vault from CLAWSHIELD_VAULT_ADDR, _TOKEN, _KEY_PATH.
func NewVaultProviderFromEnv() (*VaultProvider, error) {
	addr := os.Getenv("CLAWSHIELD_VAULT_ADDR")
	token := os.Getenv("CLAWSHIELD_VAULT_TOKEN")
	path := os.Getenv("CLAWSHIELD_VAULT_KEY_PATH")
	if addr == "" || token == "" || path == "" {
		return nil, fmt.Errorf("vault provider requires CLAWSHIELD_VAULT_ADDR, _TOKEN, _KEY_PATH")
	}
	if !strings.HasPrefix(addr, "https://") {
		return nil, fmt.Errorf("vault addr must use https")
	}
	return &VaultProvider{
		Addr:  strings.TrimRight(addr, "/"),
		Token: token,
		Path:  strings.TrimPrefix(path, "/"),
		Client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (v *VaultProvider) Name() string { return "vault" }

func (v *VaultProvider) GetKey() ([]byte, error) {
	url := fmt.Sprintf("%s/v1/%s", v.Addr, v.Path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.Token)

	resp, err := v.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	hexKey := strings.TrimSpace(parsed.Data.Data["key"])
	if len(hexKey) != 64 {
		return nil, fmt.Errorf("vault key field must be 64 hex chars")
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(key) != crypto.KeySize {
		return nil, crypto.ErrInvalidKeySize
	}
	return key, nil
}
