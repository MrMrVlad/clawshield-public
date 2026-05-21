package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// InitAgentAuthSchema adds encrypted agent secret storage.
func (s *Store) InitAgentAuthSchema() error {
	_, err := s.db.Exec(`ALTER TABLE agents ADD COLUMN agent_secret_enc TEXT DEFAULT ''`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

// SetAgentSecretEnc stores the encrypted agent check-in secret.
func (s *Store) SetAgentSecretEnc(agentID, secretEnc string) error {
	res, err := s.db.Exec(`UPDATE agents SET agent_secret_enc = ? WHERE agent_id = ?`, secretEnc, agentID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("agent not found")
	}
	return nil
}

// GetAgentSecretEnc returns the encrypted agent secret blob, or empty if unset.
func (s *Store) GetAgentSecretEnc(agentID string) (string, error) {
	var enc sql.NullString
	err := s.db.QueryRow(`SELECT agent_secret_enc FROM agents WHERE agent_id = ?`, agentID).Scan(&enc)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if enc.Valid {
		return enc.String, nil
	}
	return "", nil
}
