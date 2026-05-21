package store

import "strings"

// InitLockdownSchema adds emergency lockdown column to agents.
func (s *Store) InitLockdownSchema() error {
	_, err := s.db.Exec(`ALTER TABLE agents ADD COLUMN emergency_lockdown INTEGER NOT NULL DEFAULT 0`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column") {
		return err
	}
	return nil
}

func (s *Store) SetEmergencyLockdown(agentID string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE agents SET emergency_lockdown = ? WHERE agent_id = ?`, v, agentID)
	return err
}

func (s *Store) GetEmergencyLockdown(agentID string) (bool, error) {
	var v int
	err := s.db.QueryRow(`SELECT COALESCE(emergency_lockdown, 0) FROM agents WHERE agent_id = ?`, agentID).Scan(&v)
	if err != nil {
		return false, err
	}
	return v != 0, nil
}
