package store

import (
	"database/sql"
	"errors"
	"time"
)

// Application settings (Phase 14).
//
// A key/value store for APPLICATION-WIDE display preferences. It is
// deliberately separate from everything forensic: nothing written here
// may change stored evidence, timestamps, hashes or analysis results,
// and nothing here is exported with a case.

// GetSetting returns one setting's value, and whether it was set.
func (s *Store) GetSetting(key string) (string, bool, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM app_settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// SetSetting stores one setting, replacing any previous value.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
