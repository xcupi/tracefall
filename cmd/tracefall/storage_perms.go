package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// lockDownStorage makes the data directory owner-only (0700) and the database
// file and its SQLite sidecars owner-only (0600). The directory is created if
// missing. Opening a directory with 0700 blocks other users from every file
// beneath it, including ones created later with a looser mode.
func lockDownStorage(dataDir, dbPath string) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("creating the data directory: %w", err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return fmt.Errorf("restricting the data directory: %w", err)
	}
	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating the database directory: %w", err)
		}
	}
	// Create the database file closed to others before SQLite opens it, so it
	// is never briefly world-readable. The WAL and shared-memory files SQLite
	// adds take the main file's mode.
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("preparing the database file: %w", err)
	}
	f.Close()
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("restricting %s: %w", p, err)
		}
	}
	return nil
}
