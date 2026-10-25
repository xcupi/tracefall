package srum

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
)

// idStore is disposable, owner-only and disk-backed. SQLite's cache and page
// count are bounded independently of the number or size of source ID blobs.
type idStore struct {
	db  *sql.DB
	tx  *sql.Tx
	put *sql.Stmt
	get *sql.Stmt
	dir string
}

func idIndexError(err error) error {
	var code interface{ Code() int }
	if errors.As(err, &code) && code.Code()&255 == 13 {
		return fmt.Errorf("%w: temporary ID index full", ErrLimitExceeded)
	}
	return err
}

func openIDStore(ctx context.Context) (*idStore, error) {
	dir, err := os.MkdirTemp("", "tracefall-srum-*")
	if err != nil {
		return nil, err
	}
	s := &idStore{dir: dir}
	fail := func(err error) (*idStore, error) { s.close(); return nil, err }
	s.db, err = sql.Open("sqlite", filepath.Join(dir, "ids.db"))
	if err != nil {
		return fail(err)
	}
	s.db.SetMaxOpenConns(1)
	// This is a rebuildable index, never the source. Disable journaling to avoid
	// duplicate disk retention and cap the database at 1 GiB.
	for _, q := range []string{"PRAGMA page_size=4096", "PRAGMA max_page_count=262144", "PRAGMA cache_size=-4096", "PRAGMA mmap_size=0", "PRAGMA journal_mode=OFF", "PRAGMA synchronous=OFF", "CREATE TABLE ids(id INTEGER PRIMARY KEY,typ INTEGER,blob BLOB)"} {
		if _, err = s.db.ExecContext(ctx, q); err != nil {
			return fail(err)
		}
	}
	if err = os.Chmod(filepath.Join(dir, "ids.db"), 0600); err != nil {
		return fail(err)
	}
	s.tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	s.put, err = s.tx.PrepareContext(ctx, "INSERT OR REPLACE INTO ids(id,typ,blob) VALUES(?,?,?)")
	if err != nil {
		return fail(err)
	}
	return s, nil
}
func (s *idStore) finish(ctx context.Context) error {
	if err := s.put.Close(); err != nil {
		return err
	}
	s.put = nil
	if err := s.tx.Commit(); err != nil {
		return err
	}
	s.tx = nil
	var err error
	s.get, err = s.db.PrepareContext(ctx, "SELECT typ,blob FROM ids WHERE id=?")
	return err
}
func (s *idStore) lookup(ctx context.Context, id int64) (idEntry, bool, error) {
	var e idEntry
	err := s.get.QueryRowContext(ctx, id).Scan(&e.typ, &e.blob)
	if err == sql.ErrNoRows {
		return e, false, nil
	}
	return e, err == nil, err
}
func (s *idStore) close() {
	if s.put != nil {
		s.put.Close()
	}
	if s.get != nil {
		s.get.Close()
	}
	if s.tx != nil {
		s.tx.Rollback()
	}
	if s.db != nil {
		s.db.Close()
	}
	if s.dir != "" {
		os.Remove(filepath.Join(s.dir, "ids.db"))
		os.Remove(s.dir)
	}
}
