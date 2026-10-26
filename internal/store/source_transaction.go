package store

import (
	"context"
	"database/sql"
)

// WithSourceTransaction admits a source's raw records, deduplicated events,
// observations and final imported status together. The callback receives a
// private transaction-bound view; the shared Store is never mutated. Only the
// source-write methods and FindEventByDedupHash may be used on this view.
// SQLite owns rollback recovery after process death. Batches still bound memory,
// but the transaction holds the database's writer/connection until completion.
func (s *Store) WithSourceTransaction(ctx context.Context, fn func(*Store) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	view := &Store{db: s.db, sourceTx: tx}
	if err = fn(view); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

type sourceExecutor interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) *sql.Row
}

func (s *Store) sourceExecutor() sourceExecutor {
	if s.sourceTx != nil {
		return s.sourceTx
	}
	return s.db
}

type sourceWriteTx struct {
	*sql.Tx
	borrowed bool
}

func (t sourceWriteTx) Commit() error {
	if t.borrowed {
		return nil
	}
	return t.Tx.Commit()
}
func (t sourceWriteTx) Rollback() error {
	if t.borrowed {
		return nil
	}
	return t.Tx.Rollback()
}
func (s *Store) beginSourceWrite() (sourceWriteTx, error) {
	if s.sourceTx != nil {
		return sourceWriteTx{s.sourceTx, true}, nil
	}
	tx, err := s.db.Begin()
	return sourceWriteTx{tx, false}, err
}
