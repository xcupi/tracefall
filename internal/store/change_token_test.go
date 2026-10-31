package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestChangeTokenReplacementIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replace.db")
	init, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = init.Close(); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	before, e := s.ChangeToken(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxIdleConns(0)
	after, e := s.ChangeToken(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if before.changes != after.changes || before.version != after.version {
		t.Fatal("fixture did not reproduce equal counters across replacement")
	}
	if before == after {
		t.Fatal("equal-counter replacement aliased old connection")
	}
}

func TestChangeTokenRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	token := func() ChangeToken {
		t.Helper()
		v, e := s.ChangeToken(ctx)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	exec := func(q string) {
		t.Helper()
		if _, e := s.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	exec(`CREATE TABLE token_test (id INTEGER PRIMARY KEY, value TEXT)`)
	exec(`INSERT INTO token_test VALUES(1,'a')`)
	before := token()
	if got := token(); got != before {
		t.Fatal("read-only token changed")
	}
	exec(`UPDATE token_test SET value='b' WHERE id=1`)
	if token() == before {
		t.Fatal("same-count same-connection update not detected")
	}
	before = token()
	tx, e := s.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(`UPDATE token_test SET value='rolled back'`); e != nil {
		t.Fatal(e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	// Rollback may conservatively invalidate; it must not mask later commits.
	before = token()
	exec(`UPDATE token_test SET value='c'`)
	if token() == before {
		t.Fatal("commit after rollback missed")
	}
	before = token()
	if _, e = s.db.Exec(`INSERT INTO token_test VALUES(1,'duplicate')`); e == nil {
		t.Fatal("expected failed write")
	}
	exec(`UPDATE token_test SET value='d'`)
	if token() == before {
		t.Fatal("commit after failure missed")
	}
	external, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer external.Close()
	before = token()
	if _, e = external.Exec(`UPDATE token_test SET value='external'`); e != nil {
		t.Fatal(e)
	}
	if token() == before {
		t.Fatal("external commit missed")
	}
	before = token()
	s.db.SetMaxIdleConns(0)
	after := token()
	if after == before {
		t.Fatal("replacement connection missed")
	}
	s.db.SetMaxIdleConns(1)
	cancel, c := context.WithCancel(ctx)
	c()
	if _, e = s.ChangeToken(cancel); e == nil {
		t.Fatal("cancellation ignored")
	}
}
