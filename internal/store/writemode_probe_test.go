package store

import (
	"fmt"
	"testing"
	"time"
)

// Why per-row writes cost what they do: the store opens SQLite with one
// connection and no explicit journal/synchronous setting, so every
// statement outside a transaction is its own durable commit.
func TestProbe_WriteModeAndCommitCost(t *testing.T) {
	s := openTest(t)
	db := s.DB()

	for _, p := range []string{"journal_mode", "synchronous", "cache_size"} {
		var v string
		if err := db.QueryRow("PRAGMA " + p).Scan(&v); err != nil {
			t.Logf("PRAGMA %s: %v", p, err)
			continue
		}
		t.Logf("PRAGMA %-13s = %s", p, v)
	}

	if _, err := db.Exec(`CREATE TABLE probe (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	const n = 2000

	start := time.Now()
	for i := 0; i < n; i++ {
		if _, err := db.Exec(`INSERT INTO probe (id, v) VALUES (?, '')`, i); err != nil {
			t.Fatal(err)
		}
	}
	autocommit := time.Since(start)

	start = time.Now()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := n; i < 2*n; i++ {
		if _, err := tx.Exec(`INSERT INTO probe (id, v) VALUES (?, '')`, i); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	batched := time.Since(start)

	t.Logf("%d writes, one statement per commit: %v (%v each)", n, autocommit, autocommit/n)
	t.Logf("%d writes, single transaction:      %v (%v each)", n, batched, batched/n)
	t.Logf("ratio: %s", fmt.Sprintf("%.1fx", float64(autocommit)/float64(batched)))
}
