package srum

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"tracefall/internal/ese"
	"tracefall/internal/ese/esegen"
	"tracefall/internal/parsers"
)

func TestStreamOversizedIDIsVisibleLimit(t *testing.T) {
	table := idMapTable(idRow(0, 1, nil))
	table.Records[0].Tagged = []esegen.Tagged{{ID: 256, Flags: esegen.TagSeparated, Data: esegen.Le32(1)}}
	table.HasLVTree = true
	table.LVLeafCapacity = 1
	lv := esegen.LongValue{ID: 1, Total: 65538}
	for off := 0; off < int(lv.Total); off += 1024 {
		n := 1024
		if int(lv.Total)-off < n {
			n = int(lv.Total) - off
		}
		lv.Segments = append(lv.Segments, esegen.Segment{Offset: uint32(off), Data: make([]byte, n)})
	}
	table.LongValues = []esegen.LongValue{lv}
	path := write(t, []esegen.Table{table, appTable(appRow(1, ole(t0), 1, 5, 1, 2, 3, 4, 5))}, esegen.Options{})
	cov, err := New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { t.Fatal("oversized ID emitted"); return nil })
	if !errors.Is(err, ErrLimitExceeded) || !cov.LimitReached || cov.RecordsFailed != 0 {
		t.Fatalf("ID budget not visible: %v %+v", err, cov)
	}
}

func TestStreamMalformedIDFailsClosed(t *testing.T) {
	bad := idRow(0, 1, utf16z("app.exe"))
	delete(bad.Fixed, 2)
	path := write(t, []esegen.Table{idMapTable(bad), appTable(appRow(1, ole(t0), 1, 5, 1, 2, 3, 4, 5))}, esegen.Options{})
	cov, err := New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { t.Fatal("malformed ID source emitted"); return nil })
	if err == nil || !errors.Is(err, ese.ErrCorrupt) || cov.RecordsFailed == 0 {
		t.Fatalf("malformed id accepted: %v %+v", err, cov)
	}
}

func TestIDIndexFullIsResourceLimit(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "ids.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{"PRAGMA max_page_count=2", "CREATE TABLE ids(b BLOB)"} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	_, err = db.Exec("INSERT INTO ids(b) VALUES(zeroblob(65536))")
	if err == nil {
		t.Fatal("fixture did not reach index budget")
	}
	if !errors.Is(idIndexError(err), ErrLimitExceeded) {
		t.Fatalf("index full not a reader limit: %v", err)
	}
}

func TestIDStoreBoundedAndRemoved(t *testing.T) {
	ctx := context.Background()
	s, err := openIDStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir := s.dir
	defer s.close()
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatal("unrestricted id index", st, err)
	}
	st, err = os.Stat(filepath.Join(dir, "ids.db"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("index file permissions %v %v", st, err)
	}
	// Replacement semantics must match the compatibility map.
	for _, v := range []string{"old", "new"} {
		if _, err = s.put.ExecContext(ctx, 7, 2, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.finish(ctx); err != nil {
		t.Fatal(err)
	}
	e, ok, err := s.lookup(ctx, 7)
	if err != nil || !ok || e.typ != 2 || string(e.blob) != "new" {
		t.Fatal(e, ok, err)
	}
	_, ok, err = s.lookup(ctx, 8)
	if err != nil || ok {
		t.Fatal("missing id", ok, err)
	}
	s.close()
	if _, err = os.Stat(filepath.Join(dir, "ids.db")); !os.IsNotExist(err) {
		t.Fatal("index leaked", err)
	}
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("directory leaked", err)
	}
}

func TestStreamIDMapCoverage(t *testing.T) {
	path := write(t, []esegen.Table{standardIDs(), appTable(appRow(1, ole(t0), 1, 5, 1, 2, 3, 4, 5))}, esegen.Options{})
	cov, err := New().ParseStream(context.Background(), path, parsers.ParseContext{}, func(parsers.ParseResult) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(cov.Notes, ";"), "id map: 6 live records") {
		t.Fatalf("id map source count missing: %+v", cov)
	}
}
