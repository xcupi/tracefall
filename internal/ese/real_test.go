package ese_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/ese"
)

// TestRealDatabases reads databases from a real Windows 10 collection and
// compares them with what two independent readers (libesedb through pyesedb,
// and dissect.esedb) made of the same bytes. Set TRACEFALL_REAL_ESE_DIR to a
// directory holding SRUDB.dat, WebCacheV01.dat, CacheStorage.edb and
// IndexedDB.edb; the files are pinned by SHA-256.
//
// What the comparison covers: the catalog, the number of live records per
// table (libesedb), the number of readable records (dissect), the bytes of
// every fixed and variable column of every readable record, and the decoded
// value of every tagged column (inline and separated long values, text) outside
// the engine's own system tables. It does not cover compressed or
// multi-valued columns: this collection has none; those paths are tested on
// generated databases in ese_test.go.
func TestRealDatabases(t *testing.T) {
	dir := os.Getenv("TRACEFALL_REAL_ESE_DIR")
	if dir == "" {
		t.Skip("TRACEFALL_REAL_ESE_DIR not set")
	}
	for name, want := range realManifest {
		name, want := name, want
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join(dir, name))
			if err != nil {
				t.Skipf("not present: %v", err)
			}
			defer f.Close()
			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != want.sha256 {
				t.Fatalf("file is not the pinned sample: sha256 %s", got)
			}
			st, _ := f.Stat()
			db, err := ese.Open(f, st.Size())
			if err != nil {
				t.Fatal(err)
			}
			if len(db.Tables()) != len(want.tables) {
				t.Errorf("%d tables, want %d", len(db.Tables()), len(want.tables))
			}
			for _, tb := range db.Tables() {
				w, ok := want.tables[tb.Name]
				if !ok {
					t.Errorf("table %q is not in the manifest", tb.Name)
					continue
				}
				fx, tg := sha256.New(), sha256.New()
				system := strings.HasPrefix(tb.Name, "MSys")
				cols := sortedColumns(tb)
				decodable := 0
				stats, err := tb.Scan(func(r ese.Row) error {
					decodable++
					var a, b []string
					for _, c := range cols {
						v, _ := r.Get(c.Name)
						if c.ID < 256 {
							if v.Err != nil {
								a = append(a, fmt.Sprintf("%d=ERR", c.ID))
							} else if v.Null {
								a = append(a, fmt.Sprintf("%d=NULL", c.ID))
							} else {
								a = append(a, fmt.Sprintf("%d=%x", c.ID, v.Raw))
							}
							continue
						}
						b = append(b, fmt.Sprintf("%d=%s", c.ID, taggedText(v)))
					}
					fx.Write([]byte(strings.Join(a, ";") + "\n"))
					if !system {
						tg.Write([]byte(strings.Join(b, ";") + "\n"))
					}
					return nil
				})
				if err != nil {
					t.Errorf("%s: %v", tb.Name, err)
					continue
				}
				if decodable != w.decodable {
					t.Errorf("%s: %d readable records, dissect has %d", tb.Name, decodable, w.decodable)
				}
				if stats.Live != w.live {
					t.Errorf("%s: %d live records, libesedb has %d", tb.Name, stats.Live, w.live)
				}
				if stats.Unreadable != 0 {
					t.Errorf("%s: %d live entries could not be read", tb.Name, stats.Unreadable)
				}
				if got := hex.EncodeToString(fx.Sum(nil)); got != w.fixedVar {
					t.Errorf("%s: fixed/variable column bytes differ from dissect", tb.Name)
				}
				if !system {
					if got := hex.EncodeToString(tg.Sum(nil)); got != w.tagged {
						t.Errorf("%s: tagged column values differ from dissect", tb.Name)
					}
				}
			}
		})
	}
}

func sortedColumns(tb *ese.Table) []*ese.Column {
	cols := append([]*ese.Column(nil), tb.Columns...)
	for i := 1; i < len(cols); i++ {
		for j := i; j > 0 && cols[j].ID < cols[j-1].ID; j-- {
			cols[j], cols[j-1] = cols[j-1], cols[j]
		}
	}
	return cols
}

// taggedText renders a tagged value the way the reference dump did: text as
// UTF-8 with its terminating NULs removed, anything else as hex, multi-values
// bracketed.
func taggedText(v ese.Value) string {
	enc := func(b []byte) string {
		if v.Col.Type == ese.TypeText || v.Col.Type == ese.TypeLongText {
			s := fmt.Sprintf("%x", []byte(ese.DecodeText(b, v.Col)))
			for strings.HasSuffix(s, "00") {
				s = s[:len(s)-2]
			}
			return "S" + s
		}
		return fmt.Sprintf("%x", b)
	}
	switch {
	case v.Err != nil:
		return "ERR:" + v.Err.Error()
	case v.Null:
		return "NULL"
	case v.Multi != nil:
		var m []string
		for _, x := range v.Multi {
			m = append(m, enc(x))
		}
		return "M[" + strings.Join(m, ",") + "]"
	}
	return enc(v.Raw)
}
