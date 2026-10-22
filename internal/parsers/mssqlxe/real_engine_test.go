package mssqlxe

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

// Engine-written binary files, each pinned by SHA-256 and compared with the
// engine's own reading of the same file (sys.fn_get_audit_file /
// sys.fn_xe_file_target_read_file). The files are never committed; a test skips
// when its variable is unset. The reader and runtime must be configured as for
// any native read, and audit additionally needs the explicit opt-in.
func TestRealEngineBinaryFiles(t *testing.T) {
	cases := []struct {
		env, sha string
		audit    bool
		events   int
		actions  map[string]int
	}{
		{"TRACEFALL_REAL_MSSQL_SQLAUDIT", "e703523764bd22eaea913e7bb9b144df41b6f7632027506e773977e0ec6469bf", true, 25,
			map[string]int{"AL": 1, "APRL": 1, "AUSC": 3, "CR": 1, "LGIF": 3, "LGIS": 16}},
		{"TRACEFALL_REAL_MSSQL_XEL_ENGINE_A", "dab4d6d1c19d441bd4757c53c61a9e2dcbb458eda38a041b80d516afd258efbf", false, 123, nil},
		{"TRACEFALL_REAL_MSSQL_XEL_ENGINE_B", "7637074bcadc02d1785d9f6175c79cb251494a49f0ffba90911daeb11f2ebcc2", false, 124, nil},
	}
	for _, c := range cases {
		t.Run(c.env, func(t *testing.T) {
			path := os.Getenv(c.env)
			if path == "" {
				t.Skip(c.env + " not set")
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(before)); got != c.sha {
				t.Fatalf("fixture hash mismatch: %s", got)
			}
			if c.audit {
				t.Setenv("TRACEFALL_MSSQL_AUDIT_EXPERIMENTAL", "1")
			}
			p := New()
			if c.audit {
				p = NewAudit()
			}
			r, err := p.Parse(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Events) != c.events {
				t.Fatalf("events=%d want %d (engine's own reading)", len(r.Events), c.events)
			}
			if c.actions != nil {
				got := map[string]int{}
				for _, e := range r.Events {
					got[e.Extra["sql_action"]]++
				}
				for k, v := range c.actions {
					if got[k] != v {
						t.Errorf("action %s = %d, want %d", k, got[k], v)
					}
				}
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("input mutated")
			}
		})
	}
}
