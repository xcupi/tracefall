package api

import (
	"os"
	"path/filepath"
	"testing"
	"tracefall/internal/model"
)

func TestMSSQLTextTreeAPIIdentity(t *testing.T) {
	mux := newTestRouter(t)
	c := createTestCase(t, mux, "SQL text evidence")
	for round := 0; round < 2; round++ {
		root := t.TempDir()
		files := map[string]string{
			"SQL/ERRORLOG":     "2026-01-15T09:15:30Z Server      Microsoft SQL Server 2022\n2026-01-15T09:15:30Z Server      Microsoft SQL Server 2022\n",
			"SQL/SQLAGENT.OUT": "2026-01-15 09:15:30 - ? [100] Microsoft SQLServerAgent version 16.0\n",
			"other/ERRORLOG":   "unrelated application errors\n",
		}
		if round == 1 {
			files["recollection-note.txt"] = "second acquisition"
		}
		for name, text := range files {
			p := filepath.Join(root, name)
			os.MkdirAll(filepath.Dir(p), 0700)
			if err := os.WriteFile(p, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
		}
		var d DiscoverResult
		r := doJSON(t, mux, "POST", "/api/cases/"+c.ID+"/ingest", map[string]string{"path": root}, &d)
		if r.Code != 200 {
			t.Fatal(r.Body.String())
		}
		_, im := importAll(t, mux, c.ID, d)
		if round == 0 && im.EventCount != 3 {
			t.Fatalf("SQL events=%d want 3", im.EventCount)
		}
		var timeline []model.Event
		r = doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/timeline", nil, &timeline)
		if r.Code != 200 {
			t.Fatal(r.Body.String())
		}
		if len(timeline) != 3 {
			t.Fatalf("round %d persisted=%d want 3", round, len(timeline))
		}
		for _, e := range timeline {
			if e.SourceReference == "" || e.RawEvidenceID == "" {
				t.Fatal("missing provenance", e)
			}
			var p EventProvenance
			rec := doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/"+e.ID, nil, &p)
			if rec.Code != 200 || len(p.Observations) != round+1 {
				t.Fatalf("observation count round=%d: %+v body=%s", round, p, rec.Body.String())
			}
			seen := map[string]bool{}
			for _, o := range p.Observations {
				if o.RawEvidenceID == "" || seen[o.RawEvidenceID] {
					t.Fatal("raw observation identity lost", p)
				}
				seen[o.RawEvidenceID] = true
			}
			if p.RawEvidence.Raw == "" || p.RawEvidence.SourceReference != e.SourceReference {
				t.Fatal("raw provenance lost", p)
			}
			if e.FilePath != "SQL/ERRORLOG" && e.FilePath != "SQL/SQLAGENT.OUT" {
				t.Fatal("server identity leak", e.FilePath)
			}
		}
	}
}
