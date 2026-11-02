package store

import (
	"testing"
	"tracefall/internal/model"
)

func TestFailedSourceRetryRefusesHistoricalPartialRows(t *testing.T) {
	for _, kind := range []string{"raw", "event", "observation"} {
		t.Run(kind, func(t *testing.T) {
			s := openTest(t)
			seedCaseAndSourceFile(t, s)
			if err := s.MarkSourceFileFailed("sf-1"); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "raw":
				if err := s.SaveRawEvidence([]model.RawEvidence{{ID: "raw-1", CaseID: "case-1", SourceFileID: "sf-1", SourceReference: "line:1", Raw: "record"}}); err != nil {
					t.Fatal(err)
				}
			case "event":
				if err := s.SaveEvents([]model.Event{{ID: "event-1", CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1"}}); err != nil {
					t.Fatal(err)
				}
			case "observation":
				if err := s.SaveSourceFiles([]model.SourceFile{{ID: "sf-2", CaseID: "case-1", CollectionID: "collection-1", SHA256: "different", ImportStatus: model.SourceFileImported}}); err != nil {
					t.Fatal(err)
				}
				if err := s.SaveEvents([]model.Event{{ID: "event-2", CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-2"}}); err != nil {
					t.Fatal(err)
				}
				if err := s.SaveEventObservations([]model.EventObservation{{ID: "obs-1", EventID: "event-2", CaseID: "case-1", CollectionID: "collection-1", SourceFileID: "sf-1"}}); err != nil {
					t.Fatal(err)
				}
			}
			applied, err := s.RetryFailedSource("sf-1")
			if err != nil || applied {
				t.Fatalf("historical %s partial admitted: applied=%v err=%v", kind, applied, err)
			}
			sf, err := s.GetSourceFile("sf-1")
			if err != nil || sf.ImportStatus != model.SourceFileFailed {
				t.Fatalf("status changed: %s err=%v", sf.ImportStatus, err)
			}
		})
	}
}

// A failed source keeps the coverage the parser measured, but never claims it
// emitted events: whatever batches existed were discarded (added after review).
func TestMarkSourceFileFailedWithCoverageForcesZeroEmitted(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	five := 5
	if err := s.MarkSourceFileFailedWithCoverage("sf-1", &model.ParseCoverage{RecordsRead: 9, EmittedEvents: &five}); err != nil {
		t.Fatal(err)
	}
	sf, err := s.GetSourceFile("sf-1")
	if err != nil {
		t.Fatal(err)
	}
	c := sf.ParseCoverage
	if sf.ImportStatus != model.SourceFileFailed || c == nil || c.RecordsRead != 9 || c.EmittedEvents == nil || *c.EmittedEvents != 0 {
		t.Fatalf("status=%s coverage=%+v", sf.ImportStatus, c)
	}
	if five != 5 {
		t.Error("the caller's coverage must not be modified")
	}
}
