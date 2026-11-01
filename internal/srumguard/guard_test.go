package srumguard

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"tracefall/internal/correlate"
	"tracefall/internal/detect"
	"tracefall/internal/investigate"
	"tracefall/internal/model"
	"tracefall/internal/narrative"
)

// bigSent is a counter that, read as a transfer, would be a striking number.
const (
	bigSent = "53687091200"
	bigRecv = "1073741824"
)

var claim = regexp.MustCompile(`(?i)exfil|upload|download|transferr?ed|sent to|destination|remote (host|party|server|address)|stolen|\bleak|staging`)

func srumNetEvents(at time.Time) []model.Event {
	mk := func(i int, typ string, extra map[string]string) model.Event {
		extra["srum_table"] = "{T}"
		return model.Event{
			ID: fmt.Sprintf("srum-%d", i), CaseID: "case01", CollectionID: "col01", SourceFileID: "sf01", Host: "host01", User: "S-1-5-21-1-2-3-1001",
			Timestamp: at.Add(time.Duration(i) * time.Hour), ArtifactType: model.ArtifactSRUM, EventType: typ, ProcessName: "tool.exe",
			SourceReference: fmt.Sprintf("table:{T}#id:%d", i), Extra: extra,
		}
	}
	return []model.Event{
		mk(1, model.EventSRUMNetworkUsage, map[string]string{"bytes_sent": bigSent, "bytes_received": bigRecv, "interface_type_name": "wifi"}),
		mk(2, model.EventSRUMNetworkConnection, map[string]string{"connected_seconds": "86400"}),
		mk(3, model.EventSRUMSDPNetwork, map[string]string{"bytes_in_bound": bigRecv, "bytes_out_bound": bigSent, "bytes_total": "54760833024"}),
	}
}

func isSRUMNet(e model.Event) bool {
	return e.EventType == model.EventSRUMNetworkUsage || e.EventType == model.EventSRUMNetworkConnection || e.EventType == model.EventSRUMSDPNetwork
}

// A case with real process activity of the same program next to the counters:
// every rule and correlation sees both, and none may take the counters in.
func caseEvents() []model.Event {
	at := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	ev := srumNetEvents(at)
	ev = append(ev, model.Event{ID: "p1", CaseID: "case01", CollectionID: "col01", SourceFileID: "sf02", Host: "host01", User: "alice", Timestamp: at.Add(30 * time.Minute),
		ArtifactType: model.ArtifactWindowsEventLog, EventType: model.EventProcessCreate, ProcessName: "tool.exe", ProcessPath: `C:\Users\alice\tool.exe`,
		CommandLine: `C:\Users\alice\tool.exe --sync`, EventID: 4688, Extra: map[string]string{}})
	return ev
}

func TestNoRuleCorrelationOrInvestigationConsumesSRUMNetworkCounters(t *testing.T) {
	events := caseEvents()
	findings := detect.Run("case01", events)
	corrs := correlate.Run("case01", events)
	invs := investigate.Run("case01", events, findings, corrs)
	for _, f := range findings {
		for _, id := range f.SupportingEvents {
			for _, e := range events {
				if e.ID == id && isSRUMNet(e) {
					t.Errorf("finding %s (%s) cites SRUM network counters %s", f.RuleID, f.Title, id)
				}
			}
		}
		if s := f.Title + " " + f.Description; claim.MatchString(s) || strings.Contains(s, bigSent) {
			t.Errorf("finding %s states a transfer: %q", f.RuleID, s)
		}
	}
	for _, c := range corrs {
		// Audit finding, recorded in docs/srum-coverage.md: the entity correlation
		// groups events by process name across artifact types, so a SRUM row whose
		// application resolved to the same name is listed among them. It reads the
		// name only (never a counter, a direction or an interface) and its sentence
		// says nothing about traffic; the checks below pin that. Every other
		// correlation type must not cite SRUM network rows at all.
		if c.Type == model.CorrelationEntity {
			continue
		}
		for _, id := range c.EventIDs {
			for _, e := range events {
				if e.ID == id && isSRUMNet(e) {
					t.Errorf("correlation %s cites SRUM network counters %s", c.Type, id)
				}
			}
		}
		if s := c.Title + " " + c.Description; claim.MatchString(s) || strings.Contains(s, bigSent) {
			t.Errorf("correlation %s states a transfer: %q", c.Type, s)
		}
	}
	for _, c := range corrs {
		if c.Type == model.CorrelationEntity && (strings.Contains(c.Description, bigSent) || strings.Contains(c.Description, bigRecv) || claim.MatchString(c.Title+" "+c.Description)) {
			t.Errorf("entity correlation words a counter or a transfer: %q", c.Description)
		}
	}
	for _, iv := range invs {
		if s := iv.Title + " " + iv.Summary + " " + strings.Join(iv.ScoreRationale, " "); claim.MatchString(s) || strings.Contains(s, bigSent) {
			t.Errorf("investigation states a transfer: %q", s)
		}
	}
}

func TestSRUMNetworkCountersAloneProduceNothing(t *testing.T) {
	events := srumNetEvents(time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC))
	if f := detect.Run("case01", events); len(f) != 0 {
		t.Errorf("findings from SRUM network counters alone: %+v", f)
	}
	if c := correlate.Run("case01", events); len(c) != 0 {
		t.Errorf("correlations from SRUM network counters alone: %+v", c)
	}
}

func TestNarrativePacketNeverCarriesSRUMCounters(t *testing.T) {
	events := caseEvents()
	p, err := narrative.PrepareReview(narrative.ReviewInput{CaseID: "case01", Events: events})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{bigSent, bigRecv, "54760833024"} {
		if strings.Contains(p.User, v) || strings.Contains(p.System, v) {
			t.Errorf("a SRUM counter (%s) reached the narrative packet", v)
		}
	}
	if m := claim.FindString(p.User); m != "" {
		t.Errorf("the narrative packet states %q", m)
	}
}

// consumerDirs are the places that decide, score or word a conclusion. None of
// them may so much as name a SRUM event type or a SRUM counter.
var consumerDirs = []string{"detect", "correlate", "investigate", "report", "narrative", "attck", "egress", "enrich", "gate", "authseq", "clockskew"}

var forbiddenInConsumers = regexp.MustCompile(`EventSRUM|ArtifactSRUM|srum_(app|network|sdp|push)|"(bytes_sent|bytes_received|bytes_in_bound|bytes_out_bound|bytes_total)"`)

func TestNoDecisionCodeNamesSRUMOrItsCounters(t *testing.T) {
	root := ".."
	for _, d := range consumerDirs {
		dir := filepath.Join(root, d)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		filepath.WalkDir(dir, func(p string, de fs.DirEntry, err error) error {
			if err != nil || de.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, _ := os.ReadFile(p)
			for i, line := range strings.Split(string(b), "\n") {
				if forbiddenInConsumers.MatchString(line) {
					t.Errorf("%s:%d names SRUM or a SRUM counter: %s", p, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
	}
}

// Outside the parser, only plumbing may name the SRUM artifact: the model that
// defines it, dedup identity, the artifact catalogue, and the import paths that
// route it to the bounded reader.
var plumbing = map[string]bool{
	"model/model.go": true, "model/dedup.go": true, "model/parse_coverage.go": true, "artifacts/artifacts.go": true,
	"api/import_stream.go": true, "ingest/isolate.go": true, "ingest/ingest.go": true, "api/service.go": true,
	"api/report_event_details.go": true,
}

func TestSRUMIsNamedOnlyByPlumbingAndTheParser(t *testing.T) {
	re := regexp.MustCompile(`ArtifactSRUM|EventSRUM|"srum_`)
	filepath.WalkDir("..", func(p string, de fs.DirEntry, err error) error {
		rel, _ := filepath.Rel("..", p)
		rel = filepath.ToSlash(rel)
		if err != nil || de.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") ||
			strings.HasPrefix(rel, "parsers/srum/") || strings.HasPrefix(rel, "srumguard/") || plumbing[rel] {
			return nil
		}
		b, _ := os.ReadFile(p)
		for i, line := range strings.Split(string(b), "\n") {
			if re.MatchString(line) {
				t.Errorf("%s:%d names SRUM outside the parser and plumbing; if it decides or words anything, it needs the no-transfer review: %s", rel, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
}

// The UI may label and group SRUM event types; any line of app.js that names
// SRUM must not word a transfer.
func TestUIStringsAboutSRUMStateNoTransfer(t *testing.T) {
	b, err := os.ReadFile("../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(b), "\n") {
		l := strings.ToLower(line)
		if (strings.Contains(l, "srum") || strings.Contains(l, "bytes_sent") || strings.Contains(l, "bytes_received") || strings.Contains(l, "bytes_in_bound") || strings.Contains(l, "bytes_out_bound")) && claim.MatchString(line) {
			t.Errorf("app.js:%d words a transfer next to SRUM: %s", i+1, strings.TrimSpace(line))
		}
	}
}
