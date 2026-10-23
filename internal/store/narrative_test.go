package store

import (
	"testing"
	"time"

	"tracefall/internal/model"
)

func narr(id string, at time.Time) model.Narrative {
	return model.Narrative{ID: id, CaseID: "case-1", Status: model.NarrativeOK, CreatedAt: at, Destination: "llm.example.invalid", Local: false, Model: "m",
		PayloadSystem: "sys", PayloadUser: "usr", PayloadSHA256: "abc", RawAnswer: "raw", SentencesJSON: `[{"text":"t","cites":[]}]`, Rejected: 2,
		ReasonsJSON: `{"x":2}`, FindingIDs: []string{"f1", "f2"}, PromptTokens: 10, CompletionTokens: 5, RequestedBy: "local-user"}
}

func TestNarratives_LatestWinsAndEverythingRoundTrips(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	if _, ok, err := s.LatestNarrative("case-1"); ok || err != nil {
		t.Fatalf("no draft yet: %v %v", ok, err)
	}
	t0 := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	for _, n := range []model.Narrative{narr("a", t0), narr("c", t0.Add(2*time.Hour)), narr("b", t0.Add(time.Hour))} {
		if err := s.SaveNarrative(n); err != nil {
			t.Fatal(err)
		}
	}
	got, ok, err := s.LatestNarrative("case-1")
	if err != nil || !ok || got.ID != "c" {
		t.Fatalf("latest = %+v %v %v", got.ID, ok, err)
	}
	want := narr("c", t0.Add(2*time.Hour))
	if got.PayloadSystem != want.PayloadSystem || got.PayloadUser != "usr" || got.PayloadSHA256 != "abc" || got.RawAnswer != "raw" || got.Rejected != 2 ||
		got.ReasonsJSON != `{"x":2}` || len(got.FindingIDs) != 2 || got.FindingIDs[1] != "f2" || got.PromptTokens != 10 || got.CompletionTokens != 5 ||
		got.RequestedBy != "local-user" || got.Destination != "llm.example.invalid" || got.Local || !got.CreatedAt.Equal(want.CreatedAt) || got.SentencesJSON != want.SentencesJSON {
		t.Errorf("did not round-trip: %+v", got)
	}
	l := narr("d", t0.Add(3*time.Hour))
	l.Local = true
	_ = s.SaveNarrative(l)
	if got, _, _ := s.LatestNarrative("case-1"); !got.Local {
		t.Errorf("local flag lost")
	}
	if _, ok, _ := s.LatestNarrative("case-2"); ok {
		t.Errorf("another case's draft")
	}
}

func TestCaseNames_FromTheFieldsThatHoldNamesOnly(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	mk := func(id string, mod func(*model.Event)) model.Event {
		e := model.Event{ID: id, CaseID: "case-1", CollectionID: "collection-1", Timestamp: time.Now().UTC(), EventType: "x", ArtifactType: "windows_event_log",
			SourceFileID: "sf-1", Parser: "p", Confidence: 1, DedupHash: id}
		mod(&e)
		return e
	}
	if err := s.SaveEvents([]model.Event{
		mk("e1", func(e *model.Event) {
			e.Host, e.User, e.NetworkSource, e.NetworkDest = "host01", "CORP\\alice", "10.1.2.3", "fileserver02"
			e.Extra = map[string]string{"TargetUserName": "bob", "SubjectUserName": "carol$", "TargetDomainName": "corp.example", "ComputerName": "wks-7",
				"ntlm_hash": "aad3b435b51404eeaad3b435b51404ee", "sql_statement": "SELECT 1", "evidence_meaning": "not a name"}
		}),
		mk("e2", func(e *model.Event) { e.Host = "HOST01"; e.User = "dave" }), // the same host in another case
		mk("e3", func(e *model.Event) {
			e.Extra = map[string]string{"target_user": "erin", "workstation": "ws-9", "domain": "lab.example"}
		}),
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.CaseNames("case-1")
	if err != nil {
		t.Fatal(err)
	}
	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	for _, v := range []string{"host01", "wks-7", "fileserver02", "ws-9"} {
		if !has(n.Hosts, v) {
			t.Errorf("hosts lack %q: %v", v, n.Hosts)
		}
	}
	for _, v := range []string{"CORP\\alice", "bob", "carol$", "dave", "erin"} {
		if !has(n.Users, v) {
			t.Errorf("users lack %q: %v", v, n.Users)
		}
	}
	for _, v := range []string{"corp.example", "lab.example"} {
		if !has(n.Domains, v) {
			t.Errorf("domains lack %q: %v", v, n.Domains)
		}
	}
	all := append(append(append([]string{}, n.Hosts...), n.Users...), n.Domains...)
	for _, v := range []string{"10.1.2.3", "aad3b435b51404eeaad3b435b51404ee", "SELECT 1", "not a name"} {
		if has(all, v) {
			t.Errorf("%q is not a name and must not be in the dictionary", v)
		}
	}
	if o, _ := s.CaseNames("case-2"); len(o.Hosts)+len(o.Users)+len(o.Domains) != 0 {
		t.Errorf("another case's names: %+v", o)
	}
}

func TestDeleteCase_RemovesNarratives(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	if err := s.SaveNarrative(narr("a", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCase("case-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.LatestNarrative("case-1"); ok {
		t.Errorf("a draft survives its case")
	}
}
