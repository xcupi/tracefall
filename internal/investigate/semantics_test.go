package investigate

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

// taskEvent is a scheduled-task record of a given host/acquisition.
func taskEvent(id, host, collection string, ts time.Time) model.Event {
	return model.Event{
		ID: id, Host: host, CollectionID: collection, SourceFileID: "source-" + id, RawEvidenceID: "raw-" + id,
		Timestamp: ts, EventType: model.EventScheduledTaskCreate, ArtifactType: "scheduled_task",
		ProcessName: "agent.exe", Extra: map[string]string{"task_name": "maintenance"},
	}
}

func twoFindings(ids ...string) []model.Finding {
	var fs []model.Finding
	for i, id := range ids {
		fs = append(fs, model.Finding{ID: "finding0" + string(rune('1'+i)), RuleID: "new-scheduled-task", SupportingEvents: []string{id}})
	}
	return fs
}

// The identity boundary: a correlation joins two findings only when its events
// are the same machine, or are both host-less in the same acquisition.
func TestRun_IdentityBoundary(t *testing.T) {
	for _, corr := range []string{model.CorrelationEntity, model.CorrelationActivityChain} {
		for _, tc := range []struct {
			name       string
			h1, h2     string
			c1, c2     string
			wantMerged bool
		}{
			{"anonymous acquisitions", "", "", "collection01", "collection02", false},
			{"same anonymous acquisition", "", "", "collection01", "collection01", true},
			{"no host and no acquisition", "", "", "", "", false},
			{"unknown against known host, one acquisition", "", "host01", "collection01", "collection01", false},
			{"identical recorded host in two acquisitions", "host01", "host01", "collection01", "collection02", true},
			{"contradictory hosts in one acquisition", "host01", "host02", "collection01", "collection01", false},
			{"short and qualified name of one acquisition", "HOST01", "host01.example.test", "collection01", "collection01", true},
			{"short and qualified name in two acquisitions", "HOST01", "host01.example.test", "collection01", "collection02", false},
			{"same short name, two qualified names, one acquisition", "host01.a.test", "host01.b.test", "collection01", "collection01", false},
		} {
			t.Run(corr+"/"+tc.name, func(t *testing.T) {
				es := []model.Event{
					taskEvent("event01", tc.h1, tc.c1, mustTime("2026-01-02T03:04:05Z")),
					taskEvent("event02", tc.h2, tc.c2, mustTime("2026-01-02T03:04:06Z")),
				}
				cs := []model.Correlation{{ID: "correlation01", Type: corr, EventIDs: []string{"event01", "event02"}}}
				got := Run("case01", es, twoFindings("event01", "event02"), cs)
				want := 2
				if tc.wantMerged {
					want = 1
				}
				if len(got) != want {
					t.Fatalf("investigations=%d want %d: %+v", len(got), want, got)
				}
				seen := map[string]int{}
				for _, inv := range got {
					for _, id := range inv.EventIDs {
						seen[id]++
					}
					if !tc.wantMerged && (inv.EventCount != 1 || len(inv.FindingIDs) != 1 || len(inv.SourceFileIDs) != 1) {
						t.Fatalf("partition lost membership: %+v", inv)
					}
				}
				if !reflect.DeepEqual(seen, map[string]int{"event01": 1, "event02": 1}) {
					t.Fatalf("events lost or duplicated: %v", seen)
				}
			})
		}
	}
}

// A correlation whose type is cross-host by design still joins two known hosts.
func TestRun_CrossHostCorrelationJoinsKnownHosts(t *testing.T) {
	es := []model.Event{
		taskEvent("event01", "host01", "collection01", mustTime("2026-01-02T03:04:05Z")),
		taskEvent("event02", "host02", "collection01", mustTime("2026-01-02T03:04:06Z")),
	}
	cs := []model.Correlation{{ID: "correlation01", Type: model.CorrelationCredentialChain, EventIDs: []string{"event01", "event02"}}}
	if got := Run("case01", es, twoFindings("event01", "event02"), cs); len(got) != 1 {
		t.Fatalf("investigations=%d want 1", len(got))
	}
}

// A finding is one claim of its rule and is never split, even when its own
// supporting events carry different acquisitions.
func TestRun_FindingIsNeverSplit(t *testing.T) {
	es := []model.Event{
		taskEvent("event01", "", "collection01", time.Time{}),
		taskEvent("event02", "", "collection02", time.Time{}),
	}
	fs := []model.Finding{{ID: "finding01", RuleID: "new-scheduled-task", SupportingEvents: []string{"event01", "event02"}}}
	got := Run("case01", es, fs, nil)
	if len(got) != 1 || got[0].EventCount != 2 {
		t.Fatalf("got %+v", got)
	}
}

// Splitting by identity changes no investigation id: the ids come from the
// findings, which are unchanged.
func TestRun_SplitKeepsInvestigationIDsOfTheUncorrelatedRun(t *testing.T) {
	es := []model.Event{
		taskEvent("event01", "", "collection01", time.Time{}),
		taskEvent("event02", "", "collection02", time.Time{}),
	}
	fs := twoFindings("event01", "event02")
	cs := []model.Correlation{{ID: "correlation01", Type: model.CorrelationEntity, EventIDs: []string{"event01", "event02"}}}
	ids := func(x []model.Investigation) []string {
		var o []string
		for _, i := range x {
			o = append(o, i.ID)
		}
		sort.Strings(o)
		return o
	}
	a, b := Run("case01", es, fs, cs), Run("case01", es, fs, nil)
	if len(a) != 2 || !reflect.DeepEqual(ids(a), ids(b)) {
		t.Fatalf("ids %v vs %v", ids(a), ids(b))
	}
	if !reflect.DeepEqual(a, Run("case01", es, fs, cs)) {
		t.Fatal("investigations differ between runs")
	}
}

func TestRun_UnknownHostAndTimeAreNotPrinted(t *testing.T) {
	es := []model.Event{taskEvent("event01", "", "collection01", time.Time{})}
	got := Run("case01", es, twoFindings("event01"), nil)
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	inv := got[0]
	if strings.HasSuffix(inv.Title, " on ") || !strings.Contains(inv.Title, "host not recorded") {
		t.Errorf("title for unknown host: %q", inv.Title)
	}
	if !inv.StartTime.IsZero() || !inv.EndTime.IsZero() {
		t.Errorf("undated investigation has bounds %v %v", inv.StartTime, inv.EndTime)
	}
	for _, bad := range []string{"00:00:00", "midnight", "was registered", "registration"} {
		if strings.Contains(strings.ToLower(inv.Summary), bad) {
			t.Errorf("summary asserts %q for an undated event: %q", bad, inv.Summary)
		}
	}
	if !strings.Contains(inv.Summary, "time not recorded") {
		t.Errorf("summary does not say the time is not recorded: %q", inv.Summary)
	}
}

func TestRun_BoundsComeFromDatedEventsOnly(t *testing.T) {
	d1, d2 := mustTime("2026-01-02T03:04:05Z"), mustTime("2026-01-02T03:10:00Z")
	es := []model.Event{
		taskEvent("event01", "host01", "collection01", time.Time{}),
		taskEvent("event02", "host01", "collection01", d2),
		taskEvent("event03", "host01", "collection01", d1),
	}
	fs := []model.Finding{{ID: "finding01", RuleID: "new-scheduled-task", SupportingEvents: []string{"event01", "event02", "event03"}}}
	got := Run("case01", es, fs, nil)
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if !got[0].StartTime.Equal(d1) || !got[0].EndTime.Equal(d2) {
		t.Errorf("bounds %v..%v want %v..%v", got[0].StartTime, got[0].EndTime, d1, d2)
	}
	if got[0].EventCount != 3 {
		t.Errorf("undated event dropped: %d", got[0].EventCount)
	}
	if !strings.Contains(got[0].Summary, "time not recorded") || !strings.Contains(got[0].Summary, "03:04:05 UTC") {
		t.Errorf("summary: %q", got[0].Summary)
	}
}

func TestRun_UndatedInvestigationsSortAfterDated(t *testing.T) {
	es := []model.Event{
		taskEvent("event01", "host01", "collection01", time.Time{}),
		taskEvent("event02", "host02", "collection01", mustTime("2026-01-02T03:04:05Z")),
	}
	got := Run("case01", es, twoFindings("event01", "event02"), nil)
	if len(got) != 2 || got[0].StartTime.IsZero() || !got[1].StartTime.IsZero() {
		t.Fatalf("order: %+v", got)
	}
}

func narrate(es ...model.Event) string { return buildNarrative(seqOf(es)) }

func TestNarrative_UndatedClausesStateNoTime(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   model.Event
		bad  []string
	}{
		{"task", taskEvent("e1", "host01", "c", time.Time{}), []string{"registered", "00:00:00", " at "}},
		{"service", model.Event{ID: "e1", Host: "host01", EventType: model.EventServiceInstall, Extra: map[string]string{"service_name": "svc"}, FilePath: "C:/x/agent.exe"}, []string{"installed at", "00:00:00"}},
		{"run key", model.Event{ID: "e1", Host: "host01", EventType: model.EventRegistryRunKey, FilePath: "C:/x/agent.exe"}, []string{"established at", "00:00:00"}},
		{"network", model.Event{ID: "e1", Host: "host01", EventType: model.EventNetworkConnection, NetworkDest: "203.0.113.5"}, []string{"subsequently", "00:00:00"}},
		{"dns", model.Event{ID: "e1", Host: "host01", EventType: model.EventDNSQuery, NetworkDest: "example.test"}, []string{"00:00:00"}},
		{"explicit creds", model.Event{ID: "e1", Host: "host01", EventType: model.EventLogonExplicitCreds, Extra: map[string]string{"target_user_name": "alice"}}, []string{"00:00:00"}},
		{"privileged", model.Event{ID: "e1", Host: "host01", EventType: model.EventPrivilegedLogon}, []string{"00:00:00"}},
		{"logon", model.Event{ID: "e1", Host: "host01", User: "alice", EventType: model.EventLogonSuccess}, []string{"00:00:00"}},
		{"process", model.Event{ID: "e1", Host: "host01", EventType: model.EventProcessCreate, ProcessName: "a.exe"}, []string{"began", "00:00:00"}},
		{"failures", model.Event{ID: "e1", Host: "host01", User: "alice", EventType: model.EventLogonFailure}, []string{"between", "00:00:00"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := narrate(tc.ev)
			if !strings.Contains(got, "time not recorded") {
				t.Fatalf("no statement that the time is unknown: %q", got)
			}
			for _, bad := range tc.bad {
				if strings.Contains(got, bad) {
					t.Errorf("contains %q: %q", bad, got)
				}
			}
		})
	}
}

func TestNarrative_NoSequenceClaimAcrossAnUndatedEndpoint(t *testing.T) {
	dated := model.Event{ID: "e1", Host: "host01", User: "alice", EventType: model.EventLogonSuccess, Timestamp: mustTime("2026-01-02T03:04:05Z")}
	undatedLogon := model.Event{ID: "e2", Host: "host01", User: "carol", EventType: model.EventLogonSuccess}
	undatedProc := model.Event{ID: "e3", Host: "host01", EventType: model.EventProcessCreate, ProcessName: "a.exe"}
	undatedNet := model.Event{ID: "e4", Host: "host01", EventType: model.EventNetworkConnection, NetworkDest: "203.0.113.5"}
	got := narrate(dated, undatedLogon, undatedProc, undatedNet)
	for _, bad := range []string{"followed", "subsequently", "began", "which spawned"} {
		if strings.Contains(got, bad) {
			t.Errorf("sequence word %q across an undated endpoint: %q", bad, got)
		}
	}
	if !strings.HasPrefix(got, "A successful logon for user alice on host host01 was observed at 03:04:05 UTC") {
		t.Errorf("dated clause changed: %q", got)
	}
}

func TestNarrative_UndatedFailuresAreNotABurstWindow(t *testing.T) {
	a := model.Event{ID: "e1", Host: "host01", User: "alice", EventType: model.EventLogonFailure, Timestamp: mustTime("2026-01-02T03:04:05Z")}
	b := model.Event{ID: "e2", Host: "host01", User: "alice", EventType: model.EventLogonFailure, Timestamp: mustTime("2026-01-02T03:04:07Z")}
	c := model.Event{ID: "e3", Host: "host01", User: "alice", EventType: model.EventLogonFailure}
	got := narrate(c, a, b)
	if !strings.Contains(got, "2 failed logon attempt(s) for user alice were observed between 03:04:05 UTC and 03:04:07 UTC") {
		t.Errorf("dated burst: %q", got)
	}
	if !strings.Contains(got, "1 failed logon attempt(s) for user alice were observed (time not recorded)") {
		t.Errorf("undated failure: %q", got)
	}
}

func TestNarrative_DatedClausesUnchanged(t *testing.T) {
	got := narrate(taskEvent("e1", "host01", "c", mustTime("2026-01-02T03:04:05Z")))
	if got != "A scheduled task (maintenance) was registered at 03:04:05 UTC." {
		t.Errorf("dated task clause changed: %q", got)
	}
}
