package correlate

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"tracefall/internal/model"
)

func processPair() []model.Event {
	t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return []model.Event{{ID: "parent", CaseID: "case01", CollectionID: "collection01", Host: "host01", EventType: model.EventProcessCreate, ProcessName: "parent.exe", PID: 111, Timestamp: t}, {ID: "child", CaseID: "case01", CollectionID: "collection01", Host: "host01", EventType: model.EventProcessCreate, ProcessName: "child.exe", ParentProcessName: "parent.exe", PID: 222, PPID: 999, Timestamp: t.Add(time.Minute)}}
}
func TestProcessChainRejectsContradictoryPPID(t *testing.T) {
	if got := BuildProcessChains("case01", processPair()); len(got) != 0 {
		t.Fatalf("contradictory PPID must not join: %+v", got)
	}
}

func TestProcessIdentitySelection(t *testing.T) {
	for _, name := range []string{"long_lived", "concurrent", "reuse", "zero", "tie", "duplicate_identity", "case", "collection", "host", "missing_identity", "memory_names", "memory_snapshot", "exit", "guid", "guid_mismatch"} {
		t.Run(name, func(t *testing.T) {
			es := processPair()
			es[1].PPID = 111
			want := 1
			wantParent := "parent"
			hypothesis := false
			switch name {
			case "long_lived":
				es[1].Timestamp = es[0].Timestamp.Add(24 * time.Hour)
			case "concurrent":
				p := es[0]
				p.ID = "other"
				p.PID = 333
				p.Timestamp = p.Timestamp.Add(30 * time.Second)
				es = append(es, p)
			case "reuse":
				p := es[0]
				p.ID = "reused"
				p.ProcessName = "other.exe"
				p.Timestamp = p.Timestamp.Add(30 * time.Second)
				es = append(es, p)
				want = 0
			case "zero":
				es[0].Timestamp = time.Time{}
				want = 0
			case "tie":
				es[1].Timestamp = es[0].Timestamp
				want = 0
			case "duplicate_identity":
				p := es[0]
				p.ID = "other"
				es = append(es, p)
				want = 0
			case "case":
				es[0].CaseID = "case02"
				want = 0
			case "collection":
				es[0].CollectionID = "collection02"
				want = 0
			case "host":
				es[0].Host = "host02"
				want = 0
			case "missing_identity":
				es[0].PID = 0
				es[1].PPID = 0
				hypothesis = true
			case "memory_names":
				es[0].PID = 0
				es[1].PPID = 0
				for i := range es {
					es[i].ArtifactType = model.ArtifactMemoryAnalysis
				}
				want = 0
			case "memory_snapshot":
				for i := range es {
					es[i].ArtifactType = model.ArtifactMemoryAnalysis
					es[i].Extra = map[string]string{"timestamp_basis": "memory_snapshot"}
				}
				want = 0
			case "exit":
				es[0].Extra = map[string]string{"exit_time": es[0].Timestamp.Add(30 * time.Second).Format(time.RFC3339)}
				want = 0
			case "guid":
				es[0].PID = 0
				es[1].PPID = 0
				es[0].Extra = map[string]string{"process_guid": "guid01"}
				es[1].Extra = map[string]string{"parent_process_guid": "guid01"}
				es[1].Timestamp = es[0].Timestamp.Add(24 * time.Hour)
			case "guid_mismatch":
				es[0].Extra = map[string]string{"process_guid": "guid01"}
				es[1].Extra = map[string]string{"parent_process_guid": "guid02"}
				want = 0
			}
			got := BuildProcessChains("case01", es)
			reversed := append([]model.Event{}, es...)
			for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
				reversed[i], reversed[j] = reversed[j], reversed[i]
			}
			if other := BuildProcessChains("case01", reversed); !reflect.DeepEqual(got, other) {
				t.Fatalf("process attribution depends on input order: %+v vs %+v", got, other)
			}
			if len(got) != want {
				t.Fatalf("got %+v, want %d links", got, want)
			}
			if want > 0 {
				if got[0].EventIDs[0] != wantParent {
					t.Fatalf("wrong parent: %+v", got)
				}
				if hypothesis && (!strings.Contains(strings.ToLower(got[0].Description), "hypothetical") || strings.Contains(got[0].Description, "(PID") || strings.Contains(got[0].Description, " created ")) {
					t.Fatalf("name-only attribution overclaims: %s", got[0].Description)
				}
			}
		})
	}
}

func TestProcessIdentityRejectsSelfParentPID(t *testing.T) {
	es := processPair()
	es[1].PID = 111
	es[1].PPID = 111
	if got := BuildProcessChains("case01", es); len(got) != 0 {
		t.Fatalf("a reused PID cannot parent itself: %+v", got)
	}
}

func TestProcessGUIDDoesNotInventPIDZero(t *testing.T) {
	es := processPair()
	es[0].PID = 0
	es[1].PPID = 0
	es[0].Extra = map[string]string{"process_guid": "guid01"}
	es[1].Extra = map[string]string{"parent_process_guid": "guid01"}
	got := BuildProcessChains("case01", es)
	if len(got) != 1 || strings.Contains(got[0].Description, "PID 0") || !strings.Contains(got[0].Description, "guid01") {
		t.Fatalf("GUID-only identity must not invent PID: %+v", got)
	}
}
