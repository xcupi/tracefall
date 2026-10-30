package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"tracefall/internal/casefiles"
	"tracefall/internal/correlate"
	"tracefall/internal/enrich/llm"
	"tracefall/internal/model"
	"tracefall/internal/parsers/winevent"
	"tracefall/internal/store"
	"tracefall/internal/web"
)

// This is normalized synthetic software proof, NOT native EVTX fidelity.
// A compiled -test binary exercises actual loopback HTTP and a closed/reopened
// SQLite store. It never opens a user case or needs a provider/credential.
func TestTaskContextFilteredStoreIdentity(t *testing.T) {
	svc := newTestService(t)
	c, err := svc.CreateCase("Synthetic streamed identity", "")
	if err != nil {
		t.Fatal(err)
	}
	col := model.Collection{ID: "11111111-2222-4333-8444-555555555555", CaseID: c.ID, SourceType: model.SourceTypeDiskImage}
	sf := model.SourceFile{ID: "source", CaseID: c.ID, CollectionID: col.ID, OriginalFilename: "synthetic.evtx", Path: "synthetic.evtx"}
	if err := svc.store.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); err != nil {
		t.Fatal(err)
	}
	var events []model.Event
	for _, n := range []int{200, 202} {
		e := model.Event{ID: fmt.Sprint(n), CaseID: c.ID, CollectionID: col.ID, SourceFileID: sf.ID, Host: "host01", EventID: n, ArtifactType: model.ArtifactWindowsEventLog}
		if n == 202 {
			e.Host = "host01.corp.example"
		}
		if !winevent.Normalize(&e, winevent.Input{EventID: n, Provider: "Microsoft-Windows-TaskScheduler", Channel: "Microsoft-Windows-TaskScheduler/Operational", Data: map[string]string{"InstanceId": "{11111111-2222-3333-4444-555555555555}", "TaskInstanceId": "{11111111-2222-3333-4444-555555555555}"}}) {
			t.Fatal("normalize")
		}
		events = append(events, e)
	}
	metadata := model.Event{ID: "meta", CaseID: c.ID, CollectionID: col.ID, SourceFileID: sf.ID, Host: "host01", EventType: "unrelated_metadata", Extra: map[string]string{"domain": "corp.example", "os_current_build": "1"}}
	events = append(events, metadata)
	if err := svc.store.SaveEvents(events); err != nil {
		t.Fatal(err)
	}
	count := func(cs []model.Correlation) int {
		n := 0
		for _, c := range cs {
			if c.Type == model.CorrelationTaskInstanceContext {
				n++
			}
		}
		return n
	}
	filtered, err := correlate.RunFrom(c.ID, svc.store.EventSourceFor(c.ID))
	if err != nil || count(filtered) != 1 {
		t.Fatalf("store lost proven alias: %+v %v", filtered, err)
	}
	blocker := metadata
	blocker.ID = "conflict"
	blocker.Extra = map[string]string{"domain": "other.example", "os_current_build": "2"}
	if err := svc.store.SaveEvents([]model.Event{blocker}); err != nil {
		t.Fatal(err)
	}
	full, err := svc.store.ListEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	filtered, err = correlate.RunFrom(c.ID, svc.store.EventSourceFor(c.ID))
	if err != nil || count(filtered) != 0 || count(correlate.Run(c.ID, full)) != 0 {
		t.Fatalf("untyped domain/build contradiction erased by filtered store: %+v %v", filtered, err)
	}
}

func TestTaskContextHTTPRestartSynthetic(t *testing.T) {
	root := t.TempDir()
	// Optional retained neutral fixture for an independent production-binary
	// restart probe. Never point this at an existing/user case directory.
	if owned := os.Getenv("TRACEFALL_TASK_SYNTHETIC_PROOF_DIR"); owned != "" {
		if err := os.Mkdir(owned, 0700); err != nil {
			t.Fatal(err)
		}
		root = owned
	}
	dbPath := filepath.Join(root, "synthetic.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(db, casefiles.NewStore(filepath.Join(root, "data")))
	if err := svc.ConfigureChatGPT(filepath.Join(root, "data"), filepath.Join(root, "no-provider-binary"), "", "", llm.None{}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(routerFor(svc))
	defer func() { server.Close(); db.Close() }()
	request := func(method, path string, body, out any) {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
		req, err := http.NewRequest(method, server.URL+path, &buf)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tracefall-Client", "dashboard")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, b)
		}
		if out != nil {
			if err := json.Unmarshal(b, out); err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
		}
	}
	var c model.Case
	request("POST", "/api/cases", map[string]string{"name": "Synthetic task context proof"}, &c)
	prefix := "/api/cases/" + c.ID
	request("PUT", "/api/admin/integrations/chatgpt", map[string]string{"provider": "none"}, nil)
	request("PUT", prefix+"/egress", map[string]string{"level": "none"}, nil)
	var egress map[string]any
	request("GET", prefix+"/egress", nil, &egress)
	if egress["level"] != "none" {
		t.Fatalf("egress: %+v", egress)
	}
	var provider map[string]any
	request("GET", "/api/admin/integrations/chatgpt", nil, &provider)
	if provider["effective_provider"] != "none" {
		t.Fatalf("provider not disabled: %+v", provider)
	}
	col := model.Collection{ID: "11111111-2222-4333-8444-555555555555", CaseID: c.ID, SourceType: model.SourceTypeDiskImage, IngestionStatus: model.CollectionStatusPending}
	sf := model.SourceFile{ID: "synthetic-source", CaseID: c.ID, CollectionID: col.ID, OriginalFilename: "synthetic.evtx", Path: "synthetic.evtx", ImportStatus: model.SourceFileImported, Supported: true, ArtifactType: model.ArtifactWindowsEventLog, Parser: "synthetic-normalized"}
	if err := db.CreateCollectionWithSourceFiles(col, []model.SourceFile{sf}); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	p := model.Event{ID: "process", CaseID: c.ID, CollectionID: col.ID, Host: "host01", Timestamp: stamp, EventType: model.EventProcessCreate, PID: 4242, ProcessName: "powershell.exe", ProcessPath: `C:\Tools\powershell.exe`, CommandLine: "powershell.exe -EncodedCommand AAAA", ArtifactType: model.ArtifactWindowsEventLog, SourceFileID: sf.ID, DedupHash: "synthetic-process"}
	save := func(events []model.Event) {
		t.Helper()
		var obs []model.EventObservation
		for i := range events {
			events[i].DedupHash = "synthetic-" + events[i].ID
			events[i].SourceFileID = sf.ID
			obs = append(obs, model.EventObservation{ID: "obs-" + events[i].ID, EventID: events[i].ID, CaseID: c.ID, CollectionID: col.ID, SourceFileID: sf.ID})
		}
		if err := db.SaveEvents(events); err != nil {
			t.Fatal(err)
		}
		if err := db.SaveEventObservations(obs); err != nil {
			t.Fatal(err)
		}
	}
	save([]model.Event{p})
	request("POST", prefix+"/analyze", nil, nil)
	var baseline []model.Investigation
	request("GET", prefix+"/investigations", nil, &baseline)
	if len(baseline) == 0 {
		t.Fatal("baseline ordinary finding/investigation absent")
	}
	var beforeFindings []model.Finding
	request("GET", prefix+"/findings", nil, &beforeFindings)
	var taskEvents []model.Event
	for _, n := range []int{200, 201, 202, 129} {
		e := model.Event{ID: fmt.Sprintf("task-%d", n), CaseID: c.ID, CollectionID: col.ID, Host: "host01", Timestamp: stamp, EventID: n, ArtifactType: model.ArtifactWindowsEventLog}
		data := map[string]string{"TaskName": `\Maintenance\Cleanup`, "InstanceId": "{11111111-2222-3333-4444-555555555555}", "TaskInstanceId": "{11111111-2222-3333-4444-555555555555}", "ProcessID": "0x1092", "Path": p.ProcessPath, "EnginePID": "900", "ResultCode": "0"}
		if !winevent.Normalize(&e, winevent.Input{EventID: n, Provider: "Microsoft-Windows-TaskScheduler", Channel: "Microsoft-Windows-TaskScheduler/Operational", Data: data}) {
			t.Fatal("normalize")
		}
		taskEvents = append(taskEvents, e)
	}
	save(taskEvents)
	snapshot := func() string {
		t.Helper()
		events, err := db.ListEvents(c.ID)
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(events, func(i, j int) bool { return events[i].ID < events[j].ID })
		obs, err := db.ListEventObservationsBySourceFile(sf.ID)
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(obs, func(i, j int) bool { return obs[i].ID < obs[j].ID })
		b, err := json.Marshal([]any{events, obs})
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%x", sha256.Sum256(b))
	}
	frozen := snapshot()
	request("POST", prefix+"/analyze", nil, nil)
	if got := snapshot(); got != frozen {
		t.Fatalf("analysis rewrote source rows: %s != %s", got, frozen)
	}
	var after []model.Investigation
	request("GET", prefix+"/investigations", nil, &after)
	if !reflect.DeepEqual(baseline, after) {
		t.Fatalf("context changed ordinary assessment: before=%+v after=%+v", baseline, after)
	}
	var afterFindings []model.Finding
	request("GET", prefix+"/findings", nil, &afterFindings)
	if len(afterFindings) != len(beforeFindings) {
		t.Fatalf("context invented finding: %d -> %d", len(beforeFindings), len(afterFindings))
	}
	var cs []model.Correlation
	request("GET", prefix+"/correlations", nil, &cs)
	types := map[string]int{}
	supports := map[string][]string{}
	for _, x := range cs {
		if x.Type == model.CorrelationTaskInstanceContext || x.Type == model.CorrelationTaskProcessContext {
			types[x.Type]++
			supports[x.Type] = x.EventIDs
		}
	}
	if types[model.CorrelationTaskInstanceContext] != 1 || types[model.CorrelationTaskProcessContext] != 1 {
		t.Fatalf("missing context types: %+v", types)
	}
	if !reflect.DeepEqual(supports[model.CorrelationTaskInstanceContext], []string{"task-200", "task-201", "task-202"}) || !reflect.DeepEqual(supports[model.CorrelationTaskProcessContext], []string{"process", "task-129"}) {
		t.Fatalf("support identity mismatch: %+v", supports)
	}
	all, err := db.ListEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	full := correlate.Run(c.ID, all)
	filtered, err := correlate.RunFrom(c.ID, db.EventSourceFor(c.ID))
	if err != nil {
		t.Fatal(err)
	}
	only := func(in []model.Correlation) []model.Correlation {
		var out []model.Correlation
		for _, x := range in {
			if strings.HasPrefix(x.Type, "task_") {
				out = append(out, x)
			}
		}
		return out
	}
	if !reflect.DeepEqual(only(full), only(filtered)) {
		t.Fatal("filtered store context parity failed")
	}
	// Serve the actual embedded compiled asset over HTTP, not a source-file read.
	assetServer := httptest.NewServer(web.StaticHandler())
	resp, err := assetServer.Client().Get(assetServer.URL + "/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	asset, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	assetServer.Close()
	if err != nil || !bytes.Contains(asset, []byte(`task_instance_context: "Task instance context"`)) || !bytes.Contains(asset, []byte(`task_process_context: "Task process context"`)) {
		t.Fatal("compiled UI labels absent")
	}
	server.Close()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	svc = NewService(db, casefiles.NewStore(filepath.Join(root, "data")))
	if err := svc.ConfigureChatGPT(filepath.Join(root, "data"), filepath.Join(root, "no-provider-binary"), "", "", llm.None{}); err != nil {
		t.Fatal(err)
	}
	server = httptest.NewServer(routerFor(svc))
	var restarted []model.Correlation
	request("GET", prefix+"/correlations", nil, &restarted)
	if !reflect.DeepEqual(cs, restarted) || snapshot() != frozen {
		t.Fatal("restart changed durable results or source rows")
	}
	var restartInv []model.Investigation
	request("GET", prefix+"/investigations", nil, &restartInv)
	if !reflect.DeepEqual(after, restartInv) {
		t.Fatal("restart assessment changed")
	}
	request("GET", prefix+"/egress", nil, &egress)
	if egress["level"] != "none" {
		t.Fatal("egress changed")
	}
	request("GET", "/api/admin/integrations/chatgpt", nil, &provider)
	if provider["effective_provider"] != "none" {
		t.Fatal("provider changed")
	}
	if os.Getenv("TRACEFALL_TASK_SYNTHETIC_PROOF_DIR") != "" {
		manifest := map[string]any{"case_id": c.ID, "source_rows_sha256": frozen, "events": len(all), "supports": supports, "context_counts": types, "ordinary_findings": len(afterFindings), "investigations": after}
		encoded, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "manifest.json"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("normalized synthetic HTTP/restart PASS: events=%d context_types=%v supports=%v ordinary_findings=%d unchanged_investigations=%d source_rows_sha256=%s provider=none egress=none", len(all), types, supports, len(afterFindings), len(after), frozen)
}
