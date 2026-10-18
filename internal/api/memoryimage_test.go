package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracefall/internal/memory"
	"tracefall/internal/model"
)

// A stand-in for `vol` whose "image" is a JSON document mapping plugin
// names to rows. It exists so the whole memory path -- sniffing, the
// sandboxed run, the combined analysis, parsing, detection, reporting --
// is exercised without a real Windows memory image. It proves the plumbing;
// it does not prove Volatility's own output (see docs/memory-analysis.md).
const apiFakeVol = `#!/usr/bin/python3
import json, sys
a = sys.argv[1:]
if a and a[0] == "-h":
    print("Volatility 3 Framework 2.99.0")
    for p in ["windows.info.Info","windows.pslist.PsList","windows.psscan.PsScan","windows.cmdline.CmdLine",
              "windows.netscan.NetScan","windows.malware.malfind.Malfind","windows.svcscan.SvcScan"]:
        print("    " + p)
    sys.exit(0)
img = a[a.index("-f")+1]; plugin = a[-1]
doc = json.load(open(img))
v = doc.get(plugin)
if v is None:
    sys.stderr.write("Plugin not found: " + plugin + "\n"); sys.exit(2)
if isinstance(v, dict) and "__error" in v:
    sys.stderr.write(v["__error"] + "\n"); sys.exit(1)
print(); print(json.dumps([dict(r, __children=[]) for r in v]))
`

func memDoc() map[string]any {
	r := func(kv map[string]any) map[string]any { return kv }
	return map[string]any{
		"windows.info.Info": []any{
			r(map[string]any{"Variable": "NTBuildLab", "Value": "19041.1.amd64fre.vb_release.191206-1406"}),
			r(map[string]any{"Variable": "SystemTime", "Value": "2026-02-01 09:30:00+00:00"}),
			r(map[string]any{"Variable": "Is64Bit", "Value": "True"}),
		},
		"windows.pslist.PsList": []any{
			r(map[string]any{"PID": 600, "PPID": 4, "ImageFileName": "svchost.exe", "CreateTime": "2026-02-01T08:01:00+00:00", "ExitTime": nil}),
			r(map[string]any{"PID": 4242, "PPID": 600, "ImageFileName": "powershell.exe", "CreateTime": "2026-02-01T09:10:00+00:00", "ExitTime": nil}),
		},
		"windows.psscan.PsScan": []any{
			r(map[string]any{"PID": 600, "PPID": 4, "ImageFileName": "svchost.exe", "CreateTime": "2026-02-01T08:01:00+00:00", "ExitTime": nil}),
			r(map[string]any{"PID": 4242, "PPID": 600, "ImageFileName": "powershell.exe", "CreateTime": "2026-02-01T09:10:00+00:00", "ExitTime": nil}),
			r(map[string]any{"PID": 1337, "PPID": 600, "ImageFileName": "evil.exe", "CreateTime": "2026-02-01T09:20:00+00:00", "ExitTime": nil}),
		},
		"windows.cmdline.CmdLine": []any{
			r(map[string]any{"PID": 4242, "Process": "powershell.exe", "Args": `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -enc SQBFAFgA`}),
		},
		"windows.netscan.NetScan": []any{
			r(map[string]any{"Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49812, "ForeignAddr": "203.0.113.77", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 4242, "Owner": "powershell.exe", "Created": "2026-02-01T09:11:00+00:00"}),
		},
		"windows.malware.malfind.Malfind": []any{
			r(map[string]any{"PID": 4242, "Process": "powershell.exe", "Start VPN": 2000000000000, "End VPN": 2000000004095, "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1, "PrivateMemory": 1, "Hexdump": "4d 5a 90 00", "Disasm": ""}),
		},
		"windows.svcscan.SvcScan": []any{},
	}
}

func memFixture(t *testing.T, doc map[string]any, name string) (*Service, model.Case, string) {
	t.Helper()
	svc := newTestService(t)
	dir := t.TempDir()
	vol := filepath.Join(dir, "vol")
	if err := os.WriteFile(vol, []byte(apiFakeVol), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := memory.NewRunner(memory.Config{Vol: vol, CacheDir: t.TempDir(), Timeout: 30 * time.Second, AllowUnsandboxed: true})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetMemoryRunner(r)
	c, err := svc.CreateCase("Memory "+t.Name(), "")
	if err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(t.TempDir(), name)
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(img, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return svc, c, img
}

func TestMemory_DiscoveryRecognisesTheImageAndRecordsWhatVolatilityIdentified(t *testing.T) {
	svc, c, img := memFixture(t, memDoc(), "host.vmem")
	res, err := svc.DiscoverEvidenceFromPath(c.ID, img)
	if err != nil {
		t.Fatal(err)
	}
	col := res.Collection
	if col.SourceType != model.SourceTypeMemoryImage {
		t.Fatalf("source type = %s", col.SourceType)
	}
	b, _ := os.ReadFile(img)
	h := sha256.Sum256(b)
	if col.ArchiveHash != hex.EncodeToString(h[:]) {
		t.Error("the collection hash must be the SHA-256 of the memory image as received")
	}
	files := catalogPaths(t, svc, col.ID)
	sf, ok := files["memory/volatility-analysis.json"]
	if !ok || !sf.Supported || sf.Parser != "volatility_memory@1" || sf.ArtifactType != model.ArtifactMemoryAnalysis {
		t.Fatalf("catalog = %+v", files)
	}
	raw, err := os.ReadFile(svc.files.MemoryReportPath(c.ID, col.ID))
	if err != nil {
		t.Fatalf("no memory report written: %v", err)
	}
	var rep memoryImageReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Volatility != "2.99.0" || rep.Info["NTBuildLab"] == "" || rep.Isolation == "" {
		t.Errorf("report = %+v", rep)
	}
}

func TestMemory_ImportRunsVolatilityParsesAndAnalyzes(t *testing.T) {
	svc, c, img := memFixture(t, memDoc(), "host.vmem")
	res, err := svc.DiscoverEvidenceFromPath(c.ID, img)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := svc.EvidenceFileIDs(c.ID, res.Collection.ID, EvidenceFilter{})
	imp, err := svc.ImportEvidence(c.ID, res.Collection.ID, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Imported) != 1 || imp.EventCount < 5 || len(imp.ParseFailures) != 0 {
		t.Fatalf("import = imported %d events %d failures %+v errors %v", len(imp.Imported), imp.EventCount, imp.ParseFailures, imp.Errors)
	}
	events, err := svc.store.ListEvents(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	var proc, conn, snap, hidden bool
	for _, e := range events {
		switch e.EventType {
		case model.EventProcessCreate:
			if e.PID == 4242 && strings.Contains(e.CommandLine, "-enc") && e.ParentProcessName == "svchost.exe" {
				proc = true
			}
			if e.Extra["hidden_process"] == "true" && e.PID == 1337 {
				hidden = true
			}
		case model.EventNetworkConnection:
			conn = e.NetworkDest == "203.0.113.77"
		case model.EventMemorySnapshot:
			snap = true
		}
	}
	if !proc || !conn || !snap || !hidden {
		t.Errorf("process=%v connection=%v snapshot=%v hidden=%v", proc, conn, snap, hidden)
	}
	sum, err := svc.AnalyzeCase(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("findings from the memory evidence: %d", len(sum.Findings))
	// The extracted analysis keeps the evidence chain: its own hash is recorded.
	sf := catalogPaths(t, svc, res.Collection.ID)["memory/volatility-analysis.json"]
	if sf.SHA256 == "" || sf.ImportStatus != model.SourceFileImported {
		t.Errorf("source file = %+v", sf)
	}
}

func TestMemory_APluginThatFailsIsRecordedNotFatal(t *testing.T) {
	doc := memDoc()
	doc["windows.netscan.NetScan"] = map[string]any{"__error": "a netscan structure is missing in this build"}
	svc, c, img := memFixture(t, doc, "host.vmem")
	res, err := svc.DiscoverEvidenceFromPath(c.ID, img)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := svc.EvidenceFileIDs(c.ID, res.Collection.ID, EvidenceFilter{})
	if _, err := svc.ImportEvidence(c.ID, res.Collection.ID, ids); err != nil {
		t.Fatal(err)
	}
	events, _ := svc.store.ListEvents(c.ID)
	var found bool
	for _, e := range events {
		if e.EventType == model.EventMemorySnapshot && strings.Contains(e.Extra["plugins_failed"], "netscan") {
			found = true
		}
		if e.EventType == model.EventNetworkConnection {
			t.Error("a connection appeared although netscan failed")
		}
	}
	if !found {
		t.Error("the snapshot event does not record that netscan failed")
	}
}

func TestMemory_WithoutVolatilityConfiguredTheAnalystIsToldWhatToDo(t *testing.T) {
	svc := newTestService(t) // no runner
	c, _ := svc.CreateCase("no vol", "")
	img := filepath.Join(t.TempDir(), "host.vmem")
	os.WriteFile(img, []byte("{}"), 0o644)
	_, err := svc.DiscoverEvidenceFromPath(c.ID, img)
	if !errors.Is(err, ErrMemoryNotConfigured) {
		t.Fatalf("err = %v, want ErrMemoryNotConfigured", err)
	}
	if !strings.Contains(err.Error(), "TRACEFALL_VOLATILITY") {
		t.Errorf("the error does not say how to configure it: %v", err)
	}
	if cols, _ := svc.store.ListCollections(c.ID); len(cols) != 0 {
		t.Error("a collection was left behind")
	}
}

func TestMemory_AnImageVolatilityCannotIdentifyLeavesNothingBehind(t *testing.T) {
	doc := map[string]any{"windows.info.Info": map[string]any{"__error": "Unable to validate the plugin requirements: ['plugins.Info.kernel.layer_name', 'plugins.Info.kernel.symbol_table_name']"}}
	svc, c, img := memFixture(t, doc, "host.vmem")
	_, err := svc.DiscoverEvidenceFromPath(c.ID, img)
	if !errors.Is(err, memory.ErrSymbols) {
		t.Fatalf("err = %v", err)
	}
	if cols, _ := svc.store.ListCollections(c.ID); len(cols) != 0 {
		t.Error("a collection was left behind")
	}
}

func TestMemory_UploadedImageIsStoredAndImported(t *testing.T) {
	svc, c, img := memFixture(t, memDoc(), "whatever.bin")
	b, _ := os.ReadFile(img)
	res, err := svc.DiscoverEvidenceFromUpload(c.ID, bytes.NewReader(b), "host.vmem")
	if err != nil {
		t.Fatal(err)
	}
	if res.Collection.SourceType != model.SourceTypeMemoryImage {
		t.Fatalf("source type = %s", res.Collection.SourceType)
	}
	if _, err := os.Stat(svc.files.MemoryImagePath(c.ID, res.Collection.ID)); err != nil {
		t.Errorf("the uploaded image is not stored: %v", err)
	}
	ids, _ := svc.EvidenceFileIDs(c.ID, res.Collection.ID, EvidenceFilter{})
	if imp, err := svc.ImportEvidence(c.ID, res.Collection.ID, ids); err != nil || imp.EventCount == 0 {
		t.Errorf("import from the stored image: %v %+v", err, imp)
	}
}

func TestMemory_AZipOrADiskImageIsNeverTakenForMemory(t *testing.T) {
	svc, c, _ := memFixture(t, memDoc(), "x.vmem")
	res, err := svc.DiscoverEvidenceFromPath(c.ID, filepath.Join(imageFixtures, "gpt.E01"))
	if err != nil || res.Collection.SourceType != model.SourceTypeDiskImage {
		t.Fatalf("a disk image was routed to memory analysis: %v %+v", err, res.Collection.SourceType)
	}
	if sniffMemoryImage(filepath.Join(imageFixtures, "gpt.E01"), "gpt.E01") {
		t.Error("an E01 was sniffed as a memory image")
	}
	zip := buildKAPEZip(t)
	p := filepath.Join(t.TempDir(), "kape.raw") // even with a memory-like extension
	os.WriteFile(p, zip, 0o644)
	if sniffMemoryImage(p, "kape.raw") {
		t.Error("a ZIP with a .raw name was sniffed as memory")
	}
}

func TestMemory_SniffRecognisesKnownMagicAndMemoryExtensions(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, head []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, append(head, make([]byte, 4096)...), 0o644)
		return p
	}
	cases := []struct {
		name string
		head []byte
		want bool
	}{
		{"a.lime", []byte("EMiL\x01\x00\x00\x00"), true},
		{"crash.bin", []byte("PAGEDU64"), true},
		{"x.vmem", []byte("\x00\x00\x00\x00\x00\x00\x00\x00"), true},
		{"x.mem", []byte("\x00\x00\x00\x00\x00\x00\x00\x00"), true},
		{"x.dmp", []byte("\x00\x00\x00\x00\x00\x00\x00\x00"), true},
		{"notes.txt", []byte("hello wor"), false},
		{"x.bin", []byte("\x00\x00\x00\x00\x00\x00\x00\x00"), false},
	}
	for _, c := range cases {
		if got := sniffMemoryImage(mk(c.name, c.head), c.name); got != c.want {
			t.Errorf("%s: sniff = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMemory_PipelineIngestsAnImageEndToEnd(t *testing.T) {
	svc, c, img := memFixture(t, memDoc(), "host.vmem")
	svc.pipe.poll = 10 * time.Millisecond
	startWorker(t, svc)
	mux := routerFor(svc)
	_, job := enqueue(t, mux, c.ID, map[string]any{"local_path": img})
	done := waitPipelineJob(t, mux, c.ID, job.ID)
	if done.Status != model.JobSucceeded || num(done.Result, "events") < 5 || done.Result["analyzed"] != true {
		t.Errorf("job = %+v", done)
	}
}

func TestMemory_IntegrityOfTheImageCanBeReverified(t *testing.T) {
	svc, c, img := memFixture(t, memDoc(), "host.vmem")
	res, err := svc.DiscoverEvidenceFromPath(c.ID, img)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := svc.VerifyCollectionIntegrity(c.ID, res.Collection.ID)
	if err != nil || ir.Status != IntegrityVerified {
		t.Errorf("verify = %+v %v", ir, err)
	}
}

func TestMemory_TheReportStatesHowTheMemoryWasAnalysed(t *testing.T) {
	svc, c, img := memFixture(t, memDoc(), "host.vmem")
	res, _ := svc.DiscoverEvidenceFromPath(c.ID, img)
	ids, _ := svc.EvidenceFileIDs(c.ID, res.Collection.ID, EvidenceFilter{})
	if _, err := svc.ImportEvidence(c.ID, res.Collection.ID, ids); err != nil {
		t.Fatal(err)
	}
	svc.AnalyzeCase(c.ID)
	html, _, err := svc.ReportHTML(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	for _, want := range []string{"Memory image", "2.99.0", "19041.1.amd64fre", "Volatility", "snapshot"} {
		if !strings.Contains(s, want) {
			t.Errorf("the report does not mention %q", want)
		}
	}
}

func TestMemory_HTTPWithoutVolatilityIs501NotAnOpaque500(t *testing.T) {
	svc := newTestService(t)
	mux := routerFor(svc)
	c := mustCreateCase(t, mux, "http mem")
	img := filepath.Join(t.TempDir(), "host.vmem")
	os.WriteFile(img, []byte("{}"), 0o644)
	body, _ := json.Marshal(map[string]string{"path": img})
	rec := do(t, mux, http.MethodPost, "/api/cases/"+c.ID+"/ingest", body, nil)
	if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), "TRACEFALL_VOLATILITY") {
		t.Errorf("status %d body %s", rec.Code, rec.Body.String())
	}
}

var _ = context.Background
