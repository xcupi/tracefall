package memory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeVolPy stands in for vol. The "image" is a JSON document mapping a
// plugin name to either its rows or {"__error": "stderr text"}; the
// script prints what the real renderer would.
const fakeVolPy = `#!/usr/bin/python3
import json, sys
a = sys.argv[1:]
if a and a[0] == "-h":
    print("Volatility 3 Framework 2.99.0")
    print("    plugin:")
    for p in ["windows.info.Info","windows.pslist.PsList","windows.psscan.PsScan","windows.cmdline.CmdLine",
              "windows.netscan.NetScan","windows.malware.malfind.Malfind","windows.svcscan.SvcScan",
              "windows.cmdscan.CmdScan","windows.consoles.Consoles","windows.filescan.FileScan","windows.dumpfiles.DumpFiles"]:
        print("    " + p)
    sys.exit(0)
img = a[a.index("-f")+1]
plugin = [x for x in a if x.startswith("windows.")][-1]
doc = json.load(open(img))
if plugin == "windows.dumpfiles.DumpFiles":
    # "dump:<virtaddr>" maps to {"error": text} or a list of
    # {"cache", "result", "content"}; the files are written to -o.
    va = a[a.index("--virtaddr")+1]
    d = doc.get("dump:" + va, [])
    if isinstance(d, dict):
        sys.stderr.write(d["error"] + "\n"); sys.exit(1)
    out = a[a.index("-o")+1]
    rows = []
    for e in d:
        if e.get("content") is not None:
            open(out + "/" + e["result"].split("/")[-1], "w").write(e["content"])
        rows.append({"Cache": e["cache"], "FileName": "x", "FileObject": int(va), "Result": e["result"], "__children": []})
    print()
    print(json.dumps(rows))
    sys.exit(0)
if plugin not in doc:
    sys.stderr.write("Plugin not found: " + plugin + "\n"); sys.exit(2)
v = doc[plugin]
if isinstance(v, dict) and "__error" in v:
    sys.stderr.write(v["__error"] + "\n"); sys.exit(1)
print()
print(json.dumps([dict(r, __children=[]) for r in v]))
`

func fakeImage(t *testing.T, doc map[string]any) (*Runner, string) {
	t.Helper()
	dir := t.TempDir()
	vol := filepath.Join(dir, "vol")
	if err := os.WriteFile(vol, []byte(fakeVolPy), 0o755); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(t.TempDir(), "mem.raw")
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(img, b, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(Config{Vol: vol, CacheDir: t.TempDir(), Timeout: 30 * time.Second, AllowUnsandboxed: true})
	if err != nil {
		t.Fatal(err)
	}
	return r, img
}

func rows(kv ...map[string]any) []any {
	out := make([]any, len(kv))
	for i, k := range kv {
		out[i] = k
	}
	return out
}

func fullDoc() map[string]any {
	return map[string]any{
		"windows.info.Info": rows(
			map[string]any{"Variable": "Kernel Base", "Value": "0xf80000000000"},
			map[string]any{"Variable": "NTBuildLab", "Value": "19041.1.amd64fre.vb_release.191206-1406"},
			map[string]any{"Variable": "Is64Bit", "Value": "True"},
			map[string]any{"Variable": "SystemTime", "Value": "2026-02-01 09:30:00+00:00"},
		),
		"windows.pslist.PsList":           rows(map[string]any{"PID": 4, "PPID": 0, "ImageFileName": "System"}),
		"windows.psscan.PsScan":           rows(map[string]any{"PID": 4, "PPID": 0, "ImageFileName": "System"}),
		"windows.cmdline.CmdLine":         rows(map[string]any{"PID": 4, "Process": "System", "Args": "Required memory at 0x20 is inaccessible"}),
		"windows.netscan.NetScan":         rows(),
		"windows.malware.malfind.Malfind": rows(),
		"windows.svcscan.SvcScan":         rows(),
		"windows.cmdscan.CmdScan":         rows(),
		"windows.consoles.Consoles":       rows(),
		"windows.filescan.FileScan":       rows(),
	}
}

func TestCollect_RunsTheWholeSetAndRecordsEachPlugin(t *testing.T) {
	r, img := fakeImage(t, fullDoc())
	var seen []string
	a, err := Collect(context.Background(), r, img, func(p string) { seen = append(seen, p) })
	if err != nil {
		t.Fatal(err)
	}
	if a.Schema != AnalysisSchema || a.Volatility != "2.99.0" || a.Isolation != string(r.Isolation()) || a.ImageName != "mem.raw" || a.ImageSize == 0 {
		t.Errorf("header = %+v", a)
	}
	if a.Info["SystemTime"] != "2026-02-01 09:30:00+00:00" || a.Info["NTBuildLab"] == "" {
		t.Errorf("info = %v", a.Info)
	}
	byLogical := map[string]PluginResult{}
	for _, p := range a.Plugins {
		byLogical[p.Logical] = p
		if p.Status != StatusOK {
			t.Errorf("%s: status %s (%s)", p.Logical, p.Status, p.Error)
		}
	}
	for _, want := range []string{"pslist", "psscan", "cmdline", "netscan", "malfind", "svcscan", "cmdscan", "consoles", "filescan"} {
		if _, ok := byLogical[want]; !ok {
			t.Errorf("plugin %s was not run", want)
		}
	}
	if byLogical["malfind"].Plugin != "windows.malware.malfind.Malfind" {
		t.Errorf("malfind resolved to %q", byLogical["malfind"].Plugin)
	}
	if len(byLogical["pslist"].Rows) != 1 || len(seen) < len(a.Plugins) {
		t.Errorf("rows %d, progress calls %v", len(byLogical["pslist"].Rows), seen)
	}
}

func TestCollect_OnePluginFailingDoesNotLoseTheOthers(t *testing.T) {
	doc := fullDoc()
	doc["windows.netscan.NetScan"] = map[string]any{"__error": "Unsatisfied requirement netscan: a structure is missing in this build"}
	r, img := fakeImage(t, doc)
	a, err := Collect(context.Background(), r, img, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range a.Plugins {
		switch p.Logical {
		case "netscan":
			if p.Status != StatusFailed || p.Error == "" || len(p.Rows) != 0 {
				t.Errorf("netscan = %+v: a failure must be recorded with its reason", p)
			}
		case "pslist":
			if p.Status != StatusOK || len(p.Rows) != 1 {
				t.Errorf("pslist lost to netscan's failure: %+v", p)
			}
		}
	}
}

func TestCollect_APluginThisVersionLacksIsRecordedAsUnavailable(t *testing.T) {
	doc := fullDoc()
	delete(doc, "windows.svcscan.SvcScan") // fake -h still lists it; ask for one it does not list instead
	r, img := fakeImage(t, doc)
	a, err := Collect(context.Background(), r, img, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range a.Plugins {
		if p.Logical == "svcscan" && p.Status != StatusFailed {
			t.Errorf("svcscan = %+v", p)
		}
	}
}

func TestCollect_ImageVolatilityCannotIdentifyIsAnErrorNotAnEmptyAnalysis(t *testing.T) {
	doc := map[string]any{"windows.info.Info": map[string]any{
		"__error": "Unable to validate the plugin requirements: ['plugins.Info.kernel.layer_name', 'plugins.Info.kernel.symbol_table_name']"}}
	r, img := fakeImage(t, doc)
	a, err := Collect(context.Background(), r, img, nil)
	if !errors.Is(err, ErrSymbols) {
		t.Fatalf("err = %v, want ErrSymbols", err)
	}
	if len(a.Plugins) != 0 {
		t.Error("plugins were run against an image that could not be identified")
	}
}

func TestCollect_AnalysisSerializesAndReloads(t *testing.T) {
	r, img := fakeImage(t, fullDoc())
	a, err := Collect(context.Background(), r, img, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), AnalysisSchema) {
		t.Error("schema marker missing from the serialized analysis")
	}
	var back Analysis
	if err := json.Unmarshal(b, &back); err != nil || len(back.Plugins) != len(a.Plugins) {
		t.Errorf("reload: %v", err)
	}
}

func TestCollect_StopsWhenCancelled(t *testing.T) {
	r, img := fakeImage(t, fullDoc())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Collect(ctx, r, img, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}
