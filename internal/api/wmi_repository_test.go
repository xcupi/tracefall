package api

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tracefall/internal/ad1/ad1gen"
	"tracefall/internal/correlate"
	"tracefall/internal/detect"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/wmitest"
)

func TestWMIRepositoryWorkerStoreDirectoryAndAD1(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ingest.SetParserRunner(ingest.Subprocess{Exe: exe, MemoryMB: 4096, Timeout: time.Minute, Sandbox: ingest.FindSandbox()})
	defer ingest.SetParserRunner(nil)
	for _, kind := range []string{"directory", "ad1", "disk", "zip"} {
		t.Run(kind, func(t *testing.T) {
			svc := newTestService(t)
			c := mustCreateCase(t, routerFor(svc), "Neutral WMI snapshot")
			files := wmitest.Bundle("neutral-api-private-canary")
			dir := t.TempDir()
			entry := dir
			if kind == "ad1" {
				list := []ad1gen.File{}
				for name, b := range files {
					list = append(list, ad1gen.File{Path: "repository/" + name, Data: b})
				}
				entry = filepath.Join(dir, "neutral.ad1")
				if err := os.WriteFile(entry, buildAD1(t, "collection", list), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				for name, b := range files {
					if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			d, err := discoverWMIFixture(t, svc, c.ID, kind, entry, files)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := svc.store.ListSourceFilesByCollection(d.Collection.ID)
			if err != nil {
				t.Fatal(err)
			}
			primary := model.SourceFile{}
			companions := 0
			for _, sf := range rows {
				if sf.ArtifactType == model.ArtifactWMIRepository && sf.Supported {
					primary = sf
				}
				if sf.ArtifactType == model.ArtifactWMIRepositoryCompanion && !sf.Supported {
					companions++
				}
			}
			if primary.ID == "" || companions != 2 {
				t.Fatalf("repository discovery primary=%q companions=%d", primary.ID, companions)
			}
			r, err := svc.ImportEvidence(c.ID, d.Collection.ID, []string{primary.ID})
			if err != nil || len(r.Errors) > 0 || r.EventCount != 3 {
				t.Fatalf("worker source import result=%+v err=%v", r, err)
			}
			events, err := svc.store.ListEvents(c.ID)
			if err != nil || len(events) != 3 {
				t.Fatalf("persisted count=%d err=%v", len(events), err)
			}
			for _, e := range events {
				if !e.Timestamp.IsZero() || e.EventType != model.EventWMISnapshot || e.CommandLine != "" || e.ProcessPath != "" || e.FilePath != "" {
					t.Fatal("snapshot became execution")
				}
				raw, err := svc.store.GetRawEvidence(e.RawEvidenceID)
				if err != nil || raw.Raw == "" {
					t.Fatal("native raw missing")
				}
				for _, sf := range rows {
					if !strings.Contains(raw.Raw, sf.ID) {
						t.Fatal("bundle provenance lacks admitted source identity")
					}
				}
			}
			primary, err = svc.store.GetSourceFile(primary.ID)
			if err != nil || primary.ParseCoverage == nil || primary.ParseCoverage.Mapped != 3 || primary.EventCount != 3 {
				t.Fatalf("stored source coverage=%+v err=%v", primary.ParseCoverage, err)
			}
			assertWMIConsumers(t, svc, c.ID, events)
			for _, sf := range rows {
				fresh, err := svc.store.GetSourceFile(sf.ID)
				if err != nil || fresh.SHA256 == "" {
					t.Fatal("required companion source hash not recorded")
				}
			}
		})
	}
}

func discoverWMIFixture(t *testing.T, svc *Service, caseID, kind, entry string, files map[string][]byte) (DiscoverResult, error) {
	t.Helper()
	if kind == "disk" {
		if _, err := exec.LookPath("mkfs.ext4"); err != nil {
			t.Skip("mkfs.ext4 required for synthetic disk bundle proof")
		}
		img := filepath.Join(t.TempDir(), "neutral.img")
		if out, err := exec.Command("mkfs.ext4", "-q", "-F", "-d", entry, img, "16M").CombinedOutput(); err != nil {
			t.Fatalf("synthetic mkfs: %v %s", err, out)
		}
		return svc.DiscoverEvidenceFromPath(caseID, img)
	}
	if kind == "zip" {
		content := map[string]string{}
		for name, b := range files {
			content["repository/"+name] = string(b)
		}
		rec := uploadZip(t, routerFor(svc), caseID, buildZipBytes(t, content))
		if rec.Code != 200 {
			t.Fatalf("ZIP bundle upload: %d %s", rec.Code, rec.Body.String())
		}
		var d DiscoverResult
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		return d, nil
	}
	return svc.DiscoverEvidenceFromPath(caseID, entry)
}
func assertWMIConsumers(t *testing.T, svc *Service, caseID string, events []model.Event) {
	t.Helper()
	if got := detect.Run(caseID, events); len(got) != 0 {
		t.Fatal("snapshot alone became a risk/malicious finding")
	}
	cs, err := correlate.RunFrom(caseID, svc.store.EventSourceFor(caseID))
	if err != nil || len(cs) != 1 || cs[0].Type != model.CorrelationWMIConfigurationContext {
		t.Fatalf("filtered persisted context=%+v err=%v", cs, err)
	}
	if _, err = svc.AnalyzeCase(caseID); err != nil {
		t.Fatal(err)
	}
	cs, err = svc.store.ListCorrelations(caseID)
	if err != nil || len(cs) != 1 || cs[0].Type != model.CorrelationWMIConfigurationContext {
		t.Fatal("generic snapshot context not persisted")
	}
	report, err := svc.buildReport(caseID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer report.release()
	check := func(b []byte) {
		for _, secret := range []string{"neutral-api-private-canary", "filter01", "consumer01"} {
			if strings.Contains(string(b), secret) {
				t.Fatalf("private property leaked to default consumer: %s", secret)
			}
		}
	}
	check(report.HTML)
	for _, f := range report.Files {
		check(f.Data)
	}
	preview, err := svc.PreviewCaseReview(caseID)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(preview)
	check(b)
	var body any
	rec := doJSON(t, routerFor(svc), "GET", "/api/cases/"+caseID+"/events", nil, &body)
	if rec.Code != 200 {
		t.Fatal("event projection unavailable")
	}
	b, _ = json.Marshal(body)
	check(b)
	rawRetained := false
	for _, e := range events {
		provenance, err := svc.EventProvenance(caseID, e.ID)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(provenance.RawEvidence.Raw, "neutral-api-private-canary") {
			rawRetained = true
		}
	}
	if !rawRetained {
		t.Fatal("explicit authorized local provenance lost native values")
	}
}
