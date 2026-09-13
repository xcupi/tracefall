package api

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"tracefall/internal/artifacts"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// Recycle Bin exposure in the Timeline UI.
//
// The backend $I parser and its recyclebin_deletion events already
// existed; what was missing was that the Artifact filter offered them
// under "Windows Recycle Bin $I metadata" -- so an analyst looking for
// "Recycle Bin" did not find it. These tests pin the name, the mapping
// and the detail, without touching the parser's forensic semantics.

func recycleBinCase(t *testing.T, mux http.Handler) string {
	t.Helper()
	c := mustCreateCase(t, mux, "recycle bin "+t.Name())
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		`C/$Recycle.Bin/S-1-5-21-1004336348-1177238915-682003330-1001/$IA1B2C3.docx`: sampleIRecord(),
	})
	if imp := importAllFrom(t, mux, c.ID, disc); len(imp.ParseFailures) != 0 {
		t.Fatalf("fixture failed to parse: %+v", imp.ParseFailures)
	}
	return c.ID
}

// 1 + 2: the artifact is supported and offered as "Recycle Bin".
func TestRecycleBinUI_AppearsInTheArtifactFilterByName(t *testing.T) {
	mux := newTestRouter(t)
	caseID := recycleBinCase(t, mux)

	var facets EventFacetsResponse
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/facets", nil, &facets)
	if rec.Code != http.StatusOK {
		t.Fatalf("facets: %d %s", rec.Code, rec.Body.String())
	}
	var found *FacetOption
	for i := range facets.ArtifactTypes {
		if facets.ArtifactTypes[i].Value == model.ArtifactRecycleBin {
			found = &facets.ArtifactTypes[i]
		}
	}
	if found == nil {
		var got []string
		for _, o := range facets.ArtifactTypes {
			got = append(got, o.Value)
		}
		t.Fatalf("the Recycle Bin artifact is absent from the filter; options were %v", got)
	}
	if found.Label != "Recycle Bin" {
		t.Errorf("artifact filter label = %q, want %q", found.Label, "Recycle Bin")
	}
}

// The capability registry must classify it as supported, naming the
// parser that produces it.
func TestRecycleBinUI_RegisteredAsSupported(t *testing.T) {
	r := artifacts.NewRegistry(ingest.Registry())
	c := r.Classify("", model.ArtifactRecycleBin)
	if !c.Supported {
		t.Error("the Recycle Bin artifact type is not registered as supported")
	}
	if c.Label != "Recycle Bin" {
		t.Errorf("registry label = %q, want %q", c.Label, "Recycle Bin")
	}
	if c.Parser == "" {
		t.Error("no parser is named for the Recycle Bin artifact")
	}
	if c.Priority != artifacts.PriorityHigh {
		t.Errorf("priority = %q, want high", c.Priority)
	}
}

// 3 + 6: filtering by Artifact = Recycle Bin returns the deletion events.
func TestRecycleBinUI_FilteringReturnsTheDeletionEvents(t *testing.T) {
	mux := newTestRouter(t)
	caseID := recycleBinCase(t, mux)

	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactRecycleBin))
	if res.Total != 1 {
		t.Fatalf("filtering by Recycle Bin returned %d events, want 1", res.Total)
	}
	e := res.Items[0]
	if e.EventType != model.EventRecycleBinDeletion {
		t.Errorf("event type = %q, want %q", e.EventType, model.EventRecycleBinDeletion)
	}
	if e.ArtifactLabel != "Recycle Bin" {
		t.Errorf("event artifact label = %q, want %q", e.ArtifactLabel, "Recycle Bin")
	}
	// The event-type filter must reach the same event.
	if byType := searchEvents(t, mux, caseID, vals("event_type", model.EventRecycleBinDeletion)); byType.Total != 1 {
		t.Errorf("filtering by event type returned %d, want 1", byType.Total)
	}
}

// 7: the detail must carry the deleted-file information an analyst needs.
func TestRecycleBinUI_DetailCarriesTheDeletedFileInformation(t *testing.T) {
	mux := newTestRouter(t)
	caseID := recycleBinCase(t, mux)

	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactRecycleBin))
	if res.Total != 1 {
		t.Fatalf("got %d events", res.Total)
	}
	e := res.Items[0]

	for _, key := range []string{
		"original_path", "original_name", "original_directory", "original_size",
		"record_version", "record_version_name",
		"paired_r_file", "paired_r_file_status",
		"timestamp_meaning", "timestamp_source", "evidence_meaning",
	} {
		if strings.TrimSpace(e.Extra[key]) == "" {
			t.Errorf("the event detail is missing %q", key)
		}
	}
	// The deletion time is the event's own timestamp, and says so.
	if e.Timestamp.IsZero() {
		t.Error("the deletion time is not on the event")
	}
	if !strings.Contains(e.Extra["timestamp_meaning"], "deletion time") {
		t.Errorf("timestamp_meaning = %q; it must identify the deletion time", e.Extra["timestamp_meaning"])
	}
	// The timeline row's detail value must be the original path, not the
	// $I filename on disk.
	if !strings.HasSuffix(e.FilePath, ".docx") || !strings.Contains(e.FilePath, `\`) {
		t.Errorf("FilePath = %q, want the deleted file's original full path", e.FilePath)
	}
	if strings.Contains(e.FilePath, "$I") {
		t.Errorf("FilePath = %q; the $I filename must never be shown as the original name", e.FilePath)
	}
}

// 8: $R stays supporting evidence for the $I record, never a separate
// deletion artifact.
func TestRecycleBinUI_RContentRemainsSupportingEvidence(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "I and R pair")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		`C/$Recycle.Bin/S-1-5-21-1-1-1-1001/$IA1B2C3.docx`: sampleIRecord(),
		`C/$Recycle.Bin/S-1-5-21-1-1-1-1001/$RA1B2C3.docx`: []byte("the deleted file's content"),
	})
	if imp := importAllFrom(t, mux, c.ID, disc); len(imp.ParseFailures) != 0 {
		t.Fatalf("parse failures: %+v", imp.ParseFailures)
	}

	// Exactly one timeline event, from the $I record.
	all := searchEvents(t, mux, c.ID, vals("page_size", "50"))
	if all.Total != 1 {
		t.Fatalf("got %d events, want 1 -- the $R half must not produce its own", all.Total)
	}
	if all.Items[0].ArtifactType != model.ArtifactRecycleBin {
		t.Errorf("the single event is %q, want the $I metadata artifact", all.Items[0].ArtifactType)
	}
	if n := searchEvents(t, mux, c.ID, vals("artifact_type", model.ArtifactRecycleBinContent)).Total; n != 0 {
		t.Errorf("the $R content produced %d timeline events; it is supporting evidence, not a deletion record", n)
	}
	// And the $I event reports the pairing as found.
	e := all.Items[0]
	if !strings.Contains(e.Extra["paired_r_file_status"], "present") {
		t.Errorf("paired_r_file_status = %q, want it to report the $R as present", e.Extra["paired_r_file_status"])
	}
	if e.Extra["paired_r_file"] == "" {
		t.Error("the paired $R filename was not recorded")
	}
	// The $R file is still IMPORTED as evidence, just eventless.
	var facets EventFacetsResponse
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/facets", nil, &facets)
	for _, o := range facets.ArtifactTypes {
		if o.Value == model.ArtifactRecycleBinContent {
			t.Error("the $R content type is offered in the event filter despite producing no events")
		}
	}
}

// 5: the option appears only when the events exist.
func TestRecycleBinUI_AbsentWhenNoIRecordExists(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "no recycle bin")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		"Windows/Prefetch/UPDATE.EXE-0BADF00D.pf": samplePrefetch(),
	})
	importAllFrom(t, mux, c.ID, disc)

	var facets EventFacetsResponse
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/facets", nil, &facets)
	for _, o := range facets.ArtifactTypes {
		if o.Value == model.ArtifactRecycleBin {
			t.Error("Recycle Bin is offered in a case that holds no $I record")
		}
	}
	if n := searchEvents(t, mux, c.ID, vals("artifact_type", model.ArtifactRecycleBin)).Total; n != 0 {
		t.Errorf("a case with no $I record returned %d Recycle Bin events", n)
	}
}

// 9: provenance from the event back to the $I file and its collection.
func TestRecycleBinUI_ProvenanceReachesTheIRecord(t *testing.T) {
	mux := newTestRouter(t)
	caseID := recycleBinCase(t, mux)

	res := searchEvents(t, mux, caseID, vals("artifact_type", model.ArtifactRecycleBin))
	if res.Total != 1 {
		t.Fatalf("got %d events", res.Total)
	}
	var prov EventProvenance
	rec := doJSON(t, mux, "GET", "/api/cases/"+caseID+"/events/"+res.Items[0].ID, nil, &prov)
	if rec.Code != http.StatusOK {
		t.Fatalf("provenance: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(prov.SourceFile.Path, "$I") {
		t.Errorf("provenance does not reach the $I file: %q", prov.SourceFile.Path)
	}
	if prov.SourceFile.ArtifactType != model.ArtifactRecycleBin {
		t.Errorf("source file artifact type = %q", prov.SourceFile.ArtifactType)
	}
	if prov.ArtifactLabel != "Recycle Bin" {
		t.Errorf("provenance artifact label = %q, want %q", prov.ArtifactLabel, "Recycle Bin")
	}
	if prov.Collection == nil || prov.Collection.CollectionID == "" {
		t.Error("the event does not resolve to an evidence collection")
	}
	if prov.RawEvidence.Raw == "" {
		t.Error("no raw $I record is retained")
	}
	// The raw record must still carry the full field set.
	var raw map[string]any
	if err := json.Unmarshal([]byte(prov.RawEvidence.Raw), &raw); err != nil {
		t.Fatalf("raw record is not JSON: %v", err)
	}
	for _, k := range []string{"original_path", "original_name", "original_directory",
		"original_size_bytes", "record_version", "paired_r_file"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("the raw $I record is missing %q", k)
		}
	}
}

// 10: deleting the source evidence removes the derived events.
func TestRecycleBinUI_DeletingEvidenceRemovesTheEvents(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "recycle bin deletion")
	disc := discoverBinaryDir(t, mux, c.ID, map[string][]byte{
		`C/$Recycle.Bin/S-1-5-21-1-1-1-1001/$IA1B2C3.docx`: sampleIRecord(),
	})
	importAllFrom(t, mux, c.ID, disc)

	if searchEvents(t, mux, c.ID, vals("artifact_type", model.ArtifactRecycleBin)).Total != 1 {
		t.Fatal("no event to delete")
	}
	rec := doJSON(t, mux, "DELETE", "/api/cases/"+c.ID+"/collections/"+disc.Collection.ID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("deleting: %d %s", rec.Code, rec.Body.String())
	}
	if n := searchEvents(t, mux, c.ID, vals("artifact_type", model.ArtifactRecycleBin)).Total; n != 0 {
		t.Errorf("%d Recycle Bin events survived deletion of their $I file", n)
	}
	var facets EventFacetsResponse
	doJSON(t, mux, "GET", "/api/cases/"+c.ID+"/events/facets", nil, &facets)
	if len(facets.ArtifactTypes) != 0 {
		t.Errorf("the artifact filter still offers %d options after all evidence was deleted", len(facets.ArtifactTypes))
	}
}

// 4: the frontend's own label table must agree with the server registry,
// or one artifact is called two different things in one application.
func TestUI_ArtifactLabelsMatchTheServerRegistry(t *testing.T) {
	src := string(appJS(t))
	block := src[strings.Index(src, "const ARTIFACT_TYPE_LABELS"):]
	block = block[:strings.Index(block, "\n};")]

	js := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s+([a-z0-9_]+):\s*"([^"]*)"`).FindAllStringSubmatch(block, -1) {
		js[m[1]] = m[2]
	}
	if len(js) == 0 {
		t.Fatal("could not read ARTIFACT_TYPE_LABELS from app.js")
	}

	r := artifacts.NewRegistry(ingest.Registry())
	types := map[string]bool{}
	for _, p := range ingest.Registry() {
		types[p.ArtifactType()] = true
		if src, ok := p.(parsers.EventArtifactTypeSource); ok {
			for _, at := range src.EventArtifactTypes() {
				types[at] = true
			}
		}
	}

	for at := range types {
		want := r.Classify("", at).Label
		got, ok := js[at]
		if !ok {
			t.Errorf("app.js has no label for supported artifact %q (server calls it %q)", at, want)
			continue
		}
		if got != want {
			t.Errorf("artifact %q: app.js says %q, the server registry says %q", at, got, want)
		}
	}
	// Recycle Bin specifically, since that is what this pass is about.
	if js[model.ArtifactRecycleBin] != "Recycle Bin" {
		t.Errorf("app.js labels the Recycle Bin artifact %q", js[model.ArtifactRecycleBin])
	}
}

// Every event type must be categorized, or it silently renders as
// "Other" in the timeline's Category column.
func TestUI_EveryEventTypeIsCategorized(t *testing.T) {
	src := string(appJS(t))
	block := src[strings.Index(src, "const EVENT_CATEGORIES"):]
	block = block[:strings.Index(block, "\n};")]
	mapped := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+([a-z0-9_]+):`).FindAllStringSubmatch(block, -1) {
		mapped[m[1]] = true
	}

	labels := src[strings.Index(src, "const EVENT_CATEGORY_LABELS"):]
	labels = labels[:strings.Index(labels, "\n};")]
	known := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+([a-z0-9_]+):`).FindAllStringSubmatch(labels, -1) {
		known[m[1]] = true
	}

	// Read the event-type constants out of the model.
	modelSrc := readModelSource(t)
	// Anchored to the start of the identifier: "ArtifactWindowsEventLog"
	// also contains "Event", and matching it would demand a category for
	// an ARTIFACT type.
	for _, m := range regexp.MustCompile(`(?m)^\s+(Event[A-Za-z]+)\s*=\s*"([a-z0-9_]+)"`).FindAllStringSubmatch(modelSrc, -1) {
		et := m[2]
		if !mapped[et] {
			t.Errorf("event type %q is not categorized; it renders as \"Other\"", et)
		}
	}
	// And every category used must have a label.
	for _, m := range regexp.MustCompile(`(?m)^\s+[a-z0-9_]+:\s*"([a-z_]+)"`).FindAllStringSubmatch(block, -1) {
		if !known[m[1]] {
			t.Errorf("category %q has no label in EVENT_CATEGORY_LABELS", m[1])
		}
	}
	if mapped[model.EventRecycleBinDeletion] != true {
		t.Error("recyclebin_deletion is not categorized")
	}
}

func readModelSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../model/model.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
