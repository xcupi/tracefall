package store

import (
	"testing"
	"time"

	"tracefall/internal/model"
)

func enrichment(id, ind, status string) model.Enrichment {
	return model.Enrichment{ID: id, CaseID: "case-1", Provider: model.EnrichmentVirusTotal, IndicatorType: "sha256", Indicator: ind, Status: status,
		ResultJSON: `{"found":true}`, FetchedAt: time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC), SourceEventIDs: []string{"ev-1", "ev-2"}}
}

func TestEnrichments_UpsertReplacesTheSameIndicatorOnly(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	if err := s.UpsertEnrichment(enrichment("a", "bbb", model.EnrichmentError)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEnrichment(enrichment("b", "aaa", model.EnrichmentFound)); err != nil {
		t.Fatal(err)
	}
	later := enrichment("c", "bbb", model.EnrichmentNotFound)
	later.FetchedAt = later.FetchedAt.Add(time.Hour)
	later.Error = ""
	if err := s.UpsertEnrichment(later); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListEnrichments("case-1", model.EnrichmentVirusTotal)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Indicator != "aaa" || got[1].Indicator != "bbb" {
		t.Fatalf("rows = %+v", got)
	}
	if got[1].Status != model.EnrichmentNotFound || !got[1].FetchedAt.Equal(later.FetchedAt) {
		t.Errorf("a later answer must replace the earlier one: %+v", got[1])
	}
	if len(got[0].SourceEventIDs) != 2 || got[0].SourceEventIDs[1] != "ev-2" || got[0].ResultJSON != `{"found":true}` {
		t.Errorf("fields did not round-trip: %+v", got[0])
	}
	if other, _ := s.ListEnrichments("case-1", "someone-else"); len(other) != 0 {
		t.Errorf("another provider's rows: %+v", other)
	}
}

func TestEnrichments_DailyCountIsAcrossCasesAndWindowed(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	now := time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC)
	if err := s.CreateCase(model.Case{ID: "case-2", Name: "second", Status: model.CaseStatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	old := enrichment("o", "old", model.EnrichmentFound)
	old.FetchedAt = now.Add(-30 * time.Hour)
	recent := enrichment("r", "recent", model.EnrichmentFound)
	recent.FetchedAt = now.Add(-2 * time.Hour)
	other := enrichment("x", "other", model.EnrichmentNotFound)
	other.CaseID = "case-2"
	other.FetchedAt = now.Add(-time.Hour)
	for _, e := range []model.Enrichment{old, recent, other} {
		if err := s.UpsertEnrichment(e); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.CountEnrichmentRequestsSince(model.EnrichmentVirusTotal, now.Add(-24*time.Hour))
	if err != nil || n != 2 {
		t.Errorf("count = %d, %v; want 2 (the 30-hour-old answer is outside the day, the other case's counts)", n, err)
	}
}

func TestEventFieldsByKey_ExactKeysOnly(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	mk := func(id string, extra map[string]string) model.Event {
		return model.Event{ID: id, CaseID: "case-1", CollectionID: "collection-1", Timestamp: time.Now().UTC(), EventType: model.EventLogonSuccess,
			ArtifactType: model.ArtifactWindowsEventLog, SourceFileID: "sf-1", Parser: "p", Confidence: 1, DedupHash: id, Extra: extra}
	}
	if err := s.SaveEvents([]model.Event{
		mk("e1", map[string]string{"content_sha256": "aa", "sha1": "bb"}),
		mk("e2", map[string]string{"ntlm_hash": "NTLM", "sql_record_sha256": "sqlsha", "sha1_raw": "rawsha1", "boot_key_source_sha256": "bk"}),
		mk("e3", map[string]string{"note": `mentions "sha1": in text`}),
		mk("e4", nil),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.EventFieldsByKey("case-1", []string{"content_sha256", "sha1", "sha256", "md5", "response_sha256"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (HashField{"e1", "content_sha256", "aa"}) || got[1] != (HashField{"e1", "sha1", "bb"}) {
		t.Errorf("fields = %+v", got)
	}
	if none, _ := s.EventFieldsByKey("case-2", []string{"sha1"}); len(none) != 0 {
		t.Errorf("another case's fields: %+v", none)
	}
	if none, err := s.EventFieldsByKey("case-1", nil); err != nil || none != nil {
		t.Errorf("no keys: %v %v", none, err)
	}
}

func TestDeleteCase_RemovesEnrichmentsAndTheEgressSetting(t *testing.T) {
	s := openTest(t)
	seedCaseAndSourceFile(t, s)
	if err := s.UpsertEnrichment(enrichment("a", "aaa", model.EnrichmentFound)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("egress:case-1", "hashes"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("egress:case-2", "hashes"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCase("case-1"); err != nil {
		t.Fatal(err)
	}
	if rows, _ := s.ListEnrichments("case-1", model.EnrichmentVirusTotal); len(rows) != 0 {
		t.Errorf("enrichments survive the case: %+v", rows)
	}
	if _, ok, _ := s.GetSetting("egress:case-1"); ok {
		t.Errorf("the deleted case's egress level survives")
	}
	if v, ok, _ := s.GetSetting("egress:case-2"); !ok || v != "hashes" {
		t.Errorf("another case's egress level was removed")
	}
}
