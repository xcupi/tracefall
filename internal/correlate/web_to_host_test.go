package correlate

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/clockskew"
	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

func delivery(id, name, sig, status, reassembly string) model.Event {
	return model.Event{
		ID: id, ArtifactType: model.ArtifactNetworkCapture, EventType: model.EventWebRequest, Timestamp: skewBase,
		NetworkSource: "10.0.0.5", NetworkDest: "203.0.113.9", NetworkDestPort: 80,
		Extra: map[string]string{"filename": name, "response_sha256": strings.Repeat("ab", 32), "response_size": "2048",
			"file_signature": sig, "status": status, "reassembly": reassembly},
	}
}

func hostFile(id, host, path string, at time.Time) model.Event {
	return model.Event{ID: id, Host: host, ArtifactType: model.ArtifactMFT, EventType: model.EventFilesystemCreated, Timestamp: at, FilePath: path}
}

func TestWebToHost_ANamedExecutableThatAppearsOnTheClientIsTied(t *testing.T) {
	cap := []model.Event{delivery("w1", "Updater.exe", "Windows executable (MZ)", "200", "complete")}
	host := []model.Event{
		hostFile("f1", "WS-B", `C:\Users\u\Downloads\updater.exe`, skewBase.Add(5*time.Minute)),
		hostFile("f2", "WS-B", `C:\Users\u\Downloads\other.exe`, skewBase.Add(5*time.Minute)),
		hostFile("f3", "WS-B", `C:\Windows\updater.exe`, skewBase.Add(-3*time.Hour)),          // before
		hostFile("f4", "WS-B", `C:\Windows\updater.exe`, skewBase.Add(48*time.Hour)),          // far after
		hostFile("f5", "WS-C", `C:\Users\u\Downloads\updater.exe`, skewBase.Add(time.Minute)), // other machine
	}
	reg := hostid.Build([]model.Event{hostWithIP("i1", "WS-B", "10.0.0.5")})
	got := BuildWebToHost("case-1", cap, host, reg, nil)
	if len(got) != 1 {
		t.Fatalf("got %d: %+v", len(got), got)
	}
	c := got[0]
	if c.Type != model.CorrelationWebToHost || len(c.EventIDs) != 2 || c.EventIDs[0] != "w1" || c.EventIDs[1] != "f1" {
		t.Fatalf("events %v (only the same-name file on the receiving machine, inside the window)", c.EventIDs)
	}
	for _, want := range []string{"by file name and order in time, not by content", strings.Repeat("ab", 32), "WS-B", "No clock offset was established"} {
		if !strings.Contains(c.Description, want) {
			t.Errorf("description lacks %q:\n%s", want, c.Description)
		}
	}
}

func TestWebToHost_AnUnresolvedClientDoesNotRestrictTheMachine_AndSaysSo(t *testing.T) {
	cap := []model.Event{delivery("w1", "payload.exe", "Windows executable (MZ)", "200", "complete")}
	host := []model.Event{hostFile("f1", "WS-C", `C:\t\payload.exe`, skewBase.Add(time.Minute))}
	got := BuildWebToHost("case-1", cap, host, hostid.Build(nil), nil)
	if len(got) != 1 || !strings.Contains(got[0].Description, "does not say which machine the client address is") {
		t.Fatalf("%+v", got)
	}
}

func TestWebToHost_UsesTheClockEstimateToPutHostTimesOnTheCaptureScale(t *testing.T) {
	cap := []model.Event{delivery("w1", "payload.exe", "Windows executable (MZ)", "200", "complete")}
	// The host's clock is an hour behind; its event reads 59 minutes before
	// the transfer but is, on the capture's scale, a minute after it.
	host := []model.Event{hostFile("f1", "WS-B", `C:\t\payload.exe`, skewBase.Add(-59*time.Minute))}
	reg := hostid.Build([]model.Event{hostWithIP("i1", "WS-B", "10.0.0.5")})
	if got := BuildWebToHost("case-1", cap, host, reg, nil); len(got) != 0 {
		t.Fatalf("without an offset the event is before the transfer: %+v", got)
	}
	est := []clockskew.Estimate{{Subject: "host:ws-b", Reference: "capture:cap1", Consistent: true, Lo: -time.Hour - time.Second, Hi: -time.Hour + time.Second}}
	got := BuildWebToHost("case-1", cap, host, reg, est)
	if len(got) != 1 || !strings.Contains(got[0].Description, "capture's scale") {
		t.Fatalf("%+v", got)
	}
}

func TestWebToHost_OnlyWholeSuccessfulRunnableObjectsCount(t *testing.T) {
	host := []model.Event{
		hostFile("f1", "WS-B", `C:\t\a.exe`, skewBase.Add(time.Minute)), hostFile("f2", "WS-B", `C:\t\logo.png`, skewBase.Add(time.Minute)),
		hostFile("f3", "WS-B", `C:\t\index.html`, skewBase.Add(time.Minute)),
	}
	for name, ev := range map[string]model.Event{
		"incomplete body":  delivery("w", "a.exe", "Windows executable (MZ)", "200", "incomplete"),
		"not found":        delivery("w", "a.exe", "Windows executable (MZ)", "404", "complete"),
		"image":            delivery("w", "logo.png", "PNG image", "200", "complete"),
		"generic document": delivery("w", "index.html", "HTML", "200", "complete"),
	} {
		if got := BuildWebToHost("case-1", []model.Event{ev}, host, nil, nil); len(got) != 0 {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func TestWebObjectNames(t *testing.T) {
	got := webObjectNames([]model.Event{
		delivery("a", "B.exe", "Windows executable (MZ)", "200", "complete"),
		delivery("b", "a.exe", "Windows executable (MZ)", "200", "complete"),
		delivery("c", "b.exe", "Windows executable (MZ)", "200", "complete"),
		delivery("d", "logo.png", "PNG image", "200", "complete"),
	})
	if len(got) != 2 || got[0] != "a.exe" || got[1] != "b.exe" {
		t.Fatalf("%v", got)
	}
}

func TestRunFrom_BuildsClockOffsetsAndWebDeliveriesFromOneSource(t *testing.T) {
	ev := []model.Event{
		hostWithIP("i1", "WS-B", "10.0.0.5"),
		delivery("w1", "payload.exe", "Windows executable (MZ)", "200", "complete"),
		hostFile("f1", "WS-B", `C:\t\payload.exe`, skewBase.Add(time.Minute)),
		ntpClient("n1", "10.0.0.5", skewBase, -time.Hour),
	}
	got, err := RunFrom("case-1", model.SliceSource(ev))
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, c := range got {
		types[c.Type]++
	}
	if types[model.CorrelationWebToHost] != 1 || types[model.CorrelationClockSkew] != 1 {
		t.Fatalf("%v", types)
	}
}

func TestWebToHost_AFileObjectInALaterMemoryImageIsStillTied(t *testing.T) {
	cap := []model.Event{delivery("w1", "payload.exe", "Windows executable (MZ)", "200", "complete")}
	mem := model.Event{ID: "m1", Host: "WS-B", ArtifactType: model.ArtifactMemoryAnalysis, EventType: model.EventMemoryFile,
		Timestamp: skewBase.Add(72 * time.Hour), FilePath: `\Users\u\payload.exe`}
	got := BuildWebToHost("case-1", cap, []model.Event{mem}, hostid.Build(nil), nil)
	if len(got) != 1 {
		t.Fatalf("a file still in memory days later is the strongest kind of tie: %+v", got)
	}
}
