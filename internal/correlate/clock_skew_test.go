package correlate

import (
	"strings"
	"testing"
	"time"

	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

var skewBase = time.Date(2020, 9, 19, 2, 21, 47, 0, time.UTC)

func ntpClient(id, ip string, captureAt time.Time, offset time.Duration) model.Event {
	return model.Event{
		ID: id, SourceFileID: "cap1", ArtifactType: model.ArtifactNetworkCapture, EventType: model.EventClockObservation,
		Timestamp: captureAt,
		Extra: map[string]string{
			"source": "ntp", "role": "client", "subject_ip": ip,
			"observed_utc": captureAt.Add(offset).Format(time.RFC3339Nano), "capture_utc": captureAt.Format(time.RFC3339Nano),
		},
	}
}

func httpDate(id, ip string, captureAt time.Time, offset time.Duration) model.Event {
	e := ntpClient(id, ip, captureAt, offset)
	e.Extra["source"], e.Extra["role"] = "http_date", "server"
	return e
}

func hostWithIP(id, name, ip string) model.Event {
	return model.Event{ID: id, Host: name, EventType: model.EventRegistryKeyLastWrite,
		Extra: map[string]string{"registry_value_name": "ComputerName", "ip_origin": ip + "=static"}}
}

func TestClockSkew_AWholeHourIsReportedAsAnOffsetNotAsAnError(t *testing.T) {
	ev := []model.Event{hostWithIP("h1", "SRV-A", "10.0.0.5")}
	for i := 0; i < 4; i++ {
		ev = append(ev, ntpClient("n"+string(rune('a'+i)), "10.0.0.5", skewBase.Add(time.Duration(i)*time.Minute), -time.Hour))
	}
	reg := hostid.Build(ev)
	got := BuildClockSkew("case-1", ev, reg)
	if len(got) != 1 {
		t.Fatalf("got %d correlations", len(got))
	}
	c := got[0]
	if c.Type != model.CorrelationClockSkew || !strings.Contains(c.Title, "SRV-A") && !strings.Contains(strings.ToLower(c.Title), "srv-a") {
		t.Fatalf("title %q", c.Title)
	}
	// The interval allows up to two seconds of capture delay and a second of
	// clock resolution, so its middle is a little short of the true hour and
	// the title says how wide it is.
	if !strings.Contains(c.Title, "-59m59s") || !strings.Contains(c.Title, "±2s") {
		t.Errorf("the offset is an hour behind, give or take the allowance: %q", c.Title)
	}
	if !strings.Contains(c.Description, "behind") || !strings.Contains(c.Description, "time-zone") || !strings.Contains(c.Description, "No timestamp has been changed") {
		t.Errorf("description: %s", c.Description)
	}
}

func TestClockSkew_AClockThatAgreesWithTheCaptureIsNotReported(t *testing.T) {
	ev := []model.Event{
		ntpClient("a", "10.0.0.5", skewBase, 0),
		ntpClient("b", "10.0.0.5", skewBase.Add(time.Minute), 400*time.Millisecond),
	}
	if got := BuildClockSkew("case-1", ev, nil); len(got) != 0 {
		t.Fatalf("a clock within the measurement's own uncertainty is not a finding: %+v", got)
	}
}

func TestClockSkew_ADisagreeingSetIsReportedAsNotConstant(t *testing.T) {
	ev := []model.Event{
		ntpClient("a", "10.0.0.5", skewBase, -time.Hour),
		ntpClient("b", "10.0.0.5", skewBase.Add(time.Hour), 0),
	}
	got := BuildClockSkew("case-1", ev, nil)
	if len(got) != 1 || !strings.Contains(got[0].Title, "not constant") {
		t.Fatalf("%+v", got)
	}
}

func TestClockSkew_PublicWebServersArePooledSoABadCaptureClockIsOneFinding(t *testing.T) {
	// Three unrelated public servers all say the capture clock is an hour
	// off: the capture machine is the odd one out, once.
	var ev []model.Event
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "198.51.100.3"} {
		ev = append(ev, httpDate("h"+string(rune('a'+i)), ip, skewBase.Add(time.Duration(i)*time.Second), time.Hour))
	}
	got := BuildClockSkew("case-1", ev, nil)
	if len(got) != 1 || !strings.Contains(got[0].Title, "internet web servers") {
		t.Fatalf("expected one pooled finding: %+v", got)
	}
	if got[0].Title == "" || !strings.Contains(got[0].Title, "+1h0m2s") {
		t.Errorf("title %q", got[0].Title)
	}
}

func TestClockSkew_ALogonInsideACapturedConnectionBoundsTheHostClock(t *testing.T) {
	first := skewBase
	last := skewBase.Add(2 * time.Minute)
	sess := model.Event{
		ID: "s1", SourceFileID: "cap1", ArtifactType: model.ArtifactNetworkCapture, EventType: model.EventNetworkConnection,
		Timestamp: first, NetworkSource: "10.0.0.66", NetworkDest: "10.0.0.5", NetworkDestPort: 3389,
		Extra: map[string]string{"session": "true", "client_port": "50123", "last_seen_utc": last.Format(time.RFC3339Nano)},
	}
	// The host logged the logon an hour ahead of the capture's clock, i.e.
	// at capture-time + 1h while the connection was open.
	logon := model.Event{
		ID: "l1", Host: "SRV-A", EventType: model.EventLogonSuccess, Timestamp: skewBase.Add(time.Minute + time.Hour),
		NetworkSource: "10.0.0.66", Extra: map[string]string{"source_port": "50123"},
	}
	other := model.Event{ // same port, different client: must not pair
		ID: "l2", Host: "SRV-A", EventType: model.EventLogonSuccess, Timestamp: skewBase,
		NetworkSource: "10.0.0.99", Extra: map[string]string{"source_port": "50123"},
	}
	ev := []model.Event{hostWithIP("h1", "SRV-A", "10.0.0.5"), sess, logon, other}
	got := BuildClockSkew("case-1", ev, hostid.Build(ev))
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if !strings.Contains(got[0].Description, "logon inside a captured connection") {
		t.Errorf("method missing: %s", got[0].Description)
	}
}

func TestClockSkew_ALogonOnAnotherServerIsNotPaired(t *testing.T) {
	sess := model.Event{
		ID: "s1", SourceFileID: "cap1", ArtifactType: model.ArtifactNetworkCapture, EventType: model.EventNetworkConnection,
		Timestamp: skewBase, NetworkSource: "10.0.0.66", NetworkDest: "10.0.0.7", NetworkDestPort: 3389,
		Extra: map[string]string{"session": "true", "client_port": "50123", "last_seen_utc": skewBase.Add(time.Minute).Format(time.RFC3339Nano)},
	}
	logon := model.Event{ID: "l1", Host: "SRV-A", EventType: model.EventLogonSuccess, Timestamp: skewBase.Add(5 * time.Hour),
		NetworkSource: "10.0.0.66", Extra: map[string]string{"source_port": "50123"}}
	ev := []model.Event{hostWithIP("h1", "SRV-A", "10.0.0.5"), hostWithIP("h2", "SRV-B", "10.0.0.7"), sess, logon}
	if got := BuildClockSkew("case-1", ev, hostid.Build(ev)); len(got) != 0 {
		t.Fatalf("the connection went to SRV-B, not SRV-A: %+v", got)
	}
}

func TestClockSkew_OneWrongWebServerDoesNotHideTheCaptureClockBeingOff(t *testing.T) {
	var ev []model.Event
	for i := 0; i < 9; i++ {
		ev = append(ev, httpDate("h"+string(rune('a'+i)), "203.0.113."+string(rune('1'+i)), skewBase.Add(time.Duration(i)*time.Second), time.Hour))
	}
	ev = append(ev, httpDate("bad", "198.51.100.9", skewBase, -4000*time.Hour))
	got := BuildClockSkew("case-1", ev, nil)
	if len(got) != 1 || !strings.Contains(got[0].Title, "9 of 10 agree") || !strings.Contains(got[0].Description, "some web servers' clocks are simply wrong") {
		t.Fatalf("%+v", got)
	}
}

func TestClockSkew_ASecondOfVariationIsOneSteadyOffsetNotAChangingOne(t *testing.T) {
	ev := []model.Event{
		ntpClient("a", "10.0.0.5", skewBase, 3600*time.Second),
		ntpClient("b", "10.0.0.5", skewBase.Add(30*time.Minute), 3604*time.Second),
	}
	got := BuildClockSkew("case-1", ev, nil)
	if len(got) != 1 || strings.Contains(got[0].Title, "not constant") || !strings.Contains(got[0].Title, "is between +1h0m") {
		t.Fatalf("%+v", got)
	}
}
