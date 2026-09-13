package filezilla_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	filezillaparser "tracefall/internal/parsers/filezilla"
)

const recentServersXML = `<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.53.1" platform="windows">
	<RecentServers>
		<Server>
			<Host>192.168.1.20</Host>
			<Port>21</Port>
			<Protocol>0</Protocol>
			<Type>0</Type>
			<User>kali</User>
			<Logontype>2</Logontype>
			<PasvMode>MODE_DEFAULT</PasvMode>
			<EncodingType>Auto</EncodingType>
			<BypassProxy>0</BypassProxy>
		</Server>
	</RecentServers>
</FileZilla3>`

func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func parse(t *testing.T, name, content string) parsers.ParseResult {
	t.Helper()
	res, err := filezillaparser.New().Parse(write(t, name, content))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return res
}

func TestParser_Identity(t *testing.T) {
	p := filezillaparser.New()
	if p.Name() != "filezilla@1" {
		t.Errorf("Name = %q", p.Name())
	}
	if p.ArtifactType() != model.ArtifactFileZillaServer {
		t.Errorf("ArtifactType = %q", p.ArtifactType())
	}
}

func TestDetect_NameMatchMustBeConfirmedByContent(t *testing.T) {
	p := filezillaparser.New()

	if !p.Detect("Users/j/AppData/Roaming/FileZilla/recentservers.xml") {
		t.Error("Detect missed recentservers.xml")
	}
	if !p.Detect("FileZilla/sitemanager.xml") {
		t.Error("Detect missed sitemanager.xml")
	}
	if p.Detect("FileZilla/filezilla.xml") {
		t.Error("Detect claimed filezilla.xml, which is settings rather than connection evidence")
	}

	// The name alone must not be enough.
	if p.ConfirmContent([]byte(`<?xml version="1.0"?><nothing-to-do-with-filezilla/>`)) {
		t.Error("ConfirmContent accepted unrelated XML under the right filename")
	}
	if !p.ConfirmContent([]byte(recentServersXML)) {
		t.Error("ConfirmContent refused a genuine recentservers.xml")
	}
}

func TestDetectContent_FindsARenamedFileAndRefusesImpostors(t *testing.T) {
	p := filezillaparser.New()

	if !p.DetectContent([]byte(recentServersXML)) {
		t.Error("DetectContent missed a FileZilla connection document")
	}
	for _, in := range []string{
		`<?xml version="1.0"?><servers><Server><Host>1.2.3.4</Host></Server></servers>`,
		`<?xml version="1.0"?><FileZilla3 version="3.53.1"><Settings><Setting name="x">1</Setting></Settings></FileZilla3>`,
		`not xml at all`,
		``,
	} {
		if p.DetectContent([]byte(in)) {
			t.Errorf("DetectContent claimed a non-FileZilla document: %.60s", in)
		}
	}
}

func TestParse_ProducesOneEventPerServerWithProvenance(t *testing.T) {
	res := parse(t, "recentservers.xml", recentServersXML)

	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	if len(res.Raw) != len(res.Events) {
		t.Fatalf("got %d raw records for %d events; they must pair 1:1", len(res.Raw), len(res.Events))
	}
	ev := res.Events[0]

	if ev.EventType != model.EventFileZillaServerEntry {
		t.Errorf("EventType = %q", ev.EventType)
	}
	if ev.ArtifactType != model.ArtifactFileZillaServer {
		t.Errorf("ArtifactType = %q", ev.ArtifactType)
	}
	if ev.Parser != "filezilla@1" {
		t.Errorf("Parser = %q", ev.Parser)
	}
	if ev.FilePath != "recentservers.xml" {
		t.Errorf("FilePath = %q", ev.FilePath)
	}
	if ev.SourceReference == "" {
		t.Error("SourceReference is empty; the event cannot be traced to its record")
	}
	if res.Raw[0].SourceReference != ev.SourceReference {
		t.Errorf("raw reference %q does not match the event's %q",
			res.Raw[0].SourceReference, ev.SourceReference)
	}
	if ev.Confidence != 1.0 {
		t.Errorf("Confidence = %v", ev.Confidence)
	}
}

// The requirement, directly: no timestamp, and no substitute for one.
func TestParse_EventHasNoTimestamp(t *testing.T) {
	ev := parse(t, "recentservers.xml", recentServersXML).Events[0]

	if !ev.Timestamp.IsZero() {
		t.Errorf("Timestamp = %v; recentservers.xml records no time and none may be invented", ev.Timestamp)
	}
	if got := ev.Extra["timestamp_meaning"]; got != "no time is recorded for this event" {
		t.Errorf("timestamp_meaning = %q", got)
	}
	if !strings.Contains(ev.Extra["timestamp_basis"], "modification time") {
		t.Errorf("the basis must state that the file's mtime is not substituted: %q", ev.Extra["timestamp_basis"])
	}
}

func TestParse_IPv4IsExtractedAndLabelled(t *testing.T) {
	ev := parse(t, "recentservers.xml", recentServersXML).Events[0]

	if got := ev.Extra["server_ipv4"]; got != "192.168.1.20" {
		t.Errorf("server_ipv4 = %q, want 192.168.1.20", got)
	}
	if got := ev.Extra["server_host_kind"]; got != "ipv4" {
		t.Errorf("server_host_kind = %q", got)
	}
	if got := ev.Extra["protocol"]; got != "FTP" {
		t.Errorf("protocol = %q, want FTP", got)
	}
	if got := ev.Extra["server_port"]; got != "21" {
		t.Errorf("server_port = %q", got)
	}
	if got := ev.Extra["server_username"]; got != "kali" {
		t.Errorf("server_username = %q", got)
	}
	if ev.User != "kali" {
		t.Errorf("Event.User = %q", ev.User)
	}
	if ev.NetworkDest != "192.168.1.20" || ev.NetworkDestPort != 21 {
		t.Errorf("network fields = %q:%d", ev.NetworkDest, ev.NetworkDestPort)
	}
}

// A hostname must never be silently presented as if an address had been
// recovered, and the absence of an IPv4 must be stated.
func TestParse_HostnameEntryReportsThatNoIPv4IsPresent(t *testing.T) {
	xml := strings.Replace(recentServersXML, "192.168.1.20", "ftp.example.org", 1)
	ev := parse(t, "recentservers.xml", xml).Events[0]

	if _, ok := ev.Extra["server_ipv4"]; ok {
		t.Error("server_ipv4 was set for a hostname entry")
	}
	if got := ev.Extra["server_hostname"]; got != "ftp.example.org" {
		t.Errorf("server_hostname = %q", got)
	}
	avail := ev.Extra["ipv4_availability"]
	if !strings.Contains(avail, "no IPv4 address is present") {
		t.Errorf("ipv4_availability = %q; the absence must be stated explicitly", avail)
	}
	if !strings.Contains(avail, "DNS") {
		t.Errorf("ipv4_availability should say why no address was derived: %q", avail)
	}
}

// The security requirement at the event boundary: the password must not
// reach the event, its extras, or its raw record.
func TestParse_PasswordNeverReachesTheEvent(t *testing.T) {
	const secret = "TOPSECRETPASSWORD123"
	xml := strings.Replace(recentServersXML,
		"<Logontype>2</Logontype>",
		`<Logontype>1</Logontype><Pass encoding="base64">`+secret+`</Pass>`, 1)

	res := parse(t, "recentservers.xml", xml)
	ev := res.Events[0]

	if got := ev.Extra["password_present"]; got != "true" {
		t.Errorf("password_present = %q, want true", got)
	}
	if got := ev.Extra["password_storage"]; got != "base64" {
		t.Errorf("password_storage = %q", got)
	}
	for k, v := range ev.Extra {
		if strings.Contains(v, secret) {
			t.Errorf("the password leaked into extra[%q]", k)
		}
	}
	for _, field := range []string{ev.CommandLine, ev.FilePath, ev.User, ev.NetworkDest, ev.RegistryPath, ev.ProcessName} {
		if strings.Contains(field, secret) {
			t.Errorf("the password leaked into an event field: %q", field)
		}
	}
	if strings.Contains(res.Raw[0].Raw, secret) {
		t.Error("the password leaked into the raw evidence record")
	}
	if strings.Contains(ev.SourceReference, secret) {
		t.Error("the password leaked into the source reference")
	}
}

// The event must not be dressed up as activity it does not evidence.
func TestParse_EventIsNotPresentedAsAConnectionOrLogon(t *testing.T) {
	ev := parse(t, "recentservers.xml", recentServersXML).Events[0]

	if ev.EventType == model.EventNetworkConnection || ev.EventType == model.EventLogonSuccess ||
		ev.EventType == model.EventProcessCreate {
		t.Errorf("EventType = %q; a configuration entry is not an observed connection, logon or execution",
			ev.EventType)
	}
	meaning := ev.Extra["evidence_meaning"]
	for _, want := range []string{"ATTEMPTED", "NOT evidence that the connection succeeded", "records no time"} {
		if !strings.Contains(meaning, want) {
			t.Errorf("evidence_meaning is missing %q: %s", want, meaning)
		}
	}
}

func TestParse_SiteManagerEntryIsDescribedDifferently(t *testing.T) {
	xml := `<?xml version="1.0"?><FileZilla3 version="3.53.1"><Servers>
		<Server><Host>10.0.0.9</Host><Port>21</Port><Protocol>0</Protocol><Name>Staging</Name></Server>
	</Servers></FileZilla3>`
	ev := parse(t, "sitemanager.xml", xml).Events[0]

	if got := ev.Extra["filezilla_section"]; got != "site_manager" {
		t.Errorf("filezilla_section = %q", got)
	}
	if got := ev.Extra["site_name"]; got != "Staging" {
		t.Errorf("site_name = %q", got)
	}
	meaning := ev.Extra["evidence_meaning"]
	if !strings.Contains(meaning, "may never have been connected to") {
		t.Errorf("a saved site must be described as weaker evidence than a recent connection: %q", meaning)
	}
}

func TestParse_MultipleEntriesGetDistinctReferences(t *testing.T) {
	xml := strings.Replace(recentServersXML, "</RecentServers>",
		`<Server><Host>10.0.0.5</Host><Port>2121</Port><Protocol>0</Protocol></Server></RecentServers>`, 1)
	res := parse(t, "recentservers.xml", xml)

	if len(res.Events) != 2 {
		t.Fatalf("got %d events, want 2", len(res.Events))
	}
	if res.Events[0].SourceReference == res.Events[1].SourceReference {
		t.Error("the two entries share a source reference")
	}
}

func TestParse_EmptyListIsRawEvidenceWithNoEvent(t *testing.T) {
	xml := `<?xml version="1.0"?><FileZilla3 version="3.53.1"><RecentServers></RecentServers></FileZilla3>`
	res := parse(t, "recentservers.xml", xml)

	if len(res.Events) != 0 {
		t.Errorf("got %d events from an empty list", len(res.Events))
	}
	if len(res.Raw) != 1 {
		t.Fatalf("got %d raw records; an empty list is still evidence", len(res.Raw))
	}
}

func TestParse_NonFileZillaFileIsRefusedAsNotTheArtifact(t *testing.T) {
	_, err := filezillaparser.New().Parse(write(t, "recentservers.xml",
		`<?xml version="1.0"?><config><Server><Host>1.2.3.4</Host></Server></config>`))
	if err == nil {
		t.Fatal("Parse accepted a non-FileZilla document")
	}
	if !strings.Contains(err.Error(), "is not a FileZilla connection file") {
		t.Errorf("err = %v; it must say the file is not the artifact, not that it is corrupt", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "corrupt") {
		t.Errorf("err = %v; 'not this artifact' must not be reported as corruption", err)
	}
}

func TestParse_MalformedInputNeverPanics(t *testing.T) {
	for _, in := range []string{
		"", "<", "<FileZilla3><RecentServers><Server><Host>",
		"<FileZilla3><RecentServers><Server><Port>&bad;</Port></Server></RecentServers></FileZilla3>",
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", in, r)
				}
			}()
			_, _ = filezillaparser.New().Parse(write(t, "recentservers.xml", in))
		}()
	}
}

func TestParse_IsDeterministic(t *testing.T) {
	path := write(t, "recentservers.xml", recentServersXML)
	first, err := filezillaparser.New().Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := filezillaparser.New().Parse(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Events) != len(first.Events) || got.Raw[0].Raw != first.Raw[0].Raw {
			t.Fatalf("run %d differs", i)
		}
		for k, v := range first.Events[0].Extra {
			if got.Events[0].Extra[k] != v {
				t.Fatalf("run %d: extra[%q] = %q, want %q", i, k, got.Events[0].Extra[k], v)
			}
		}
	}
}
