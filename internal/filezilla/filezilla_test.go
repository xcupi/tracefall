package filezilla_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	"tracefall/internal/filezilla"
)

// doc wraps server entries in the FileZilla3/RecentServers envelope.
func doc(inner string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.53.1" platform="windows">
	<RecentServers>` + inner + `</RecentServers>
</FileZilla3>`)
}

const ipv4Entry = `
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
		</Server>`

func parse(t *testing.T, data []byte) filezilla.File {
	t.Helper()
	f, err := filezilla.Parse(data, filezilla.DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f
}

func TestParse_IPv4ServerEntry(t *testing.T) {
	f := parse(t, doc(ipv4Entry))

	if f.Product != "FileZilla3" || f.Version != "3.53.1" || f.Platform != "windows" {
		t.Errorf("root attributes: product=%q version=%q platform=%q", f.Product, f.Version, f.Platform)
	}
	if len(f.Servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(f.Servers))
	}
	s := f.Servers[0]

	if s.Host != "192.168.1.20" {
		t.Errorf("Host = %q, want 192.168.1.20", s.Host)
	}
	if s.HostKind != filezilla.HostIPv4 {
		t.Errorf("HostKind = %q, want %q", s.HostKind, filezilla.HostIPv4)
	}
	if addr, ok := s.IPv4(); !ok || addr.String() != "192.168.1.20" {
		t.Errorf("IPv4() = %v, %v", addr, ok)
	}
	if s.Port != 21 {
		t.Errorf("Port = %d, want 21", s.Port)
	}
	if s.ProtocolCode != 0 || s.Protocol != "FTP" {
		t.Errorf("protocol = %d/%q, want 0/FTP", s.ProtocolCode, s.Protocol)
	}
	if s.User != "kali" {
		t.Errorf("User = %q, want kali", s.User)
	}
	if s.Section != filezilla.SectionRecentServers {
		t.Errorf("Section = %q", s.Section)
	}
	// Logontype 2 is "ask for password", which is exactly why no <Pass>
	// element exists in this entry.
	if s.LogonTypeCode != 2 || !strings.Contains(s.LogonType, "no password stored") {
		t.Errorf("logon type = %d/%q", s.LogonTypeCode, s.LogonType)
	}
	if s.PasswordPresent {
		t.Error("PasswordPresent is true for an entry with no <Pass> element")
	}
}

func TestParse_MultipleEntriesKeepTheirOrderAndIndex(t *testing.T) {
	f := parse(t, doc(ipv4Entry+`
		<Server><Host>ftp.example.org</Host><Port>2121</Port><Protocol>0</Protocol><User>bob</User></Server>
		<Server><Host>10.0.0.5</Host><Port>22</Port><Protocol>1</Protocol><User>svc</User></Server>`))

	if len(f.Servers) != 3 {
		t.Fatalf("got %d servers, want 3", len(f.Servers))
	}
	wantHosts := []string{"192.168.1.20", "ftp.example.org", "10.0.0.5"}
	for i, want := range wantHosts {
		if f.Servers[i].Host != want {
			t.Errorf("server %d host = %q, want %q", i, f.Servers[i].Host, want)
		}
		if f.Servers[i].Index != i {
			t.Errorf("server %d Index = %d", i, f.Servers[i].Index)
		}
	}
	if f.Servers[2].Protocol != "SFTP" {
		t.Errorf("protocol 1 = %q, want SFTP", f.Servers[2].Protocol)
	}
}

// A duplicate entry is kept as a duplicate. Collapsing it would erase
// the fact that the file recorded the host twice.
func TestParse_DuplicateEntriesAreBothKept(t *testing.T) {
	f := parse(t, doc(ipv4Entry+ipv4Entry))
	if len(f.Servers) != 2 {
		t.Fatalf("got %d servers, want 2 -- duplicates must not be collapsed", len(f.Servers))
	}
	if f.Servers[0].Host != f.Servers[1].Host {
		t.Error("the two entries should be identical apart from their index")
	}
}

func TestParse_HostnameIsNotTurnedIntoAnAddress(t *testing.T) {
	f := parse(t, doc(`<Server><Host>ftp.example.org</Host><Port>21</Port><Protocol>0</Protocol></Server>`))
	s := f.Servers[0]

	if s.HostKind != filezilla.HostName {
		t.Errorf("HostKind = %q, want %q", s.HostKind, filezilla.HostName)
	}
	if _, ok := s.IPv4(); ok {
		t.Error("a hostname must never yield an IPv4 address -- that would require DNS")
	}
	if s.Host != "ftp.example.org" {
		t.Errorf("Host = %q; the literal must be preserved exactly", s.Host)
	}
}

func TestParse_IPv6HostIsNotReportedAsIPv4(t *testing.T) {
	f := parse(t, doc(`<Server><Host>2001:db8::1</Host><Port>21</Port><Protocol>0</Protocol></Server>`))
	if got := f.Servers[0].HostKind; got != filezilla.HostIPv6 {
		t.Errorf("HostKind = %q, want %q", got, filezilla.HostIPv6)
	}
	if _, ok := f.Servers[0].IPv4(); ok {
		t.Error("IPv4() returned true for an IPv6 host")
	}
}

func TestParse_NonStandardPort(t *testing.T) {
	f := parse(t, doc(`<Server><Host>192.168.1.20</Host><Port>2121</Port><Protocol>0</Protocol></Server>`))
	if f.Servers[0].Port != 2121 {
		t.Errorf("Port = %d, want 2121", f.Servers[0].Port)
	}
}

func TestParse_UnparsablePortIsKeptNotZeroed(t *testing.T) {
	f := parse(t, doc(`<Server><Host>192.168.1.20</Host><Port>twenty-one</Port><Protocol>0</Protocol></Server>`))
	s := f.Servers[0]
	if s.Port != 0 {
		t.Errorf("Port = %d, want 0 for an unparsable literal", s.Port)
	}
	if s.PortRaw != "twenty-one" {
		t.Errorf("PortRaw = %q; the literal must be preserved", s.PortRaw)
	}
	if len(f.Warnings) == 0 {
		t.Error("an unparsable port must produce a warning")
	}
}

// The whole security requirement, in one test: a stored password must
// never appear anywhere in the decoded output.
func TestParse_PasswordIsNeverExtracted(t *testing.T) {
	const secret = "hunter2-SUPER-SECRET"
	f := parse(t, doc(`
		<Server>
			<Host>192.168.1.20</Host><Port>21</Port><Protocol>0</Protocol>
			<User>kali</User><Logontype>1</Logontype>
			<Pass encoding="base64">`+secret+`</Pass>
		</Server>`))

	s := f.Servers[0]
	if !s.PasswordPresent {
		t.Error("PasswordPresent = false; the entry has a <Pass> element")
	}
	if s.PasswordStorage != "base64" {
		t.Errorf("PasswordStorage = %q, want base64", s.PasswordStorage)
	}
	for k, v := range s.Unknown {
		if strings.Contains(v, secret) {
			t.Errorf("the password leaked into Unknown[%q]", k)
		}
	}
	// Exhaustive: the secret must not appear in ANY string field.
	for _, v := range []string{
		s.Host, s.User, s.Account, s.Name, s.Comment, s.RemoteDir, s.LocalDir,
		s.PasvMode, s.EncodingType, s.BypassProxy, s.PasswordStorage,
		s.PortRaw, s.ProtocolRaw, s.ServerTypeRaw, s.LogonTypeRaw, s.Protocol, s.LogonType,
	} {
		if strings.Contains(v, secret) {
			t.Errorf("the password leaked into a decoded field: %q", v)
		}
	}
	for _, w := range f.Warnings {
		if strings.Contains(w, secret) {
			t.Errorf("the password leaked into a warning: %q", w)
		}
	}
}

// A private key is credential material too, and is redacted on the same
// terms rather than falling through into Unknown.
func TestParse_KeyfileIsRedactedLikeAPassword(t *testing.T) {
	const key = "-----BEGIN OPENSSH PRIVATE KEY-----AAAA"
	f := parse(t, doc(`
		<Server><Host>10.0.0.5</Host><Protocol>1</Protocol>
		<Keyfile>`+key+`</Keyfile></Server>`))
	s := f.Servers[0]
	if !s.PasswordPresent {
		t.Error("a <Keyfile> element must be reported as credential material present")
	}
	for k, v := range s.Unknown {
		if strings.Contains(v, "PRIVATE KEY") {
			t.Errorf("key material leaked into Unknown[%q]", k)
		}
	}
}

func TestParse_UnexpectedElementsArePreservedNotDropped(t *testing.T) {
	f := parse(t, doc(`
		<Server><Host>192.168.1.20</Host><Protocol>0</Protocol>
		<SomeFutureField>value-42</SomeFutureField></Server>`))
	if got := f.Servers[0].Unknown["SomeFutureField"]; got != "value-42" {
		t.Errorf("Unknown[SomeFutureField] = %q, want value-42", got)
	}
}

func TestParse_XMLEntitiesAreDecoded(t *testing.T) {
	f := parse(t, doc(`<Server><Host>192.168.1.20</Host><Protocol>0</Protocol>
		<User>dom&amp;user</User><Name>Site &lt;1&gt;</Name></Server>`))
	if got := f.Servers[0].User; got != "dom&user" {
		t.Errorf("User = %q, want dom&user", got)
	}
	if got := f.Servers[0].Name; got != "Site <1>" {
		t.Errorf("Name = %q, want Site <1>", got)
	}
}

func TestParse_UTF16LEDocumentIsDecoded(t *testing.T) {
	utf8Doc := string(doc(ipv4Entry))
	units := utf16.Encode([]rune(utf8Doc))
	le := []byte{0xFF, 0xFE}
	for _, u := range units {
		le = append(le, byte(u), byte(u>>8))
	}

	f := parse(t, le)
	if len(f.Servers) != 1 || f.Servers[0].Host != "192.168.1.20" {
		t.Fatalf("UTF-16LE document decoded to %d servers: %+v", len(f.Servers), f.Servers)
	}
}

func TestParse_NamespacedDocumentIsRead(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<fz:FileZilla3 xmlns:fz="urn:filezilla" version="3.53.1">
	<fz:RecentServers>
		<fz:Server><fz:Host>192.168.1.20</fz:Host><fz:Port>21</fz:Port><fz:Protocol>0</fz:Protocol></fz:Server>
	</fz:RecentServers>
</fz:FileZilla3>`)
	f := parse(t, data)
	if len(f.Servers) != 1 || f.Servers[0].Host != "192.168.1.20" {
		t.Fatalf("namespaced document decoded to %d servers", len(f.Servers))
	}
}

func TestParse_SiteManagerSectionIsDistinctFromRecentServers(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<FileZilla3 version="3.53.1">
	<Servers>
		<Server><Host>10.0.0.9</Host><Port>21</Port><Protocol>0</Protocol><Name>Staging</Name></Server>
	</Servers>
</FileZilla3>`)
	f := parse(t, data)
	if len(f.Servers) != 1 {
		t.Fatalf("got %d servers", len(f.Servers))
	}
	if f.Servers[0].Section != filezilla.SectionSiteManager {
		t.Errorf("Section = %q, want %q", f.Servers[0].Section, filezilla.SectionSiteManager)
	}
}

// Truncation is partial evidence, not no evidence: the entries that
// preceded the damage are reported, and the damage is recorded.
func TestParse_TruncatedDocumentKeepsWhatWasDecoded(t *testing.T) {
	full := string(doc(ipv4Entry + `
		<Server><Host>10.0.0.5</Host><Port>21</Port><Protocol>0</Protocol></Server>`))
	cut := full[:strings.Index(full, "<Host>10.0.0.5")+10]

	f, err := filezilla.Parse([]byte(cut), filezilla.DefaultLimits())
	if err != nil {
		t.Fatalf("a truncated FileZilla document must not be an error: %v", err)
	}
	if !f.Truncated {
		t.Error("Truncated = false for a document cut mid-element")
	}
	if len(f.Servers) != 1 || f.Servers[0].Host != "192.168.1.20" {
		t.Fatalf("the complete entry before the truncation was lost: %+v", f.Servers)
	}
	if len(f.Warnings) == 0 {
		t.Error("a truncation must be recorded in Warnings")
	}
}

func TestParse_MalformedXMLNeverPanics(t *testing.T) {
	inputs := []string{
		"",
		"<",
		"<FileZilla3",
		"<FileZilla3><RecentServers>",
		"<FileZilla3><RecentServers><Server><Host>",
		"<FileZilla3><RecentServers><Server><Host>1.2.3.4</Host></Server></RecentServers>",
		"<FileZilla3 version=\"3\"><RecentServers><Server/></RecentServers></FileZilla3>",
		"<FileZilla3><RecentServers><Server><Port>&broken;</Port></Server></RecentServers></FileZilla3>",
		string([]byte{0xFF, 0xFE, 0x3C, 0x00}),
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on input %q: %v", in, r)
				}
			}()
			_, _ = filezilla.Parse([]byte(in), filezilla.DefaultLimits())
		}()
	}
}

func TestParse_NonFileZillaXMLIsRefusedAsNotTheArtifact(t *testing.T) {
	inputs := [][]byte{
		[]byte(`<?xml version="1.0"?><configuration><Server><Host>1.2.3.4</Host></Server></configuration>`),
		[]byte(`<?xml version="1.0"?><FileZilla3 version="3.53.1"><Settings><Setting name="x">1</Setting></Settings></FileZilla3>`),
		[]byte(`{"not":"xml"}`),
	}
	for i, in := range inputs {
		_, err := filezilla.Parse(in, filezilla.DefaultLimits())
		if !errors.Is(err, filezilla.ErrNotFileZilla) {
			t.Errorf("input %d: err = %v, want ErrNotFileZilla", i, err)
		}
	}
}

// filezilla.xml sits in the same directory as recentservers.xml and
// shares its root element. It is settings, not connection evidence, and
// must not be claimed.
func TestSniff_SettingsFileIsNotClaimed(t *testing.T) {
	settings := []byte(`<?xml version="1.0"?>
<FileZilla3 version="3.53.1" platform="windows">
	<Settings>
		<Setting name="Use Pasv mode">1</Setting>
	</Settings>`)
	if filezilla.Sniff(settings) {
		t.Error("Sniff claimed filezilla.xml, which holds settings and no connection entries")
	}
}

func TestSniff(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"recentservers", doc(ipv4Entry), true},
		{"site manager", []byte(`<FileZilla3 version="3"><Servers><Server/></Servers></FileZilla3>`), true},
		{"empty", nil, false},
		{"short", []byte("<Fi"), false},
		{"unrelated xml", []byte(`<?xml version="1.0"?><servers><Server><Host>1.2.3.4</Host></Server></servers>`), false},
		{"root only", []byte(`<FileZilla3 version="3"><Settings/></FileZilla3>`), false},
	}
	for _, tt := range tests {
		if got := filezilla.Sniff(tt.in); got != tt.want {
			t.Errorf("%s: Sniff = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestParse_EmptyRecentServersIsEvidenceNotAnError(t *testing.T) {
	f, err := filezilla.Parse(doc(""), filezilla.DefaultLimits())
	if err != nil {
		t.Fatalf("an empty RecentServers list must not be an error: %v", err)
	}
	if len(f.Servers) != 0 {
		t.Errorf("got %d servers, want 0", len(f.Servers))
	}
	if f.Product != "FileZilla3" {
		t.Errorf("Product = %q; the document was still identified", f.Product)
	}
}

func TestParse_ServerLimitIsEnforced(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString(`<Server><Host>1.2.3.4</Host><Protocol>0</Protocol></Server>`)
	}
	lim := filezilla.DefaultLimits()
	lim.MaxServers = 10
	f, err := filezilla.Parse(doc(b.String()), lim)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(f.Servers) != 10 {
		t.Errorf("got %d servers, want the limit of 10", len(f.Servers))
	}
	if len(f.Warnings) == 0 {
		t.Error("hitting the limit must be recorded, not silent")
	}
}

func TestParse_IsDeterministic(t *testing.T) {
	data := doc(ipv4Entry + `<Server><Host>a.example</Host><Protocol>0</Protocol><Zed>1</Zed><Alpha>2</Alpha></Server>`)
	// Compared as JSON so map-valued fields (Unknown) are compared by
	// content, and so a field added later is covered without this test
	// being updated.
	first, err := json.Marshal(parse(t, data))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := json.Marshal(parse(t, data))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(first) {
			t.Fatalf("run %d differs from the first:\n got %s\nwant %s", i, got, first)
		}
	}
}

func TestProtocolAndLogonTypeNames(t *testing.T) {
	if filezilla.ProtocolName(0) != "FTP" {
		t.Errorf("ProtocolName(0) = %q", filezilla.ProtocolName(0))
	}
	// An undocumented code must yield no name at all rather than a
	// plausible-looking guess.
	if got := filezilla.ProtocolName(9999); got != "" {
		t.Errorf("ProtocolName(9999) = %q, want an empty string", got)
	}
	if got := filezilla.LogonTypeName(0); got != "anonymous" {
		t.Errorf("LogonTypeName(0) = %q", got)
	}
	if got := filezilla.LogonTypeName(77); got != "" {
		t.Errorf("LogonTypeName(77) = %q, want an empty string", got)
	}
}
