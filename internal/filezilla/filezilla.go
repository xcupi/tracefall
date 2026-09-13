// Package filezilla decodes FileZilla's XML connection records --
// recentservers.xml and the Site Manager's sitemanager.xml.
//
// # What this artifact asserts
//
// That the FileZilla client HELD a server entry. recentservers.xml is
// written when a connection is initiated from the Quickconnect bar, so an
// entry is evidence that a connection to that host was ATTEMPTED from
// this user's profile. It is not evidence that the connection succeeded,
// that a transfer happened, or that anyone authenticated. sitemanager.xml
// is weaker still: a site can be typed in and saved without ever being
// used.
//
// Neither file records a time. There is no per-entry timestamp anywhere
// in the format, so this package returns none and the parser invents
// none -- see the Server type.
//
// # Credentials
//
// These files can carry stored passwords. This package NEVER returns a
// password value. It reports only that one is present and how it was
// stored, because "an FTP password is saved in this profile" is the
// forensically useful fact and the secret itself is not needed to state
// it. There is no option, flag or debug path that changes this: the
// value is not carried out of the decoder at all, so nothing downstream
// can leak what it never received.
package filezilla

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"tracefall/internal/xmlutil"
)

// Limits bound what a single document may cost to decode. A FileZilla
// XML file is tiny in practice; these exist so a malformed or hostile one
// cannot be.
type Limits struct {
	MaxBytes    int // maximum document size accepted
	MaxServers  int // maximum server entries decoded from one document
	MaxWarnings int // maximum warnings retained
}

// DefaultLimits are generous next to any real FileZilla profile: the
// largest Site Manager files seen in the wild hold a few hundred sites in
// a few hundred kilobytes.
func DefaultLimits() Limits {
	return Limits{MaxBytes: 8 << 20, MaxServers: 4096, MaxWarnings: 64}
}

// Section names which of FileZilla's two connection files an entry came
// from. They are different claims and are never merged.
const (
	SectionRecentServers = "recent_servers" // <RecentServers>: hosts connected to via Quickconnect
	SectionSiteManager   = "site_manager"   // <Servers>: sites saved in the Site Manager
)

// HostKind classifies what the <Host> element actually contains. It is
// decided by parsing the literal, never by resolving it: this package
// performs no DNS and no network I/O of any kind.
const (
	HostIPv4      = "ipv4"
	HostIPv6      = "ipv6"
	HostName      = "hostname"
	HostAbsent    = "absent"
	HostMalformed = "malformed"
)

// Server is one decoded <Server> element.
//
// There is deliberately no timestamp field. Neither recentservers.xml nor
// sitemanager.xml records when an entry was created, connected to, or
// last used, and the file's own mtime describes the file, not the entry.
type Server struct {
	Section string // SectionRecentServers or SectionSiteManager
	Index   int    // 0-based position within its section, as stored

	Host     string // the <Host> literal, exactly as stored
	HostKind string // HostIPv4 | HostIPv6 | HostName | HostAbsent | HostMalformed
	Port     int    // <Port>; 0 when absent or unreadable
	PortRaw  string // the <Port> literal, kept when it did not parse

	ProtocolCode int    // <Protocol>, FileZilla's ServerProtocol enum value
	ProtocolRaw  string // the <Protocol> literal as stored
	Protocol     string // decoded name, or "" when the code is not one this package documents

	ServerTypeCode int    // <Type>, FileZilla's ServerType enum value
	ServerTypeRaw  string // the <Type> literal as stored

	LogonTypeCode int    // <Logontype>, FileZilla's LogonType enum value
	LogonTypeRaw  string // the <Logontype> literal as stored
	LogonType     string // decoded name, or "" when not documented here

	User    string // <User>
	Account string // <Account>, the separate FTP account name (not a password)
	Name    string // <Name>, the Site Manager label for this entry
	Comment string // <Comments>

	RemoteDir string // <RemoteDir>, the server-side path in FileZilla's encoded form
	LocalDir  string // <LocalDir>, the local path this site syncs against

	PasvMode     string // <PasvMode>
	EncodingType string // <EncodingType>
	BypassProxy  string // <BypassProxy>

	// PasswordPresent reports that a <Pass> element existed. The value is
	// never read into this struct. PasswordStorage carries only the
	// element's encoding= attribute (e.g. "base64"), which describes how
	// the secret was stored without disclosing it.
	PasswordPresent bool
	PasswordStorage string

	// Unknown holds child elements this package does not model, so an
	// element added by a future FileZilla release is preserved rather
	// than silently dropped. Values are kept verbatim EXCEPT for any
	// element whose name marks it as secret, which is redacted here on
	// the same terms as <Pass>.
	Unknown map[string]string
}

// IPv4 returns the host as an IPv4 address, and whether it is one.
func (s Server) IPv4() (netip.Addr, bool) {
	if s.HostKind != HostIPv4 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s.Host)
	return a, err == nil
}

// File is one decoded FileZilla XML document.
type File struct {
	Product  string // the root element name, always "FileZilla3" for a file this package accepts
	Version  string // the root element's version= attribute
	Platform string // the root element's platform= attribute

	Servers  []Server
	Warnings []string

	// Truncated reports that the document ended mid-structure. The
	// servers decoded before that point are still returned: a truncated
	// artifact is partial evidence, not no evidence.
	Truncated bool
}

// FileZilla's ServerProtocol enum, as used by the <Protocol> element.
//
// Only the values that have been stable across FileZilla 3.x are named.
// Anything else is reported by its number with no name attached, because
// inventing a protocol label for an unrecognized code would put a claim
// about how traffic was carried into the evidence that the file does not
// support.
var protocolNames = map[int]string{
	0: "FTP",
	1: "SFTP",
	2: "HTTP",
	3: "FTPS (implicit TLS)",
	4: "HTTPS",
	5: "FTPES (explicit TLS over FTP)",
	6: "FTP (insecure, plain)",
}

// FileZilla's LogonType enum, as used by the <Logontype> element. This is
// how the client was configured to obtain credentials -- not whether
// authentication succeeded.
var logonTypeNames = map[int]string{
	0: "anonymous",
	1: "normal (username and password stored)",
	2: "ask for password (no password stored)",
	3: "interactive",
	4: "account",
}

// ProtocolName returns the documented name for a ServerProtocol code, or
// "" when this package does not document it.
func ProtocolName(code int) string { return protocolNames[code] }

// LogonTypeName returns the documented name for a LogonType code, or ""
// when this package does not document it.
func LogonTypeName(code int) string { return logonTypeNames[code] }

// secretElements are child element names whose CONTENT is credential
// material. Their values are never carried out of this package.
//
// "Pass" is FileZilla's stored password. "Key" and "Keyfile" name a
// private key FileZilla authenticates with. Each is matched
// case-insensitively so a variant spelling cannot slip a secret through
// into Unknown.
var secretElements = map[string]bool{
	"pass":    true,
	"key":     true,
	"keyfile": true,
}

// ErrNotFileZilla reports that the document is well-formed XML but is not
// a FileZilla connection file. It is deliberately distinct from a parse
// error: "this is not the artifact" and "this artifact is broken" are
// different findings and must not be reported as each other.
var ErrNotFileZilla = errors.New("filezilla: not a FileZilla connection document")

// Sniff reports whether header -- the first bytes of a file -- carries
// enough structure to identify a FileZilla connection document.
//
// Identity requires BOTH the FileZilla3 root element and one of the two
// connection containers. The root element alone is not enough: FileZilla
// writes its settings, layout and trusted-certificate stores under the
// same root, and none of those is connection evidence. Requiring the
// container is what keeps filezilla.xml out of this parser.
func Sniff(header []byte) bool {
	text := string(xmlutil.DecodeUTF16(header))
	if !hasElement(text, "FileZilla3") {
		return false
	}
	return hasElement(text, "RecentServers") || hasElement(text, "Servers")
}

// hasElement reports whether text opens an element with the given LOCAL
// name, with or without a namespace prefix.
//
// The prefix has to be tolerated here because the body parser tolerates
// it: it compares xml.Name.Local and ignores prefixes entirely. A Sniff
// that matched only the literal unprefixed tag would refuse documents
// that Parse reads perfectly -- detection and decoding disagreeing about
// what the artifact is.
func hasElement(text, name string) bool {
	for i := 0; ; {
		j := strings.Index(text[i:], "<")
		if j < 0 {
			return false
		}
		i += j + 1
		rest := text[i:]
		// Skip an optional prefix. A prefix is a name followed by ":",
		// and may not contain whitespace or ">".
		if c := strings.IndexAny(rest, ":> \t\r\n/"); c >= 0 && c < len(rest) && rest[c] == ':' {
			rest = rest[c+1:]
		}
		if !strings.HasPrefix(rest, name) {
			continue
		}
		// The name must END here: "<Servers" must not match "<ServersX",
		// and "<Server" must not match "<Servers".
		after := rest[len(name):]
		if after == "" {
			return true
		}
		switch after[0] {
		case ' ', '\t', '\r', '\n', '>', '/':
			return true
		}
	}
}

// rootAttrs is only ever used to read the root element's attributes; the
// body is walked token by token so a truncated document still yields the
// entries that preceded the truncation.
type serverXML struct {
	Children []struct {
		XMLName xml.Name
		Attrs   []xml.Attr `xml:",any,attr"`
		Value   string     `xml:",chardata"`
	} `xml:",any"`
}

// Parse decodes one FileZilla connection document.
//
// A document that is not FileZilla connection evidence returns
// ErrNotFileZilla. A document that IS one but ends mid-structure returns
// what was decoded, with Truncated set and a warning recorded -- never an
// error, and never a fabricated entry to fill the gap.
func Parse(data []byte, lim Limits) (File, error) {
	if lim.MaxBytes > 0 && len(data) > lim.MaxBytes {
		return File{}, fmt.Errorf("filezilla: document is %d bytes, over the %d-byte limit", len(data), lim.MaxBytes)
	}
	if !Sniff(data) {
		return File{}, ErrNotFileZilla
	}

	var f File
	dec := xmlutil.NewDecoder(data)

	section := ""
	depth := 0
	sawRoot := false

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Truncated or malformed. Everything decoded up to this
			// point stands; the failure is recorded, not hidden, and
			// not turned into a missing entry.
			f.Truncated = true
			f.warn(lim, "document ended or failed at byte offset "+
				strconv.FormatInt(dec.InputOffset(), 10)+": "+err.Error()+
				" -- entries decoded before this point are reported; any after it are not present")
			break
		}

		start, ok := tok.(xml.StartElement)
		if !ok {
			if end, ok := tok.(xml.EndElement); ok {
				depth--
				if section != "" && (end.Name.Local == "RecentServers" || end.Name.Local == "Servers") {
					section = ""
				}
			}
			continue
		}
		depth++

		// Namespaces: the local name is compared, never the prefix, so a
		// document that declares one is read the same as one that does
		// not. FileZilla writes none, but a file that has passed through
		// another tool may.
		switch {
		case depth == 1:
			sawRoot = true
			f.Product = start.Name.Local
			for _, a := range start.Attr {
				switch a.Name.Local {
				case "version":
					f.Version = a.Value
				case "platform":
					f.Platform = a.Value
				}
			}
		case start.Name.Local == "RecentServers":
			section = SectionRecentServers
		case start.Name.Local == "Servers":
			section = SectionSiteManager
		case start.Name.Local == "Server" && section != "":
			if lim.MaxServers > 0 && len(f.Servers) >= lim.MaxServers {
				f.warn(lim, "stopped after "+strconv.Itoa(lim.MaxServers)+
					" server entries: the document declares more than this build decodes")
				// Consume the rest so the decoder still reports a
				// truncation cleanly if one follows.
				if err := dec.Skip(); err != nil {
					f.Truncated = true
				}
				depth--
				continue
			}
			var sx serverXML
			if err := dec.DecodeElement(&sx, &start); err != nil {
				f.Truncated = true
				f.warn(lim, "a <Server> entry at byte offset "+
					strconv.FormatInt(dec.InputOffset(), 10)+" could not be decoded: "+err.Error())
				break
			}
			depth--
			f.Servers = append(f.Servers, buildServer(sx, section, sectionCount(f.Servers, section), &f, lim))
		}
	}

	if !sawRoot || f.Product != "FileZilla3" {
		return File{}, ErrNotFileZilla
	}
	// A FileZilla3 document with a connection container but no decodable
	// <Server> is a real, empty artifact -- the user cleared their recent
	// servers, or never used Quickconnect. That is a fact about the
	// evidence and is reported as an empty result, not as an error.
	return f, nil
}

func sectionCount(servers []Server, section string) int {
	n := 0
	for _, s := range servers {
		if s.Section == section {
			n++
		}
	}
	return n
}

func (f *File) warn(lim Limits, msg string) {
	if lim.MaxWarnings > 0 && len(f.Warnings) >= lim.MaxWarnings {
		return
	}
	f.Warnings = append(f.Warnings, msg)
}

func buildServer(sx serverXML, section string, index int, f *File, lim Limits) Server {
	s := Server{Section: section, Index: index}

	for _, c := range sx.Children {
		name := c.XMLName.Local
		value := strings.TrimSpace(c.Value)

		if secretElements[strings.ToLower(name)] {
			// The value is not read, not stored, and not logged. Only
			// its presence and its declared storage form travel on.
			s.PasswordPresent = true
			for _, a := range c.Attrs {
				if strings.EqualFold(a.Name.Local, "encoding") {
					s.PasswordStorage = a.Value
				}
			}
			continue
		}

		switch name {
		case "Host":
			s.Host = value
		case "Port":
			s.PortRaw = value
			if n, err := strconv.Atoi(value); err == nil {
				s.Port = n
			} else if value != "" {
				f.warn(lim, "server entry "+strconv.Itoa(index)+" has a <Port> that is not a number: "+
					strconv.Quote(value)+" -- kept as stored, not converted")
			}
		case "Protocol":
			s.ProtocolRaw = value
			if n, err := strconv.Atoi(value); err == nil {
				s.ProtocolCode = n
				s.Protocol = protocolNames[n]
			}
		case "Type":
			s.ServerTypeRaw = value
			if n, err := strconv.Atoi(value); err == nil {
				s.ServerTypeCode = n
			}
		case "Logontype":
			s.LogonTypeRaw = value
			if n, err := strconv.Atoi(value); err == nil {
				s.LogonTypeCode = n
				s.LogonType = logonTypeNames[n]
			}
		case "User":
			s.User = value
		case "Account":
			s.Account = value
		case "Name":
			s.Name = value
		case "Comments":
			s.Comment = value
		case "RemoteDir":
			s.RemoteDir = value
		case "LocalDir":
			s.LocalDir = value
		case "PasvMode":
			s.PasvMode = value
		case "EncodingType":
			s.EncodingType = value
		case "BypassProxy":
			s.BypassProxy = value
		default:
			if value == "" {
				continue
			}
			if s.Unknown == nil {
				s.Unknown = map[string]string{}
			}
			s.Unknown[name] = value
		}
	}

	s.HostKind = classifyHost(s.Host)
	return s
}

// classifyHost decides what the <Host> literal is by parsing it. No name
// is resolved and no address is inferred from surrounding text: a
// hostname stays a hostname, and the absence of an IPv4 address is
// reported as such rather than filled in.
func classifyHost(host string) string {
	if host == "" {
		return HostAbsent
	}
	// A bracketed literal is how an IPv6 address is written where a port
	// may follow; FileZilla stores the bare form, but accept both.
	trimmed := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		if addr.Is4() || addr.Is4In6() {
			return HostIPv4
		}
		return HostIPv6
	}
	if isPlausibleHostname(host) {
		return HostName
	}
	return HostMalformed
}

// isPlausibleHostname checks the shape of a DNS name without asserting
// that it exists. Anything that fails is reported as malformed rather
// than quietly accepted as a host.
func isPlausibleHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return false
			}
		}
	}
	return true
}
