// Package filezilla turns FileZilla's XML connection files into
// normalized evidence.
//
// # What these events assert
//
// That the FileZilla client on this machine HELD a server entry naming a
// host, port, protocol and username. recentservers.xml is written when a
// connection is started from the Quickconnect bar, so an entry there is
// evidence a connection was ATTEMPTED from this user's profile.
// sitemanager.xml is weaker: a site can be saved and never used.
//
// Neither is evidence that a connection succeeded, that anyone
// authenticated, or that a byte was transferred. Every event says so.
//
// # No timestamp
//
// Neither file records a per-entry time, so the events carry none. The
// file's modification time is when the FILE was last written -- it dates
// the most recent change to the list, not any individual entry, and
// substituting it would put a fabricated instant on the timeline.
//
// # Credentials
//
// A stored password is never extracted, never stored and never logged.
// internal/filezilla does not carry the value out of the decoder at all,
// so this parser has nothing to leak: it reports only that a password was
// present and how it was stored.
package filezilla

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"tracefall/internal/filezilla"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const parserName = "filezilla@1"

// Parser implements parsers.ArtifactParser, parsers.ContentDetector and
// parsers.ContentConfirmer.
type Parser struct {
	limits filezilla.Limits
}

func New() *Parser { return &Parser{limits: filezilla.DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactFileZillaServer }

// connectionFiles are FileZilla's two connection stores, by name. A name
// match is only ever a hint here -- ConfirmContent must agree before the
// file is claimed.
var connectionFiles = map[string]bool{
	"recentservers.xml": true,
	"sitemanager.xml":   true,
}

// Detect matches FileZilla's two connection filenames. On its own this
// proves nothing: any XML file can be called recentservers.xml, so
// ConfirmContent below re-checks the bytes before the file is claimed.
func (Parser) Detect(relPath string) bool {
	return connectionFiles[strings.ToLower(filepath.Base(relPath))]
}

// ConfirmContent requires the name match to be backed by the document's
// own structure, so a file merely NAMED recentservers.xml is returned to
// content detection rather than claimed and then failed at import.
func (Parser) ConfirmContent(header []byte) bool { return filezilla.Sniff(header) }

// DetectContent finds a FileZilla connection file under any name, which
// is how one carried out of a triage image and renamed is still found.
//
// Identity needs the FileZilla3 root AND a connection container.
// FileZilla writes its settings, layout and certificate stores under the
// same root element, and none of those is connection evidence -- so
// filezilla.xml, which sits in the same directory, is deliberately not
// claimed by this parser.
func (Parser) DetectContent(header []byte) bool { return filezilla.Sniff(header) }

func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}

	f, err := filezilla.Parse(data, p.limits)
	if err != nil {
		if errors.Is(err, filezilla.ErrNotFileZilla) {
			// Stated as what it is. "This file is not the artifact" must
			// never be reported as "this artifact is corrupt".
			return parsers.ParseResult{}, fmt.Errorf(
				"filezilla: %s is not a FileZilla connection file (no FileZilla3 root with a "+
					"RecentServers or Servers container)", filepath.Base(absPath))
		}
		return parsers.ParseResult{}, fmt.Errorf("filezilla: %w", err)
	}

	sourceName := filepath.Base(absPath)
	var out parsers.ParseResult

	for _, s := range f.Servers {
		ev, raw := serverEvent(s, f, sourceName)
		out.Events = append(out.Events, ev)
		out.Raw = append(out.Raw, raw)
	}

	if len(out.Events) == 0 {
		// A FileZilla connection file with no entries is a real finding
		// about the evidence -- the list was cleared, or Quickconnect was
		// never used. It is recorded as structured evidence with no
		// event, rather than as a parse failure.
		raw, _ := json.Marshal(map[string]any{
			"source_file":      sourceName,
			"product":          f.Product,
			"client_version":   f.Version,
			"platform":         f.Platform,
			"server_entries":   0,
			"truncated":        f.Truncated,
			"warnings":         f.Warnings,
			"evidence_meaning": "a FileZilla connection file that holds no server entries",
		})
		out.Raw = append(out.Raw, model.RawEvidence{
			SourceReference: "filezilla:empty",
			Raw:             string(raw),
		})
	}
	return out, nil
}

// sectionMeaning states, per file, exactly how strong the entry is as
// evidence. The two files are genuinely different claims and are never
// described in the same words.
func sectionMeaning(section string) string {
	switch section {
	case filezilla.SectionRecentServers:
		return "FileZilla recorded this server in its RECENT SERVERS list, which the client writes when a " +
			"connection is started from the Quickconnect bar. This is evidence that a connection to this host " +
			"was ATTEMPTED from this user's profile. It is NOT evidence that the connection succeeded, that " +
			"anyone authenticated, or that any file was transferred -- and it records no time."
	case filezilla.SectionSiteManager:
		return "FileZilla stored this server in its SITE MANAGER, which holds sites a user saved. A saved site " +
			"may never have been connected to at all. This is configuration evidence, not activity evidence, " +
			"and it records no time."
	}
	return "a FileZilla server entry"
}

func serverEvent(s filezilla.Server, f filezilla.File, sourceName string) (model.Event, model.RawEvidence) {
	ref := "filezilla:" + s.Section + ":" + strconv.Itoa(s.Index)

	extra := map[string]string{
		"artifact_class":     "filezilla_server_entry",
		"source_file":        sourceName,
		"filezilla_section":  s.Section,
		"filezilla_version":  f.Version,
		"filezilla_platform": f.Platform,
		"server_entry_index": strconv.Itoa(s.Index),
		"server_host":        s.Host,
		"server_host_kind":   s.HostKind,
		"evidence_meaning":   sectionMeaning(s.Section),
		"timestamp_meaning":  "no time is recorded for this event",
		"timestamp_basis": "A FileZilla server entry carries no timestamp. Neither recentservers.xml nor " +
			"sitemanager.xml records when an entry was created, connected to or last used. The file's own " +
			"modification time dates the most recent change to the whole list, not this entry, and is not " +
			"substituted here.",
	}

	// The IPv4 question, answered explicitly either way. An analyst
	// asking "which IP was this" must not have to infer the answer from
	// the absence of a field.
	switch s.HostKind {
	case filezilla.HostIPv4:
		extra["server_ipv4"] = s.Host
		extra["server_address_type"] = "IPv4 address, recorded literally in the <Host> element"
	case filezilla.HostIPv6:
		extra["server_ipv6"] = s.Host
		extra["server_address_type"] = "IPv6 address, recorded literally in the <Host> element"
		extra["ipv4_availability"] = "no IPv4 address is present in this entry: the host is stored as an " +
			"IPv6 address. No IPv4 address was inferred."
	case filezilla.HostName:
		extra["server_hostname"] = s.Host
		extra["server_address_type"] = "hostname, recorded literally in the <Host> element"
		extra["ipv4_availability"] = "no IPv4 address is present in this entry: the host is stored as a " +
			"hostname. Resolving it would require DNS, which Tracefall does not perform -- and a name's " +
			"address today is not necessarily what it resolved to when the entry was written."
	case filezilla.HostAbsent:
		extra["server_address_type"] = "no <Host> element was present in this entry"
	default:
		extra["server_address_type"] = "the <Host> element is present but is neither a valid IP address " +
			"nor a well-formed hostname; it is reported exactly as stored"
	}

	if s.Port > 0 {
		extra["server_port"] = strconv.Itoa(s.Port)
	} else if s.PortRaw != "" {
		extra["server_port_raw"] = s.PortRaw
		extra["server_port_note"] = "the <Port> element is not a number and was not converted"
	}

	extra["protocol_code"] = s.ProtocolRaw
	if s.Protocol != "" {
		extra["protocol"] = s.Protocol
	} else if s.ProtocolRaw != "" {
		extra["protocol"] = "unrecognized"
		extra["protocol_note"] = "FileZilla ServerProtocol code " + s.ProtocolRaw +
			" is not one this build documents; no protocol name was assumed for it"
	}

	if s.User != "" {
		extra["server_username"] = s.User
	}
	if s.Account != "" {
		extra["server_account"] = s.Account
	}
	if s.Name != "" {
		extra["site_name"] = s.Name
	}
	if s.Comment != "" {
		extra["site_comment"] = s.Comment
	}
	if s.RemoteDir != "" {
		extra["remote_directory"] = s.RemoteDir
	}
	if s.LocalDir != "" {
		extra["local_directory"] = s.LocalDir
	}
	if s.ServerTypeRaw != "" {
		extra["server_type_code"] = s.ServerTypeRaw
	}
	if s.LogonTypeRaw != "" {
		extra["logon_type_code"] = s.LogonTypeRaw
		if s.LogonType != "" {
			extra["logon_type"] = s.LogonType
		}
		extra["logon_type_meaning"] = "how the client was configured to obtain credentials for this server. " +
			"It says nothing about whether authentication was ever attempted or succeeded."
	}
	if s.PasvMode != "" {
		extra["transfer_mode"] = s.PasvMode
	}
	if s.EncodingType != "" {
		extra["encoding_type"] = s.EncodingType
	}
	if s.BypassProxy != "" {
		extra["bypass_proxy"] = s.BypassProxy
	}

	// Credential material: presence only, never a value.
	extra["password_present"] = strconv.FormatBool(s.PasswordPresent)
	if s.PasswordPresent {
		if s.PasswordStorage != "" {
			extra["password_storage"] = s.PasswordStorage
		}
		extra["password_handling"] = "a stored password exists in this entry. Tracefall does not extract, " +
			"store, display, log or decode it -- only its presence is recorded."
	}

	for k, v := range s.Unknown {
		extra["filezilla_"+strings.ToLower(k)] = v
	}
	if len(f.Warnings) > 0 {
		extra["parse_warnings"] = strings.Join(f.Warnings, "; ")
	}
	if f.Truncated {
		extra["document_truncated"] = "true"
	}

	raw, _ := json.Marshal(map[string]any{
		"source_file":      sourceName,
		"product":          f.Product,
		"client_version":   f.Version,
		"platform":         f.Platform,
		"section":          s.Section,
		"entry_index":      s.Index,
		"host":             s.Host,
		"host_kind":        s.HostKind,
		"port":             s.Port,
		"port_raw":         s.PortRaw,
		"protocol_code":    s.ProtocolRaw,
		"protocol":         s.Protocol,
		"server_type_code": s.ServerTypeRaw,
		"logon_type_code":  s.LogonTypeRaw,
		"logon_type":       s.LogonType,
		"user":             s.User,
		"account":          s.Account,
		"name":             s.Name,
		"comments":         s.Comment,
		"remote_dir":       s.RemoteDir,
		"local_dir":        s.LocalDir,
		"pasv_mode":        s.PasvMode,
		"encoding_type":    s.EncodingType,
		"bypass_proxy":     s.BypassProxy,
		"password_present": s.PasswordPresent,
		"password_storage": s.PasswordStorage,
		// Stated in the raw record too, because the raw record is what an
		// analyst reads to check what the parser did with the source.
		"password_value":   "not extracted: FileZilla password material is never read out of the source file",
		"other_elements":   s.Unknown,
		"warnings":         f.Warnings,
		"truncated":        f.Truncated,
		"evidence_meaning": sectionMeaning(s.Section),
	})

	ev := model.Event{
		// No Timestamp. See timestamp_basis above.
		EventType:    model.EventFileZillaServerEntry,
		ArtifactType: model.ArtifactFileZillaServer,
		Parser:       parserName,
		FilePath:     sourceName,
		User:         s.User,
		// NetworkDest and NetworkDestPort carry the server the client was
		// configured for. They are the connection's INTENDED endpoint as
		// recorded in configuration -- the event type and evidence_meaning
		// are what stop this reading as an observed connection.
		NetworkDest:     s.Host,
		NetworkDestPort: s.Port,
		// 1.0: the mapping is unambiguous. Every field here is a labelled
		// XML element read literally, with nothing inferred.
		Confidence:      1.0,
		SourceReference: ref,
		Extra:           extra,
	}
	return ev, model.RawEvidence{SourceReference: ref, Raw: string(raw)}
}
