package winevent

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"tracefall/internal/model"
)

const smbServerProvider = "Microsoft-Windows-SMBServer"
const smbServerChannel = "Microsoft-Windows-SMBServer/Security"

// normalizeSMBServerEvent maps two SMB server audit-failure records of the
// Microsoft-Windows-SMBServer/Security log. Their UserData root is named
// EventData and the reader flattens its children:
//
//	551   "SMB Session Authentication Failure": Status, TranslatedStatus,
//	      ClientAddress, SessionId, UserName, ClientName, SPN,
//	      SPNValidationPolicy, ReasonCode (SessionGUID, ConnectionGUID)
//	1009  "The server denied anonymous access to the client": ClientAddress,
//	      ClientName, SessionID (SessionGUID, ConnectionGUID)
//
// Note the two spell the session id differently (SessionId / SessionID) and
// each reads only its own spelling.
//
// The SMB client IDs 31010/31002 are not mapped: no record layout was verified.
func normalizeSMBServerEvent(ev *model.Event, in Input) (handled, mapped bool) {
	switch in.EventID {
	case 551, 1009:
	default:
		return false, false
	}
	if !strings.EqualFold(in.Provider, smbServerProvider) || !strings.EqualFold(in.Channel, smbServerChannel) {
		return true, false
	}
	p := in.Data
	blank := func(k string) bool { return strings.TrimSpace(p[k]) == "" }
	if in.EventID == 551 && blank("ClientAddress") && blank("ClientName") && blank("UserName") {
		return true, false
	}
	if in.EventID == 1009 && blank("ClientAddress") && blank("ClientName") && blank("SessionID") {
		return true, false
	}
	ev.EventType = model.EventSMBSecurity
	ev.User = ""
	if in.EventID == 551 {
		ev.User = dashToEmpty(strings.TrimSpace(p["UserName"]))
	}
	if raw, ok := p["ClientAddress"]; ok {
		ev.Extra["client_address_recorded"] = raw
		if ip, port, decoded := decodeClientAddress(raw); decoded {
			ev.NetworkSource = ip
			if port != "" {
				ev.Extra["source_port"] = port
			}
		}
	}
	setRecorded(ev, "client_name", p, "ClientName")
	setRecorded(ev, "session_guid", p, "SessionGUID")
	setRecorded(ev, "connection_guid", p, "ConnectionGUID")
	ev.Extra["outcome"] = "failure"
	switch in.EventID {
	case 551:
		setRecorded(ev, "session_id", p, "SessionId")
		setRecorded(ev, "status", p, "Status")
		setRecorded(ev, "translated_status", p, "TranslatedStatus")
		setRecorded(ev, "spn", p, "SPN")
		setRecorded(ev, "spn_validation_policy", p, "SPNValidationPolicy")
		setRecorded(ev, "reason_code", p, "ReasonCode")
		ev.Extra["action"] = "smb_session_authentication_failed"
		ev.Extra["evidence_meaning"] = "The SMB server audit log recorded an SMB session authentication failure for the client and account shown, with the status values shown."
		ev.Extra["limitations"] = "An audit-failure record of one rejected session setup: not a logon, and it does not establish that the account exists, that credentials were guessed, or intent; anonymous and misconfigured clients and scanners produce these routinely. Status values are retained as recorded without interpretation. The client address and name are as the SMB server saw them and may be a NAT or proxy address."
	case 1009:
		setRecorded(ev, "session_id", p, "SessionID")
		ev.Extra["action"] = "smb_anonymous_access_denied"
		ev.Extra["evidence_meaning"] = "The SMB server audit log recorded that the server denied anonymous access to the client shown."
		ev.Extra["limitations"] = "A denied connection attempt: not a logon, and it does not establish what the client wanted, that credentials were guessed, or intent; clients that offer no credentials produce these routinely. The client address and name are as the SMB server saw them and may be a NAT or proxy address."
	}
	return true, true
}

// decodeClientAddress turns the SMB server's ClientAddress into an IP and a
// port. The manifest types it as a SOCKADDR, so the record carries the bytes of
// a SOCKADDR_IN (16 bytes, family 2) or SOCKADDR_IN6 (28 bytes, family 23); a
// text address, with or without port, is also accepted. Anything else is not
// decoded and is never guessed.
func decodeClientAddress(raw string) (ip, port string, ok bool) {
	s := strings.TrimSpace(raw)
	if len(s) == 32 || len(s) == 56 {
		if b, err := hex.DecodeString(s); err == nil {
			family := binary.LittleEndian.Uint16(b[0:2])
			p := strconv.Itoa(int(binary.BigEndian.Uint16(b[2:4])))
			switch {
			case family == 2 && len(b) == 16:
				return net.IP(b[4:8]).String(), p, true
			case family == 23 && len(b) == 28:
				return net.IP(b[8:24]).String(), p, true
			}
			return "", "", false
		}
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().String(), strconv.Itoa(int(ap.Port())), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String(), "", true
	}
	return "", "", false
}
