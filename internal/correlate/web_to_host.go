package correlate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"tracefall/internal/clockskew"
	"tracefall/internal/hostid"
	"tracefall/internal/model"
)

// webToHostWindow is how long after an object crossed the wire a host event
// naming the same file is still considered a consequence of it. A file can
// sit on disk for days before it is run; the window bounds the question, and
// the description says that it is a bound, not a finding.
const webToHostWindow = 24 * time.Hour

// webToHostSlack lets a host event land just before the transfer on the
// capture's scale without being thrown away: the two clocks are only known
// to within the clock-offset estimate, and even without one, a file's name can
// be recorded as the transfer starts.
const webToHostSlack = 2 * time.Minute

const maxWebToHost = 200

// Names that would match a very large share of ordinary traffic and say
// nothing: a bare directory index or a generic script served on every page.
var genericObjectNames = map[string]bool{
	"index.html": true, "index.htm": true, "favicon.ico": true, "robots.txt": true, "default.aspx": true,
	"index.php": true, "style.css": true, "main.css": true, "jquery.js": true,
}

// Object kinds worth tying to a host: something a machine can run or load.
// Anything else (an image, a stylesheet) crossing the wire is the normal
// business of a web browser and would bury the correlation.
func executableSignature(sig string) bool {
	s := strings.ToLower(sig)
	for _, k := range []string{"executable", "elf", "script", "archive", "msi", "java", "dll", "office", "shortcut", "powershell", "batch"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func hasRunnableExtension(name string) bool {
	n := strings.ToLower(name)
	for _, ext := range []string{".exe", ".dll", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".hta", ".lnk", ".sh", ".zip", ".rar", ".7z", ".doc", ".docm", ".xls", ".xlsm", ".iso", ".img"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	return false
}

// webObjectNames returns the file names worth looking for on hosts: objects
// a capture shows being delivered whole whose name or content marks them as
// something that can be run.
func webObjectNames(events []model.Event) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range events {
		if o, ok := objectOf(e); ok && !seen[o.name] {
			seen[o.name] = true
			out = append(out, o.name)
		}
	}
	sort.Strings(out)
	// EventFilter.Names honours at most MaxNames, so ask for no more than it
	// will take rather than have it drop some without saying.
	if len(out) > model.MaxNames {
		out = out[:model.MaxNames]
	}
	return out
}

type delivered struct {
	ev   model.Event
	name string // lower-cased
	sha  string
	size string
	sig  string
}

func objectOf(e model.Event) (delivered, bool) {
	if e.EventType != model.EventWebRequest || e.ArtifactType != model.ArtifactNetworkCapture {
		return delivered{}, false
	}
	name := strings.ToLower(e.Extra["filename"])
	if name == "" || e.Extra["response_sha256"] == "" || e.Extra["reassembly"] != "complete" {
		return delivered{}, false
	}
	// Only a whole object: a 206 body is one byte range of it, and its hash is
	// the hash of that range.
	if e.Extra["status"] != "200" {
		return delivered{}, false
	}
	if genericObjectNames[name] {
		return delivered{}, false
	}
	if !executableSignature(e.Extra["file_signature"]) && !hasRunnableExtension(name) {
		return delivered{}, false
	}
	return delivered{ev: e, name: name, sha: e.Extra["response_sha256"], size: e.Extra["response_size"], sig: e.Extra["file_signature"]}, true
}

// BuildWebToHost ties an object delivered over the wire to events on a host
// that name the same file afterwards.
//
// The tie is by file name and order in time, and says so. It is NOT a hash
// match: the host's own artifacts (file system metadata, process creation)
// do not carry the file's hash, so the file on the host can only be said to
// share a name with the object that was delivered. A match is a lead that
// needs the file itself to confirm.
//
// The capture shows the object arrived at the client; it does not show that
// the client saved or ran it. Those are what the host events can add.
func BuildWebToHost(caseID string, capture, host []model.Event, reg *hostid.Registry, skews []clockskew.Estimate) []model.Correlation {
	var objects []delivered
	for _, e := range capture {
		if o, ok := objectOf(e); ok {
			objects = append(objects, o)
		}
	}
	if len(objects) == 0 || len(host) == 0 {
		return nil
	}
	byName := map[string][]model.Event{}
	for _, h := range host {
		if h.ArtifactType == model.ArtifactNetworkCapture || h.Timestamp.IsZero() {
			continue
		}
		for _, n := range []string{model.LastElement(h.FilePath), model.LastElement(h.ProcessPath), strings.ToLower(h.ProcessName)} {
			if n != "" {
				byName[n] = append(byName[n], h)
			}
		}
	}
	skewOf := map[string]clockskew.Estimate{}
	for _, s := range skews {
		skewOf[s.Subject] = s
	}

	var out []model.Correlation
	for _, o := range objects {
		cands := byName[o.name]
		if len(cands) == 0 {
			continue
		}
		clientHost := ""
		if r := reg.ByIP(o.ev.NetworkSource); r.Identity != nil {
			clientHost = r.Identity.Name
		}
		at := o.ev.Timestamp
		var matched []model.Event
		seen := map[string]bool{}
		for _, h := range cands {
			if seen[h.ID] {
				continue
			}
			if clientHost != "" && h.Host != "" && !strings.EqualFold(h.Host, clientHost) {
				continue // the object went to a different machine
			}
			ts := h.Timestamp
			if s, ok := skewOf["host:"+strings.ToLower(h.Host)]; ok && s.Steady() {
				// Express the host's time on the capture's scale. The offset
				// is an interval; use its edge that is kinder to the match
				// and let the slack absorb the rest.
				lo, _ := s.Shift(ts)
				ts = lo
			}
			if ts.Before(at.Add(-webToHostSlack)) {
				continue
			}
			// A file object in a memory image is dated to the capture of the
			// image, which can be long after the transfer; for it only the
			// order matters, since it shows the file was still around then.
			if h.EventType != model.EventMemoryFile && h.EventType != model.EventMemoryFileContent && ts.After(at.Add(webToHostWindow)) {
				continue
			}
			seen[h.ID] = true
			matched = append(matched, h)
		}
		if len(matched) == 0 {
			continue
		}
		sort.SliceStable(matched, func(i, j int) bool { return matched[i].Timestamp.Before(matched[j].Timestamp) })
		hosts := map[string]bool{}
		for _, m := range matched {
			if m.Host != "" {
				hosts[m.Host] = true
			}
		}
		var hostList []string
		for h := range hosts {
			hostList = append(hostList, h)
		}
		sort.Strings(hostList)
		if len(matched) > 12 {
			matched = matched[:12]
		}
		ids := []string{o.ev.ID}
		for _, m := range matched {
			ids = append(ids, m.ID)
		}
		clientNote := "the capture does not say which machine the client address is"
		if clientHost != "" {
			clientNote = fmt.Sprintf("the client address %s is %s", o.ev.NetworkSource, clientHost)
			if r := reg.ByIP(o.ev.NetworkSource); r.Identity != nil {
				clientNote += " (" + r.Basis.Describe() + ")"
			}
		}
		clockNote := "No clock offset was established for the host, so its times are read as they are."
		for _, h := range hostList {
			if s, ok := skewOf["host:"+strings.ToLower(h)]; ok && s.Steady() {
				clockNote = fmt.Sprintf("The host's clock was estimated %s from the capture's and its times were read on the capture's scale.", clockskew.Format(s.Offset()))
				break
			}
		}
		sameBytes := false
		for _, m := range matched {
			if m.EventType == model.EventMemoryFileContent && m.Extra["sha256"] == o.sha {
				sameBytes = true
			}
		}
		matchNote := "The match is by file name and order in time, not by content: the host's records do not carry the file's hash, so this shows a file of the same name appeared, not that it is the same file. "
		if sameBytes {
			matchNote = "Bytes recovered from the host's memory have the same SHA-256 as the object that was delivered, so the content is the same, not just the name. "
		}
		kind := o.sig
		if kind == "" {
			kind = "unrecognised content"
		}
		out = append(out, model.Correlation{
			CaseID: caseID, Type: model.CorrelationWebToHost,
			Title: fmt.Sprintf("%s delivered over HTTP, then seen on %s", o.name, strings.Join(hostList, ", ")),
			Description: fmt.Sprintf(
				"The capture shows %s (%s, %s bytes, SHA-256 %s) returned by %s with status %s to %s; %s. "+
					"%d event(s) on %s name a file called %q within %s after it. %s "+
					"%s"+
					"The capture shows the bytes crossed the wire; the host events are what show the file existing or running. Confirm with the file itself.",
				o.name, kind, o.size, o.sha, o.ev.NetworkDest, o.ev.Extra["status"], o.ev.NetworkSource, clientNote,
				len(seen), strings.Join(hostList, ", "), o.name, webToHostWindow, clockNote, matchNote),
			EventIDs: ids, FirstSeen: at, LastSeen: laterOf(at, matched[len(matched)-1].Timestamp),
		})
		if len(out) >= maxWebToHost {
			break
		}
	}
	return out
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
