// Package grafanalog turns one Grafana application log line into an event.
//
// Grafana writes logfmt: logger=context ... t=<RFC3339 UTC> level=info
// msg="Request Completed" method=POST path=/login status=401 remote_addr=...
// The same line appears in grafana.log and, when Grafana logs to the console, as
// the text of a container's JSON log.
//
// What a line proves. A "Request Completed" line records that Grafana answered a
// request with a status; the default configuration logs only some requests, and
// an anonymous request carries no user name, so a failed login does not record
// which name was tried. Absence of a line is not absence of a request.
package grafanalog

import (
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"tracefall/internal/cmdsem"
	"tracefall/internal/logfmt"
	"tracefall/internal/model"
)

const (
	maxValue  = 512
	maxFields = 24
)

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "\u2026"
}

// requestKeys are consumed by the web_request mapping and are not repeated as
// grafana_* fields.
var requestKeys = map[string]bool{
	"logger": true, "t": true, "level": true, "msg": true, "method": true, "path": true, "status": true,
	"remote_addr": true, "size": true, "referer": true, "handler": true, "uname": true, "userId": true, "orgId": true,
}

// ParseLine reads one logfmt line. It reports false for a line that is not a
// Grafana record: no parsable t=, no logger= or no msg=.
func ParseLine(line string) (model.Event, bool) {
	p, ok := logfmt.Parse(strings.TrimRight(line, "\r\n"))
	if !ok {
		return model.Event{}, false
	}
	get := func(k string) string { v, _ := p.Get(k); return v }
	ts, err := time.Parse(time.RFC3339Nano, get("t"))
	if err != nil || get("logger") == "" {
		return model.Event{}, false
	}
	if _, has := p.Get("msg"); !has {
		return model.Event{}, false
	}
	msg := get("msg")
	e := model.Event{Timestamp: ts.UTC(), Extra: map[string]string{
		"message":        clip(cmdsem.Redact(msg), maxValue),
		"grafana_level":  get("level"),
		"grafana_logger": get("logger"),
	}}
	if msg == "Request Completed" {
		e.EventType = model.EventWebRequest
		e.NetworkSource = get("remote_addr")
		e.User = get("uname")
		e.Extra["method"] = get("method")
		e.Extra["uri"] = clip(get("path"), maxValue)
		e.Extra["status"] = get("status")
		e.Extra["bytes"] = get("size")
		e.Extra["referrer"] = clip(cmdsem.Redact(get("referer")), maxValue)
		e.Extra["grafana_handler"] = get("handler")
		e.Extra["grafana_user_id"] = get("userId")
		e.Extra["grafana_org_id"] = get("orgId")
		e.Extra["records_outcome"] = "false: the line records the status the server returned, not what the request did"
		return e, true
	}
	e.EventType = model.EventGrafanaLog
	keys := p.Keys()
	sort.Strings(keys)
	n := 0
	for i, k := range keys {
		if requestKeys[k] || (i > 0 && keys[i-1] == k) || n >= maxFields {
			continue
		}
		e.Extra["grafana_"+k] = clip(cmdsem.Redact(get(k)), maxValue)
		n++
	}
	return e, true
}
