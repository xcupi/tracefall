// Package evtx parses raw Windows Event Log (.evtx) files into
// normalized events, reading the binary format directly via
// internal/evtx rather than depending on EvtxECmd having been run first.
//
// The channel/EventID mapping is NOT implemented here: it lives in
// internal/parsers/winevent and is shared with the EvtxECmd CSV parser,
// so the same Windows record read from either source produces identical
// normalized fields -- and therefore one deduplicated Event with two
// observations, rather than two events that every detection rule would
// count twice. See docs/native-artifacts.md.
package evtx

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"tracefall/internal/evtx"
	"tracefall/internal/model"
	"tracefall/internal/normalize"
	"tracefall/internal/parsers"
	"tracefall/internal/parsers/winevent"
)

const parserName = "evtx@1"

// Parser implements parsers.ArtifactParser (and parsers.ContentDetector)
// for raw .evtx files.
type Parser struct {
	limits evtx.Limits
}

func New() *Parser { return &Parser{limits: evtx.DefaultLimits()} }

func (Parser) Name() string         { return parserName }
func (Parser) ArtifactType() string { return model.ArtifactWindowsEventLog }

// Detect matches the .evtx extension. This is only the fast path: a file
// with the extension is still content-checked when it is parsed, and a
// file WITHOUT the extension is still recognized by DetectContent, so
// nothing depends on the name being right.
func (Parser) Detect(relPath string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(relPath)), ".evtx")
}

// DetectContent identifies an event log by its file signature, so a log
// saved as "Security.bak" is still found and a ZIP renamed to
// "Security.evtx" is still rejected.
func (Parser) DetectContent(header []byte) bool { return evtx.Sniff(header) }

// Parse reads every record and normalizes the ones Tracefall maps.
//
// Records that parse cleanly but belong to a channel/EventID pair with
// no mapping are counted and skipped, exactly as the CSV parser already
// behaves -- an under-specified event is worse than no event. Records
// that fail to parse, and chunks that fail validation, are reported
// through the summary event's Extra rather than being passed over in
// silence: a partially recovered log must never look like a clean one.
func (p Parser) Parse(absPath string) (parsers.ParseResult, error) {
	f, err := evtx.Open(absPath, p.limits)
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("evtx: %w", err)
	}
	defer f.Close()

	var out parsers.ParseResult
	var unmapped int

	stats, err := f.Walk(func(rec evtx.Record) error {
		ev, ok := toEvent(rec)
		if !ok {
			unmapped++
			return nil
		}
		out.Events = append(out.Events, ev)

		// The raw record is preserved as the resolved System + EventData
		// pairs, not as re-serialized BinXML: that is what was actually
		// read, it is auditable by a human, and it is bounded. The
		// original bytes remain in the evidence file itself, which
		// Tracefall never modifies.
		rawJSON, _ := json.Marshal(map[string]any{
			"system":     rec.System,
			"event_data": rec.Data,
			"chunk":      rec.ChunkNumber,
			"offset":     rec.Offset,
		})
		out.Raw = append(out.Raw, model.RawEvidence{
			SourceReference: ev.SourceReference,
			Raw:             string(rawJSON),
		})
		return nil
	})
	if err != nil {
		return parsers.ParseResult{}, fmt.Errorf("evtx: %w", err)
	}

	// Recovery facts belong on every event from this file, so an analyst
	// looking at any one of them can see the file it came from was not
	// fully readable.
	if stats.Partial() || stats.LimitReached {
		note := fmt.Sprintf("chunks_read=%d chunks_failed=%d records_read=%d records_failed=%d limit_reached=%t",
			stats.ChunksRead, stats.ChunksFailed, stats.RecordsRead, stats.RecordsFailed, stats.LimitReached)
		for i := range out.Events {
			out.Events[i].Extra["evtx_partial_parse"] = note
			out.Events[i].Confidence = 0.9
		}
	}
	return out, nil
}

// toEvent converts one raw record into a normalized event, or reports
// that Tracefall has no mapping for it.
func toEvent(rec evtx.Record) (model.Event, bool) {
	sys := rec.System
	if sys.TimeCreated.IsZero() {
		// No usable timestamp: the record cannot be placed on a timeline,
		// and inventing one would corrupt correlation.
		return model.Event{}, false
	}

	ev := model.Event{
		Timestamp: sys.TimeCreated.UTC(),
		// System/Computer is the strongest host signal any artifact
		// gives Tracefall -- it is recorded by the machine itself, at the
		// moment of the event. It goes straight onto the event, so no
		// later host backfill is needed (see internal/api/hostenrich.go).
		Host:            normalize.Host(sys.Computer),
		Provider:        sys.Channel,
		EventID:         sys.EventID,
		ArtifactType:    model.ArtifactWindowsEventLog,
		Parser:          parserName,
		Confidence:      1.0,
		SourceReference: "record:" + strconv.FormatUint(sys.EventRecordID, 10),
		Extra:           map[string]string{},
	}

	// The user is resolved by the shared mapping from the event payload
	// (TargetUserName/SubjectUserName and friends). The Security UserID
	// SID is the account the event was LOGGED under, which is usually
	// SYSTEM and is rarely the subject -- so it is kept in Extra as
	// evidence rather than being presented as the event's user.
	if !winevent.Normalize(&ev, winevent.Input{
		Channel:  sys.Channel,
		Provider: sys.Provider,
		EventID:  sys.EventID,
		Data:     rec.Data,
	}) {
		return model.Event{}, false
	}

	addSystemExtras(&ev, sys)
	return ev, true
}

// addSystemExtras records the EVTX-specific System fields. They live in
// Extra rather than becoming Event struct fields: they are provenance
// and triage context, they matter to no detection rule, and widening the
// Event model for them would push artifact-specific detail into every
// other artifact's events too.
func addSystemExtras(ev *model.Event, sys evtx.System) {
	set := func(k, v string) {
		if v != "" {
			ev.Extra[k] = v
		}
	}
	setInt := func(k string, v int) {
		if v != 0 {
			ev.Extra[k] = strconv.Itoa(v)
		}
	}

	ev.Extra["evtx_record_id"] = strconv.FormatUint(sys.EventRecordID, 10)
	set("evtx_provider", sys.Provider)
	set("evtx_provider_guid", sys.ProviderGUID)
	set("evtx_channel", sys.Channel)
	set("evtx_computer", sys.Computer)
	setInt("evtx_event_id", sys.EventID)
	setInt("evtx_version", sys.Version)
	setInt("evtx_level", sys.Level)
	setInt("evtx_task", sys.Task)
	setInt("evtx_opcode", sys.Opcode)
	set("evtx_keywords", sys.Keywords)
	setInt("evtx_process_id", sys.ProcessID)
	setInt("evtx_thread_id", sys.ThreadID)
	set("evtx_security_user_id", sys.UserID)
	set("evtx_activity_id", sys.ActivityID)
	set("evtx_related_activity_id", sys.RelatedActivityID)
}
