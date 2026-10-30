package defenderhistory

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

type Parser struct{}

func New() *Parser                  { return &Parser{} }
func (Parser) Name() string         { return "defenderhistory@1" }
func (Parser) ArtifactType() string { return model.ArtifactDefenderHistory }

// A path is a hint only. Content detection is restricted to this evidence-
// relative directory component, never the server's absolute storage path.
func (Parser) Detect(string) bool { return false }
func (Parser) DetectPath(p string) bool {
	parts := strings.Split(strings.ReplaceAll(p, `\`, "/"), "/")
	for i, s := range parts {
		if i < len(parts)-1 && strings.EqualFold(s, "DetectionHistory") {
			return true
		}
	}
	return false
}
func (p Parser) DetectContent(b []byte) bool { return p.ConfirmContent(b) }
func (Parser) ConfirmContent(b []byte) bool {
	// Inspect only the three checked header entries; the rest is validated at
	// import. Keep recognisable unsupported Magic.Version variants claimable so
	// import reports an explicit unsupported failure, not a benign empty result.
	pos := 0
	var es []Entry
	for i := 0; i < 3; i++ {
		if len(b)-pos < 8 {
			return false
		}
		n := uint64(binary.LittleEndian.Uint32(b[pos:]))
		span := 8 + ((n + 7) &^ uint64(7))
		if span > uint64(len(b)-pos) {
			return false
		}
		part, err := ReadEntries(b[pos : pos+int(span)])
		if err != nil {
			return false
		}
		es = append(es, part[0])
		pos += int(span)
	}
	return es[0].Type == 8 && es[1].Type == 30 && es[2].Type == 21 && strings.HasPrefix(es[2].Text, "Magic.Version:")
}
func (Parser) Parse(p string) (parsers.ParseResult, error) {
	f, err := os.Open(p)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return parsers.ParseResult{}, err
	}
	r, err := Decode(b)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	raw, err := json.Marshal(struct {
		SourceBytes []byte
		Record      *Record
	}{b, r})
	if err != nil {
		return parsers.ParseResult{}, err
	}
	ref := fmt.Sprintf("record:0;bytes:0-%d", r.EOF)
	x := map[string]string{"detection_id": r.DetectionID, "threat_id": strconv.FormatUint(r.ThreatID, 10), "resource_section_count": strconv.Itoa(len(r.Resources)), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(b)), "source_eof": strconv.Itoa(r.EOF), "timestamp_basis": "initial_detection_time FILETIME (UTC); zero is unset; no fallback", "history_semantics": "stateful engine observation; no process or action success implied"}
	e := model.Event{EventType: model.EventAntimalwareHistory, ArtifactType: model.ArtifactDefenderHistory, Parser: "defenderhistory@1", SourceReference: ref, Extra: x}
	for _, c := range r.Times {
		x[c.Role+"_filetime"] = strconv.FormatUint(c.Ticks, 10)
		if c.Role == "initial_detection_time" {
			instant := c.Time()
			// Unsigned FILETIME starts in 1601. Structurally valid ticks can
			// exceed JSON's calendar; retain them raw without dating the event.
			if !instant.IsZero() && (instant.Year() < 1601 || instant.Year() > 9999) {
				x["timestamp_normalization_note"] = "initial_detection_time outside supported FILETIME calendar 1601..9999; timestamp left undated; raw ticks retained"
			} else {
				e.Timestamp = instant
			}
		}
	}
	cov := &model.ParseCoverage{RecordsRead: 1, Mapped: 1, Notes: []string{"Strict modern Magic.Version:1.2 subset; full source EOF including padding. Raw private projection retains all typed entries and source bytes. Unknown flags have no inferred semantics."}}
	if note := x["timestamp_normalization_note"]; note != "" {
		cov.Notes = append(cov.Notes, note)
	}
	if e.Timestamp.IsZero() {
		cov.Undated = 1
	}
	return parsers.ParseResult{Coverage: cov, Events: []model.Event{e}, Raw: []model.RawEvidence{{SourceReference: ref, Raw: string(raw)}}}, nil
}
