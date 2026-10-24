package narrative

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"tracefall/internal/enrich/virustotal"
	"tracefall/internal/model"
)

const ReviewMaxVT = 60
const ReviewMaxVTRefs = 120

// ReviewVT is a local frozen allowlist DTO, NEVER serialized into model input.
// Counts are pointers: missing verdicts must never read as zero detections.
type ReviewVT struct {
	ID               string   `json:"id"`
	Provider         string   `json:"provider"`
	IndicatorType    string   `json:"indicator_type"`
	Indicator        string   `json:"indicator"`
	Status           string   `json:"status"`
	FetchedAt        string   `json:"fetched_at"`
	VerdictsRecorded bool     `json:"verdicts_recorded"`
	Malicious        *int     `json:"malicious,omitempty"`
	Suspicious       *int     `json:"suspicious,omitempty"`
	Harmless         *int     `json:"harmless,omitempty"`
	Undetected       *int     `json:"undetected,omitempty"`
	Timeout          *int     `json:"timeout,omitempty"`
	Failure          *int     `json:"failure,omitempty"`
	TypeUnsupported  *int     `json:"type_unsupported,omitempty"`
	Engines          *int     `json:"engines,omitempty"`
	SourceEventIDs   []string `json:"source_event_ids"`
	OmittedRefs      int      `json:"omitted_refs"`
	Scope            string   `json:"scope"`
}

// ValidReviewVTIndicator refuses normalization and a mismatched algorithm.
func ValidReviewVTIndicator(e model.Enrichment) bool {
	return e.Provider == model.EnrichmentVirusTotal && virustotal.ValidHash(e.Indicator) && !virustotal.TrivialHash(e.Indicator) && virustotal.HashType(e.Indicator) == e.IndicatorType
}

// ReviewVTLinks resolves only explicit references with an exact known content
// hash, within this snapshot/case. Names and process identity are not joins.
func ReviewVTLinks(e model.Enrichment, events []model.Event) []string {
	if !ValidReviewVTIndicator(e) {
		return nil
	}
	refs := map[string]bool{}
	for _, id := range e.SourceEventIDs {
		refs[id] = true
	}
	var ids []string
	for _, ev := range events {
		if ev.CaseID != e.CaseID || !refs[ev.ID] {
			continue
		}
		for _, key := range []string{"content_sha256", "response_sha256", "sha256", "sha1", "md5"} {
			algorithm := key
			if key == "content_sha256" || key == "response_sha256" {
				algorithm = "sha256"
			}
			if algorithm == e.IndicatorType && ev.Extra[key] == e.Indicator {
				ids = append(ids, ev.ID)
				break
			}
		}
	}
	sort.Strings(ids)
	return ids
}

// FreezeReviewVT drops provider prose and validates the complete numerical
// verdict record. Unknown, malformed or contradictory answers stay unusable.
func FreezeReviewVT(e model.Enrichment, links []string, scope string) ReviewVT {
	r := ReviewVT{ID: e.ID, Provider: "virustotal", IndicatorType: e.IndicatorType, Indicator: e.Indicator, Status: "unusable", SourceEventIDs: []string{}, Scope: scope}
	if !e.FetchedAt.IsZero() {
		r.FetchedAt = e.FetchedAt.UTC().Format(time.RFC3339Nano)
	}
	links = append([]string(nil), links...)
	sort.Strings(links)
	last := ""
	for _, id := range links {
		if id == last {
			continue
		}
		last = id
		if len(r.SourceEventIDs) < ReviewMaxVTRefs {
			r.SourceEventIDs = append(r.SourceEventIDs, id)
		} else {
			r.OmittedRefs++
		}
	}
	if !ValidReviewVTIndicator(e) {
		return r
	}
	switch e.Status {
	case "not_found":
		r.Status = "not_found"
		return r
	case "error":
		r.Status = "error"
		return r
	case "found":
	default:
		return r
	}
	if len(e.ResultJSON) > 128<<10 {
		return r
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal([]byte(e.ResultJSON), &raw) != nil {
		return r
	}
	var found bool
	if json.Unmarshal(raw["found"], &found) != nil || !found {
		return r
	}
	values := make([]int, 7)
	for i, key := range []string{"malicious", "suspicious", "harmless", "undetected", "timeout", "failure", "type_unsupported"} {
		v, ok := raw[key]
		if !ok || string(v) == "null" || json.Unmarshal(v, &values[i]) != nil || values[i] < 0 || values[i] > 10000 {
			return r
		}
	}
	engines := values[0] + values[1] + values[2] + values[3]
	if engines+values[4]+values[5]+values[6] > 10000 {
		return r
	}
	r.Status = "found"
	r.VerdictsRecorded = true
	r.Malicious = &values[0]
	r.Suspicious = &values[1]
	r.Harmless = &values[2]
	r.Undetected = &values[3]
	r.Timeout = &values[4]
	r.Failure = &values[5]
	r.TypeUnsupported = &values[6]
	r.Engines = &engines
	return r
}

func appendReviewVT(p *ReviewPrepared, in ReviewInput, aliases map[string]string, b *strings.Builder) {
	if len(in.Enrichments) == 0 && (in.VTCatalog == nil || in.VTCatalog.VTTotal == 0) {
		return
	}
	cv := &p.Coverage
	for _, e := range in.Enrichments {
		cv.VTTotal++
		if !ValidReviewVTIndicator(e) {
			cv.VTInvalid++
			continue
		}
		if FreezeReviewVT(e, nil, "").Status == "unusable" {
			cv.VTInvalid++
		}
		links := ReviewVTLinks(e, in.Events)
		if len(links) == 0 {
			cv.VTUnlinked++
			continue
		}
		var selected, ids []string
		for _, id := range links {
			if a := aliases[id]; a != "" {
				selected = append(selected, a)
				ids = append(ids, id)
			}
		}
		if len(selected) == 0 || cv.VTIncluded >= ReviewMaxVT {
			continue
		}
		r := FreezeReviewVT(e, ids, "single_review_attempt_snapshot")
		a := fmt.Sprintf("V%d", cv.VTIncluded+1)
		var line strings.Builder
		at := r.FetchedAt
		if at == "" {
			at = "unknown"
		}
		fmt.Fprintf(&line, "%s | external_opinion=stored_virustotal hash=%s status=%s fetched_at=%s events=%s verdicts_recorded=%t", a, p.text(e.Indicator, 100), r.Status, at, strings.Join(selected, ","), r.VerdictsRecorded)
		if r.VerdictsRecorded {
			fmt.Fprintf(&line, " malicious=%d suspicious=%d harmless=%d undetected=%d timeout=%d failure=%d type_unsupported=%d engines=%d", *r.Malicious, *r.Suspicious, *r.Harmless, *r.Undetected, *r.Timeout, *r.Failure, *r.TypeUnsupported, *r.Engines)
		}
		line.WriteByte('\n')
		// Reserve bounded fixed coverage text; never crowd out primary excerpts.
		if b.Len()+len(p.System)+line.Len()+512 > ReviewMaxBytes {
			continue
		}
		p.reviewRefs[a] = Cite{Kind: "enrichment", ID: e.ID}
		p.FrozenVT = append(p.FrozenVT, r)
		cv.VTIncluded++
		b.WriteString(line.String())
	}
	if in.VTCatalog != nil {
		cv.VTTotal = in.VTCatalog.VTTotal
		cv.VTInvalid = in.VTCatalog.VTInvalid
		cv.VTUnlinked = in.VTCatalog.VTUnlinked
	}
	cv.VTOmitted = cv.VTTotal - cv.VTIncluded
	fmt.Fprintf(b, "K1 stored_vt | vt_total=%d vt_included=%d vt_omitted=%d vt_invalid=%d vt_unlinked=%d\n", cv.VTTotal, cv.VTIncluded, cv.VTOmitted, cv.VTInvalid, cv.VTUnlinked)
}
