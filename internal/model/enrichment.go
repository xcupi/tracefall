package model

import "time"

// Enrichment is what an outside service said about one indicator of a case.
//
// It is not evidence. It records an opinion held by someone else at the moment
// they were asked (FetchedAt), about an indicator (today: a file hash) that was
// read from evidence. It is kept apart from events and findings and is never
// used to change either.
type Enrichment struct {
	ID       string `json:"id"`
	CaseID   string `json:"case_id"`
	Provider string `json:"provider"` // "virustotal"
	// IndicatorType is "sha256", "sha1" or "md5".
	IndicatorType string `json:"indicator_type"`
	Indicator     string `json:"indicator"`
	// Status is EnrichmentFound, EnrichmentNotFound or EnrichmentError.
	Status string `json:"status"`
	// ResultJSON is the provider's answer in the provider package's own shape.
	ResultJSON string `json:"result,omitempty"`
	// Error is a safe, human-readable reason when Status is "error".
	Error     string    `json:"error,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
	// SourceEventIDs are the events whose fields held this indicator.
	SourceEventIDs []string `json:"source_event_ids"`
}

const (
	EnrichmentFound    = "found"
	EnrichmentNotFound = "not_found"
	EnrichmentError    = "error"

	EnrichmentVirusTotal = "virustotal"
)
