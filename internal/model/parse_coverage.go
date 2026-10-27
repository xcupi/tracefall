package model

// ParseCoverage records what a parser actually read, separately from timeline
// events. Nil means not recorded (including older imports), never complete.
type ParseCoverage struct {
	// EmittedEvents separates output cardinality from mapped source records for
	// one-to-many parsers. Nil preserves the historical one-event-per-record contract.
	EmittedEvents *int `json:"emitted_events,omitempty"`

	// Notes are bounded parser-generated caveats, never raw evidence text.
	Notes           []string        `json:"notes,omitempty"`
	RecordsRead     int             `json:"records_read"`
	Mapped          int             `json:"mapped"`
	Unmapped        int             `json:"unmapped"`
	Undated         int             `json:"undated"`
	RecordsFailed   int             `json:"records_failed"`
	ChunksRead      int             `json:"chunks_read"`
	ChunksFailed    int             `json:"chunks_failed"`
	LimitReached    bool            `json:"limit_reached"`
	ByEvent         []CoverageEvent `json:"by_event,omitempty"`
	UnlistedRecords int             `json:"unlisted_records,omitempty"`

	// HiveReplay is the transaction-log state of a registry hive: what the
	// parser found when it opened it (clean, replayed, replayed_partial,
	// not_recoverable, no_logs) and which companion logs the extraction put
	// beside it. Nil for every other artifact and for imports made before it
	// existed, which means "not recorded", not "clean".
	HiveReplay *HiveReplay `json:"hive_replay,omitempty"`

	// CompanionOf is set on a registry transaction log (HIVE.LOG1, .LOG2, .LOG)
	// that was extracted only to be read together with the named hive. The file
	// is not independent evidence: it produces no events and is not a gap.
	CompanionOf string `json:"companion_of,omitempty"`
}

// HiveReplay records how a registry hive was read with respect to its
// transaction logs.
type HiveReplay struct {
	State       string   `json:"state"`
	Reason      string   `json:"reason,omitempty"`
	LogsApplied []string `json:"logs_applied,omitempty"`
	// Companions lists every same-directory log of the hive that the image holds
	// and what became of it. Empty when the image holds none (or when the
	// evidence did not come from a container that extracts them).
	Companions []HiveCompanion `json:"companions,omitempty"`
}

// Companion statuses.
const (
	CompanionExtracted = "extracted"
	CompanionOversize  = "oversize"
	CompanionFailed    = "failed"
)

// HiveCompanion is one transaction log beside a hive.
type HiveCompanion struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256,omitempty"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

type CoverageEvent struct {
	Provider string `json:"provider"`
	Channel  string `json:"channel"`
	EventID  int    `json:"event_id"`
	Records  int    `json:"records"`
	Mapped   int    `json:"mapped"`
}

func (c *ParseCoverage) Incomplete() bool {
	return c != nil && (len(c.Notes) > 0 || c.Unmapped > 0 || c.Undated > 0 || c.RecordsFailed > 0 || c.ChunksFailed > 0 || c.LimitReached || c.UnlistedRecords > 0)
}
