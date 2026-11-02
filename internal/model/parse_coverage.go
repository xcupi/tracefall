package model

import "fmt"

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

	// Tables is the table-level census of a database parser (SRUM): every
	// provider table seen, its live rows and whether any row of it was
	// interpreted. TablesUnlisted counts tables beyond the census limit.
	// DatabaseState and CleanShutdown say how the database was last closed;
	// CleanShutdown is nil when the parser does not record it.
	Tables         []CoverageTable `json:"tables,omitempty"`
	TablesUnlisted int             `json:"tables_unlisted,omitempty"`
	DatabaseState  string          `json:"database_state,omitempty"`
	CleanShutdown  *bool           `json:"clean_shutdown,omitempty"`

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

	// Ntfs is the filesystem-specific account of an $MFT, $UsnJrnl:$J or
	// $LogFile. Nil means not recorded (older imports), never complete.
	Ntfs *NtfsCoverage `json:"ntfs,omitempty"`
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

// CoverageTable is one table of a database source: Rows live records,
// Deleted records the engine marks deleted (never emitted), Interpreted whether
// the parser turns the table's rows into events (Event names the type).
type CoverageTable struct {
	Table       string `json:"table"`
	Rows        int    `json:"rows"`
	Interpreted bool   `json:"interpreted"`
	Event       string `json:"event,omitempty"`
	Deleted     int    `json:"deleted,omitempty"`
}

// TableSummary is the census as one sentence: how many tables, how many were
// interpreted and how many rows were not. It is empty when no census was
// recorded, so a source without one never reads as fully counted.
func (c *ParseCoverage) TableSummary() string {
	if c == nil || (len(c.Tables) == 0 && c.TablesUnlisted == 0) {
		return ""
	}
	n := len(c.Tables) + c.TablesUnlisted
	interpreted, rows := 0, 0
	for _, t := range c.Tables {
		if t.Interpreted {
			interpreted++
		} else {
			rows += t.Rows
		}
	}
	noun := "tables"
	if n == 1 {
		noun = "table"
	}
	s := fmt.Sprintf("%d %s, %d interpreted, %d rows not interpreted", n, noun, interpreted, rows)
	if c.TablesUnlisted > 0 {
		s += fmt.Sprintf("; %d more tables not listed, so these counts are lower bounds", c.TablesUnlisted)
	}
	return s
}

type CoverageEvent struct {
	Provider string `json:"provider"`
	Channel  string `json:"channel"`
	EventID  int    `json:"event_id"`
	Records  int    `json:"records"`
	Mapped   int    `json:"mapped"`
}

// Measured reports whether parser metrics were recorded, independently of
// descriptive metadata and Incomplete's caveats. Nil and metadata-only coverage
// are not measurements. A bare zero object remains measured for compatibility:
// historical JSON cannot distinguish that recorded zero from absent counters.
// EmittedEvents, including an explicit zero, is an unambiguous measurement.
func (c *ParseCoverage) Measured() bool {
	if c == nil {
		return false
	}
	if c.EmittedEvents != nil || c.RecordsRead != 0 || c.Mapped != 0 || c.Unmapped != 0 ||
		c.Undated != 0 || c.RecordsFailed != 0 || c.ChunksRead != 0 || c.ChunksFailed != 0 || c.LimitReached ||
		len(c.ByEvent) > 0 || c.UnlistedRecords != 0 || len(c.Tables) > 0 || c.TablesUnlisted != 0 || c.Ntfs != nil {
		return true
	}
	return c.CompanionOf == "" && c.HiveReplay == nil && len(c.Notes) == 0
}

func (c *ParseCoverage) Incomplete() bool {
	return c != nil && (len(c.Notes) > 0 || c.Unmapped > 0 || c.Undated > 0 || c.RecordsFailed > 0 || c.ChunksFailed > 0 || c.LimitReached || c.UnlistedRecords > 0 || c.TablesUnlisted > 0 || c.Ntfs.incomplete())
}
