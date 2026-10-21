package model

// ParseCoverage records what a parser actually read, separately from timeline
// events. Nil means not recorded (including older imports), never complete.
type ParseCoverage struct {
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
}

type CoverageEvent struct {
	Provider string `json:"provider"`
	Channel  string `json:"channel"`
	EventID  int    `json:"event_id"`
	Records  int    `json:"records"`
	Mapped   int    `json:"mapped"`
}

func (c *ParseCoverage) Incomplete() bool {
	return c != nil && (c.Unmapped > 0 || c.Undated > 0 || c.RecordsFailed > 0 || c.ChunksFailed > 0 || c.LimitReached || c.UnlistedRecords > 0)
}
