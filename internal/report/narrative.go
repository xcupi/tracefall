package report

// Narrative is Appendix E: a draft summary written by a language model.
//
// It is labelled as a draft and as not evidence wherever it appears, it names
// the model and where the request went, and it says what was and was not
// checked about it. When none was requested the appendix says so.
type Narrative struct {
	// Requested: a request was made for this case. Usable: it produced
	// sentences that passed validation. A request that produced nothing usable
	// is still stated, because case data was sent.
	Requested bool
	Usable    bool

	RequestedAt string
	// Destination is the host the request went to; Local is true when that is
	// the machine the report was made on.
	Destination string
	Local       bool
	Model       string
	Error       string

	Sentences []NarrativeSentence
	// Rejected lines were dropped by validation; Reasons says why, by class.
	Rejected int
	Reasons  []KV

	PayloadSHA256    string
	PromptTokens     int
	CompletionTokens int
	// Stale: the case's findings are no longer the ones the draft covered.
	Stale bool
}

// NarrativeSentence is one sentence of the draft and what it cites.
type NarrativeSentence struct {
	Text string
	// Cites are labels such as "F-003" or "event 3f2a..." .
	Cites string
}
