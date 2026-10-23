package report

// External is Appendix D: the opinions of outside services about indicators
// (today: file hashes) read from the evidence.
//
// It states how much of the case was allowed to leave the server, whether or
// not anything did, so a reader of the report can tell "not checked" from
// "checked and not known".
type External struct {
	// EgressLevel is the case's level when the report was generated.
	EgressLevel string
	// EgressDescription says in words what that level allows.
	EgressDescription string
	// Providers lists the services that answered, with their counts.
	VirusTotal ExternalProvider
}

// ExternalProvider is one service's answers.
type ExternalProvider struct {
	// Answered is the number of hashes the service gave an answer for
	// (known or not known); Errors is the number it could not answer.
	Answered int
	Known    int
	Unknown  int
	Errors   int
	// Rows are the listed answers, most-detected first; Omitted were cut.
	Rows    []ExternalRow
	Omitted int
}

// ExternalRow is one hash and what the service said.
type ExternalRow struct {
	Indicator     string
	IndicatorType string
	// Verdict is a neutral statement of the service's answer, never a
	// conclusion: "64 of 67 engines flagged it", "not known", "no answer".
	Verdict      string
	Label        string
	FileType     string
	ReportedName string
	LastAnalysis string
	CheckedAt    string
	// Events are the events whose fields held the hash (a few, then a count).
	Events string
	Link   string
}
