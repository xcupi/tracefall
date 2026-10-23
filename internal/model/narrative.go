package model

import "time"

// Narrative is a draft summary of a case's findings written by a language
// model, and everything needed to judge it: where the request went, exactly
// what was sent, what came back, and what was kept.
//
// It is not evidence and not a finding. It is kept apart from both and is
// shown only in a clearly labelled place.
type Narrative struct {
	ID     string `json:"id"`
	CaseID string `json:"case_id"`
	// Status is NarrativeOK or NarrativeError.
	Status string `json:"status"`
	// Error is a safe, human-readable reason when Status is "error".
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`

	// Destination is the host the request went to, Local whether that is this
	// machine, and Model the model asked.
	Destination string `json:"destination"`
	Local       bool   `json:"local"`
	Model       string `json:"model"`

	// PayloadSystem and PayloadUser are the exact texts sent, after
	// pseudonymization, so that anyone can see what left. PayloadSHA256 is the
	// hash of both, as recorded in the audit trail when they were sent.
	PayloadSystem string `json:"payload_system"`
	PayloadUser   string `json:"payload_user"`
	PayloadSHA256 string `json:"payload_sha256"`

	// RawAnswer is what the model returned, tokens and all.
	RawAnswer string `json:"raw_answer,omitempty"`
	// SentencesJSON are the sentences that passed validation, names restored,
	// each with what it cites. Rejected counts the lines that did not.
	SentencesJSON string `json:"sentences"`
	Rejected      int    `json:"rejected"`
	ReasonsJSON   string `json:"reasons,omitempty"`

	// FindingIDs are the findings the request covered, in citation order.
	FindingIDs       []string `json:"finding_ids"`
	PromptTokens     int      `json:"prompt_tokens"`
	CompletionTokens int      `json:"completion_tokens"`
	RequestedBy      string   `json:"requested_by"`
}

const (
	NarrativeOK    = "ok"
	NarrativeError = "error"
)
