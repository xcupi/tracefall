//go:build !unix

package llm

import (
	"context"
	"time"
)

// CodexNotice is shown to the analyst before they acknowledge a request that
// goes through a ChatGPT sign-in.
const CodexNotice = "This request goes to OpenAI through the account the Codex CLI is signed in with."

// CodexCLI is available only where the program can control the process it
// starts; elsewhere it is never configured.
type CodexCLI struct {
	Binary, Model, CodexHome string
	Timeout                  time.Duration
}

var _ Chatter = (*CodexCLI)(nil)

func NewCodexCLI(binary, model string) *CodexCLI { return &CodexCLI{Binary: binary, Model: model} }
func (c *CodexCLI) Configured() bool             { return false }
func (c *CodexCLI) Destination() (string, bool)  { return "chatgpt.com (through the Codex CLI)", false }
func (c *CodexCLI) ModelName() string            { return c.Model }
func (c *CodexCLI) Notice() string               { return CodexNotice }
func (c *CodexCLI) Chat(context.Context, []Message) (Result, error) {
	return Result{}, ErrNotConfigured
}
