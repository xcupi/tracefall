//go:build !unix

package llm

import "context"

// DevicePrompt is unavailable where whole-process-group cancellation is not supported.
type DevicePrompt struct{ URL, Code string }

func (c *CodexCLI) LoginStatus(context.Context) (string, error)           { return "failed", ErrNotConfigured }
func (c *CodexCLI) DeviceLogin(context.Context, func(DevicePrompt)) error { return ErrNotConfigured }
func (c *CodexCLI) Logout(context.Context) error                          { return ErrNotConfigured }
func (c *CodexCLI) AuthorizationAvailable() bool                          { return false }
