package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tracefall/internal/credentials"
	"tracefall/internal/enrich/llm"
)

// One shared pointer across WithActor/WithRequest copies. A lease pins a
// provider for a whole narrative, including preparation, retries and storage.
type llmConfiguration struct {
	mu                            sync.Mutex
	api                           llm.Chatter
	codex                         *llm.CodexCLI
	preference, environment, path string
	state                         string
	prompt                        llm.DevicePrompt
	deadline                      time.Time
	authorizationTimeout          time.Duration
	cancel                        context.CancelFunc
	done                          chan struct{}
	active                        int
	verified                      bool
}

var errLLMConfigurationBusy = errors.New("ChatGPT authorization or verification is in progress; wait or cancel authorization before starting a summary")

func newLLMConfiguration() *llmConfiguration {
	return &llmConfiguration{api: llm.None{}, state: "not_connected"}
}
func (m *llmConfiguration) effectiveLocked() string {
	if m.environment != "" {
		if m.environment == "codex-cli" || m.environment == "openai-compatible" {
			return m.environment
		}
		return "none"
	}
	if m.preference != "" {
		return m.preference
	}
	return "openai-compatible"
}

func (m *llmConfiguration) clientLocked() llm.Chatter {
	switch m.effectiveLocked() {
	case "codex-cli":
		if m.codex != nil {
			return m.codex
		}
	case "openai-compatible":
		return m.api
	}
	return llm.None{}
}
func (m *llmConfiguration) snapshot() llm.Chatter {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clientLocked()
}
func (m *llmConfiguration) acquire() (llm.Chatter, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		return nil, nil, errLLMConfigurationBusy
	}
	m.active++
	return m.clientLocked(), func() { m.mu.Lock(); m.active--; m.mu.Unlock() }, nil
}

// ConfigureChatGPT is startup-only. It never borrows the operator's sign-in.
// Explicit environment selection wins over the saved non-secret preference.
func (s *Service) ConfigureChatGPT(dataDir, binary, model, envProvider string, apiClient llm.Chatter) error {
	m := s.llm
	m.mu.Lock()
	defer m.mu.Unlock()
	if apiClient == nil {
		apiClient = llm.None{}
	}
	m.api = apiClient
	m.environment = strings.ToLower(strings.TrimSpace(envProvider))
	if dataDir == "" {
		return errors.New("ChatGPT integration storage is unavailable")
	}
	root, absErr := filepath.Abs(filepath.Join(dataDir, ".integrations"))
	if absErr != nil {
		return errors.New("could not resolve integration storage")
	}
	// Refuse symlinks for the server-owned integration root and Codex home.
	for _, p := range []string{root, filepath.Join(root, "codex")} {
		if st, err := os.Lstat(p); err == nil && (st.Mode()&os.ModeSymlink != 0 || !st.IsDir()) {
			return errors.New("integration storage must be a private directory, not a symlink")
		}
		if err := os.MkdirAll(p, 0700); err != nil {
			return errors.New("could not create integration storage")
		}
		if err := os.Chmod(p, 0700); err != nil {
			return errors.New("could not protect integration storage")
		}
	}
	m.path = filepath.Join(root, "llm-provider")
	pref, err := credentials.Read(m.path)
	if err != nil {
		return errors.New("could not load provider preference")
	}
	if pref != "" && pref != "none" && pref != "codex-cli" && pref != "openai-compatible" {
		return errors.New("invalid saved provider preference")
	}
	m.preference = pref
	m.codex = llm.NewCodexCLI(binary, model)
	m.codex.CodexHome = filepath.Join(root, "codex")
	return nil
}

type chatGPTInfo struct {
	State              string `json:"state"`
	Available          bool   `json:"available"`
	AuthorizationURL   string `json:"authorization_url,omitempty"`
	UserCode           string `json:"user_code,omitempty"`
	ExpiresAt          string `json:"expires_at,omitempty"`
	RequestVerified    bool   `json:"request_verified"`
	Preference         string `json:"preference"`
	EffectiveProvider  string `json:"effective_provider"`
	EnvironmentManaged bool   `json:"environment_managed"`
	Busy               bool   `json:"busy"`
}

func (m *llmConfiguration) infoLocked(ctx context.Context) chatGPTInfo {
	state := m.state
	if m.cancel == nil && m.codex != nil {
		st, err := m.codex.LoginStatus(ctx)
		if err != nil {
			state = "failed"
			m.verified = false
		} else if st == "signed_in" {
			state = st
		} else {
			m.verified = false
			if state == "signed_in" || state == "not_connected" || state == "" {
				state = st
			}
		}
		m.state = state
	}
	st := chatGPTInfo{State: state, Available: m.codex.AuthorizationAvailable(), RequestVerified: m.verified, Preference: m.preference, EffectiveProvider: m.effectiveLocked(), EnvironmentManaged: m.environment != "", Busy: m.cancel != nil || m.active > 0}
	if state == "waiting" {
		st.AuthorizationURL = m.prompt.URL
		st.UserCode = m.prompt.Code
		st.ExpiresAt = m.deadline.UTC().Format(time.RFC3339)
	}
	return st
}
func (h *handlers) getChatGPTIntegration(w http.ResponseWriter, r *http.Request) {
	m := h.svc.llm
	m.mu.Lock()
	info := m.infoLocked(r.Context())
	m.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, info)
}
func (h *handlers) selectChatGPTProvider(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider string `json:"provider"`
	}
	if !integrationJSON(w, r, &body) {
		return
	}
	if body.Provider != "codex-cli" && body.Provider != "openai-compatible" && body.Provider != "none" {
		writeError(w, 400, "Choose codex-cli, openai-compatible or none")
		return
	}
	m := h.svc.llm
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.environment != "" {
		writeError(w, 409, "TRACEFALL_LLM_PROVIDER overrides UI selection. Change it in the server environment and restart.")
		return
	}
	if m.active > 0 || m.cancel != nil {
		writeError(w, 409, "Wait for ongoing summaries, authorization or verification before changing provider")
		return
	}
	if m.path == "" {
		writeError(w, 503, "Integration storage unavailable")
		return
	}
	if err := credentials.Write(m.path, body.Provider); err != nil {
		writeError(w, 500, "Could not save provider preference")
		return
	}
	m.preference = body.Provider
	h.svc.auditSecurity("", "integration_provider_selected", "integration", "chatgpt", principalFrom(r).Username, "AI summary provider preference changed; no request sent and no case policy changed.")
	writeJSON(w, 200, m.infoLocked(r.Context()))
}
func (h *handlers) authorizeChatGPTIntegration(w http.ResponseWriter, r *http.Request) {
	m := h.svc.llm
	m.mu.Lock()
	if !m.codex.AuthorizationAvailable() {
		m.mu.Unlock()
		writeError(w, 503, "Install the official Codex CLI on the server first")
		return
	}
	if m.active > 0 || m.cancel != nil {
		m.mu.Unlock()
		writeError(w, 409, "A summary or integration operation is in progress")
		return
	}
	timeout := m.authorizationTimeout
	if timeout <= 0 || timeout > 15*time.Minute {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	m.cancel = cancel
	m.done = make(chan struct{})
	done := m.done
	m.state = "authorizing"
	m.prompt = llm.DevicePrompt{}
	m.verified = false
	m.deadline = time.Now().Add(timeout)
	client := m.codex
	m.mu.Unlock()
	h.svc.auditSecurity("", "integration_authorization_started", "integration", "chatgpt", principalFrom(r).Username, "Started official Codex device authorization in isolated server storage. No model request sent.")
	go func() {
		err := client.DeviceLogin(ctx, func(p llm.DevicePrompt) {
			m.mu.Lock()
			if ctx.Err() == nil {
				m.prompt = p
				m.state = "waiting"
			}
			m.mu.Unlock()
		})
		m.mu.Lock()
		defer m.mu.Unlock()
		m.prompt = llm.DevicePrompt{}
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			m.state = "expired"
		case errors.Is(ctx.Err(), context.Canceled):
			m.state = "cancelled"
		case err != nil:
			m.state = "failed"
		default:
			m.state = "signed_in"
		}
		cancel()
		m.cancel = nil
		close(done)
	}()
	writeJSON(w, 202, map[string]string{"state": "authorizing"})
}
func (h *handlers) cancelChatGPTIntegration(w http.ResponseWriter, r *http.Request) {
	m := h.svc.llm
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	// Verification is tied to its HTTP request, not the auth cancel endpoint.
	if cancel == nil || done == nil {
		m.mu.Unlock()
		w.WriteHeader(204)
		return
	}
	cancel()
	m.mu.Unlock()
	select {
	case <-done:
		w.WriteHeader(204)
	case <-r.Context().Done():
		writeError(w, 408, "Cancellation still in progress")
	}
}
func (h *handlers) disconnectChatGPTIntegration(w http.ResponseWriter, r *http.Request) {
	m := h.svc.llm
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active > 0 || m.cancel != nil {
		writeError(w, 409, "Cancel authorization and wait for ongoing requests before disconnecting")
		return
	}
	m.verified = false
	m.prompt = llm.DevicePrompt{}
	if m.codex == nil {
		writeError(w, 503, "Integration storage unavailable")
		return
	}
	if err := m.codex.Logout(r.Context()); err != nil {
		m.state = "failed"
		writeError(w, 502, "Could not confirm Codex disconnect; retry after checking server setup")
		return
	}
	m.state = "not_connected"
	h.svc.auditSecurity("", "integration_disconnected", "integration", "chatgpt", principalFrom(r).Username, "Disconnected the isolated Tracefall Codex session; personal sessions and stored case drafts unchanged. Backups may retain credentials.")
	writeJSON(w, 200, m.infoLocked(r.Context()))
}
func (h *handlers) verifyChatGPTIntegration(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Acknowledge bool `json:"acknowledge"`
	}
	if !integrationJSON(w, r, &body) {
		return
	}
	if !body.Acknowledge {
		writeError(w, 403, "Authorize a fixed synthetic request to OpenAI and its quota usage; no case data is sent")
		return
	}
	m := h.svc.llm
	m.mu.Lock()
	if m.active > 0 || m.cancel != nil {
		m.mu.Unlock()
		writeError(w, 409, "An integration operation or summary is in progress")
		return
	}
	if m.codex == nil {
		m.mu.Unlock()
		writeError(w, 409, "Authorize ChatGPT first")
		return
	}
	st, err := m.codex.LoginStatus(r.Context())
	if err != nil || st != "signed_in" {
		m.mu.Unlock()
		writeError(w, 409, "Authorize ChatGPT first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	m.cancel = cancel
	m.done = nil
	m.verified = false
	client := m.codex
	m.mu.Unlock()
	h.svc.auditSecurity("", "integration_verification_requested", "integration", "chatgpt", principalFrom(r).Username, "Authorized one fixed synthetic model request through Codex; no case data. Account limits and quota apply.")
	_, err = client.Chat(ctx, []llm.Message{{Role: "user", Content: "Reply exactly TRACEFALL_TEST_OK. This is a synthetic Tracefall connection test. No case data is included."}})
	m.mu.Lock()
	m.cancel = nil
	m.verified = err == nil && ctx.Err() == nil
	verified := m.verified
	cancel()
	m.mu.Unlock()
	if !verified {
		writeError(w, 502, "Request not verified. The request failed or was cancelled; it may have used quota. No raw CLI output is exposed.")
		return
	}
	h.svc.auditSecurity("", "integration_request_verified", "integration", "chatgpt", principalFrom(r).Username, "The fixed synthetic model request succeeded. This does not verify any future request, case summary or data-control setting.")
	writeJSON(w, 200, map[string]bool{"request_verified": true})
}
