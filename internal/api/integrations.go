package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"tracefall/internal/credentials"
	"tracefall/internal/enrich/virustotal"
)

// Shared by request-scoped Service copies. A configuration change cannot race
// a request, and replacing/removing a key must not reset the client's limiter.
type vtConfiguration struct {
	mu          sync.RWMutex
	client      *virustotal.Client
	path        string
	environment bool
	gate        chan struct{}
}

func (v *vtConfiguration) Configured() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.client.Configured()
}

var vtKeyPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// ConfigureVirusTotalStorage is called once, before serving requests. A key in
// the environment takes precedence and cannot be replaced/removed by the UI.
func (s *Service) ConfigureVirusTotalStorage(path, envKey string) error {
	v := s.vt
	v.mu.Lock()
	defer v.mu.Unlock()
	v.path = path
	envKey = strings.TrimSpace(envKey)
	if envKey != "" {
		v.environment = true
		v.client = virustotal.New(envKey)
		return nil
	}
	key, err := credentials.Read(path)
	if err != nil {
		return err
	}
	if key != "" && !vtKeyPattern.MatchString(key) {
		return errors.New("saved VirusTotal credential is invalid; repair or remove the server credential file")
	}
	v.client = virustotal.New(key)
	return nil
}

// The response never includes a key, prefix, suffix, path or hash of a key.
type vtIntegrationInfo struct {
	Configured bool   `json:"configured"`
	Source     string `json:"source"`
	Editable   bool   `json:"editable"`
}

func (v *vtConfiguration) infoLocked() vtIntegrationInfo {
	source := "none"
	if v.environment {
		source = "environment"
	} else if v.client.Configured() {
		source = "saved"
	}
	return vtIntegrationInfo{Configured: v.client.Configured(), Source: source, Editable: v.path != "" && !v.environment}
}
func (h *handlers) getVTIntegration(w http.ResponseWriter, r *http.Request) {
	v := h.svc.vt
	v.mu.RLock()
	info := v.infoLocked()
	v.mu.RUnlock()
	writeJSON(w, 200, info)
}

// Sensitive input has a small strict decoder. Never echo decoder errors or
// request bodies: even a JSON type error can contain the value of a secret.
func integrationJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, 415, "application/json is required")
		return false
	}
	if r.Body == nil {
		writeError(w, 400, "JSON body is required")
		return false
	}
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil {
		writeError(w, 400, "invalid integration settings JSON")
		return false
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		writeError(w, 400, "one JSON object is required")
		return false
	}
	return true
}
func (h *handlers) changeVTIntegration(w http.ResponseWriter, r *http.Request, key string, remove bool) {
	v := h.svc.vt
	if !v.mu.TryLock() {
		writeError(w, 409, "A VirusTotal request is in flight. Wait for it to finish before changing the key.")
		return
	}
	defer v.mu.Unlock()
	if v.environment {
		writeError(w, 409, "VirusTotal is managed by TRACEFALL_VT_API_KEY. Change or remove it in the server environment and restart.")
		return
	}
	if v.path == "" {
		writeError(w, 503, "Credential storage is not configured on this server")
		return
	}
	var err error
	if remove {
		err = credentials.Remove(v.path)
	} else {
		err = credentials.Write(v.path, key)
	}
	if err != nil {
		writeError(w, 500, "Could not update server credential storage; the active key was not changed")
		return
	}
	v.client = v.client.WithKey(key)
	action := "integration_key_saved"
	summary := "VirusTotal credential saved on the server; no provider request was sent."
	if remove {
		action = "integration_key_removed"
		summary = "VirusTotal credential removed from active configuration and server file; stored case results are unchanged."
	}
	h.svc.auditSecurity("", action, "integration", "virustotal", principalFrom(r).Username, summary)
	writeJSON(w, 200, v.infoLocked())
}
func (h *handlers) saveVTIntegration(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key string `json:"api_key"`
	}
	if !integrationJSON(w, r, &body) {
		return
	}
	key := strings.TrimSpace(body.Key)
	if !vtKeyPattern.MatchString(key) {
		writeError(w, 400, "VirusTotal API key must contain exactly 64 hexadecimal characters")
		return
	}
	h.changeVTIntegration(w, r, key, false)
}
func (h *handlers) removeVTIntegration(w http.ResponseWriter, r *http.Request) {
	h.changeVTIntegration(w, r, "", true)
}
func (h *handlers) testVTIntegration(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Acknowledge bool `json:"acknowledge"`
	}
	if !integrationJSON(w, r, &body) {
		return
	}
	if !body.Acknowledge {
		writeError(w, 403, "Confirm sending one public test hash to VirusTotal and using one request of quota; no case data is sent")
		return
	}
	if !h.svc.vt.Configured() {
		writeError(w, 409, "Save a VirusTotal key before testing the connection")
		return
	}
	const publicTestHash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
	h.svc.auditSecurity("", "integration_test_requested", "integration", "virustotal", principalFrom(r).Username, "Authorized a connection test using the fixed public EICAR SHA-256 only; no case data. Local request allowances still apply.")
	_, err := h.svc.vtLookup(r.Context(), publicTestHash)
	message := "VirusTotal accepted the request. No case data was sent. One request was counted."
	code := 200
	if err != nil {
		message = "Could not verify the VirusTotal connection. Check network access and try again."
		code = 502
		var quota *virustotal.QuotaError
		switch {
		case errors.Is(err, virustotal.ErrAuth):
			code = 400
			message = "VirusTotal refused the saved API key. Replace it and try again."
		case errors.Is(err, ErrEnrichDailyLimit), errors.Is(err, ErrEnrichMonthlyLimit):
			code = 429
			message = "The local VirusTotal request allowance is used up; no test request was sent."
		case errors.As(err, &quota):
			code = 429
			message = "VirusTotal reported a rate or quota limit. Wait before testing again."
		case errors.Is(err, virustotal.ErrNotConfigured):
			code = 409
			message = "The VirusTotal key was removed before the test started."
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			code = 408
			message = "The connection test was cancelled or timed out. A request may have used quota."
		}
	}
	h.svc.auditSecurity("", "integration_test_finished", "integration", "virustotal", principalFrom(r).Username, message)
	if code != 200 {
		writeError(w, code, message)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": message})
}
