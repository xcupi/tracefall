package mssqlxe

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// Binary files bypass the generic Go parse-worker: that worker's inherited
// RLIMIT_AS is unsuitable for CoreCLR. This path always starts its own mandatory
// network-disabled sandbox. The ingestion worker gate still applies.
func (p Parser) OwnSandbox(path string) bool {
	s := strings.ToLower(path)
	return strings.HasSuffix(s, ".xel") || strings.HasSuffix(s, ".sqlaudit")
}
func cleanPath(path string, dir bool) (string, error) {
	if !filepath.IsAbs(path) || strings.Contains(path, "://") {
		return "", fmt.Errorf("absolute local path required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if resolved != filepath.Clean(path) {
		return "", fmt.Errorf("symlink path refused")
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if dir != st.IsDir() || (!dir && !st.Mode().IsRegular()) {
		return "", fmt.Errorf("regular file/directory required")
	}
	return path, nil
}
func (p Parser) binary(path string, c parsers.ParseContext) (parsers.ParseResult, error) {
	var zero parsers.ParseResult
	if p.Audit && os.Getenv("TRACEFALL_MSSQL_AUDIT_EXPERIMENTAL") != "1" {
		return zero, fmt.Errorf("mssqlxe: native binary SQL Audit NOT-VERIFIED; explicit TRACEFALL_MSSQL_AUDIT_EXPERIMENTAL=1 required")
	}
	reader, err := cleanPath(os.Getenv("TRACEFALL_MSSQL_READER"), false)
	if err != nil {
		return zero, fmt.Errorf("mssqlxe: reader unavailable: configure TRACEFALL_MSSQL_READER")
	}
	runtime, err := cleanPath(os.Getenv("TRACEFALL_MSSQL_DOTNET_ROOT"), true)
	if err != nil {
		return zero, fmt.Errorf("mssqlxe: reader unavailable: configure TRACEFALL_MSSQL_DOTNET_ROOT")
	}
	path, err = cleanPath(path, false)
	if err != nil {
		return zero, err
	}
	input, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer input.Close()
	st, err := input.Stat()
	if err != nil {
		return zero, err
	}
	if st.Size() > 1<<30 {
		return zero, fmt.Errorf("binary input cap")
	}
	h := sha256.New()
	if _, err = io.Copy(h, input); err != nil {
		return zero, err
	}
	sourceHash := fmt.Sprintf("%x", h.Sum(nil))
	sandbox, err := exec.LookPath("bwrap")
	if err != nil {
		return zero, fmt.Errorf("mssqlxe: reader unavailable: mandatory bubblewrap sandbox")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	args := []string{"--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"}
	for _, d := range []string{"/usr", "/lib", "/lib64"} {
		args = append(args, "--ro-bind-try", d, d)
	}
	args = append(args, "--ro-bind", runtime, "/runtime", "--ro-bind", filepath.Dir(reader), "/reader", "--ro-bind", path, "/evidence", "--chdir", "/tmp", "/runtime/dotnet", "/reader/"+filepath.Base(reader), "/evidence")
	cmd := exec.CommandContext(ctx, sandbox, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "DOTNET_EnableDiagnostics=0", "DOTNET_GCHeapHardLimit=0x10000000", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1", "DOTNET_CLI_TELEMETRY_OPTOUT=1", "HOME=/tmp", "TMPDIR=/tmp"}
	cmd.WaitDelay = 2 * time.Second
	// No untrusted stderr is put into analyst-facing messages (it can contain SQL).
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return zero, err
	}
	if err = cmd.Start(); err != nil {
		return zero, fmt.Errorf("reader sandbox unavailable: %w", err)
	}
	r, decodeErr := p.decode(stdout, st.Size(), sourceHash, c)
	if decodeErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if decodeErr != nil {
		return zero, decodeErr
	}
	if waitErr != nil {
		return zero, fmt.Errorf("mssqlxe: offline reader failed (unsupported/corrupt/limit); no partial success")
	}
	input.Seek(0, 0)
	h.Reset()
	if _, err = io.Copy(h, input); err != nil || fmt.Sprintf("%x", h.Sum(nil)) != sourceHash {
		return zero, fmt.Errorf("mssqlxe: source changed")
	}
	return r, nil
}

type typedValue struct {
	Type             string          `json:"type"`
	Value            json.RawMessage `json:"value"`
	ActivityID       string          `json:"activity_id"`
	ActivitySequence string          `json:"activity_sequence"`
}
type readerRow struct {
	Kind       string                `json:"kind"`
	SourceHash string                `json:"source_sha256"`
	SourceSize string                `json:"source_size"`
	Schema     int                   `json:"schema"`
	Reader     string                `json:"reader"`
	Checksum   bool                  `json:"checksum"`
	Status     string                `json:"status"`
	Records    int                   `json:"records"`
	Ordinal    string                `json:"ordinal"`
	Name       string                `json:"name"`
	UUID       string                `json:"uuid"`
	Timestamp  string                `json:"timestamp"`
	Start      string                `json:"start_offset"`
	End        string                `json:"end_offset"`
	Size       string                `json:"size"`
	Fields     map[string]typedValue `json:"fields"`
	Actions    map[string]typedValue `json:"actions"`
}

func (p Parser) decode(input io.Reader, size int64, hash string, c parsers.ParseContext) (parsers.ParseResult, error) {
	r := parsers.ParseResult{Coverage: &model.ParseCoverage{}}
	lr := &io.LimitedReader{R: input, N: maxBytes + 1}
	s := bufio.NewScanner(lr)
	s.Buffer(make([]byte, 4096), maxLine)
	header, final := false, false
	for s.Scan() {
		raw := s.Text()
		var row readerRow
		if err := json.Unmarshal([]byte(raw), &row); err != nil {
			return r, fmt.Errorf("invalid reader JSON")
		}
		if final {
			return r, fmt.Errorf("data after final")
		}
		switch row.Kind {
		case "header":
			if row.SourceHash != hash || row.SourceSize != strconv.FormatInt(size, 10) {
				return r, fmt.Errorf("reader source mismatch")
			}
			if header || row.Schema != 1 || row.Reader != "XELite/2024.2.5.1" || !row.Checksum {
				return r, fmt.Errorf("invalid reader header")
			}
			header = true
		case "event":
			if !header || len(r.Events) >= maxRecords {
				return r, fmt.Errorf("reader record cap/header")
			}
			ordinal, err := strconv.Atoi(row.Ordinal)
			if err != nil || ordinal != len(r.Events)+1 || row.Name == "" {
				return r, fmt.Errorf("invalid ordinal/name")
			}
			start, a := strconv.ParseInt(row.Start, 10, 64)
			end, b := strconv.ParseInt(row.End, 10, 64)
			span, d := strconv.ParseInt(row.Size, 10, 64)
			if a != nil || b != nil || d != nil || start < 0 || end <= start || end > size || span != end-start {
				return r, fmt.Errorf("reader offsets out of bounds")
			}
			if _, err := time.Parse(time.RFC3339Nano, row.Timestamp); err != nil {
				return r, fmt.Errorf("invalid XE instant")
			}
			f := map[string]string{"event_name": row.Name}
			activityID, activitySeq := "", ""
			for _, m := range []map[string]typedValue{row.Fields, row.Actions} {
				for k, v := range m {
					if v.Type == "" {
						return r, fmt.Errorf("untyped reader value")
					}
					var text string
					if json.Unmarshal(v.Value, &text) != nil {
						text = string(v.Value)
					}
					f[k] = text
					if k == "attach_activity_id" && v.ActivityID != "" {
						activityID = v.ActivityID
						activitySeq = v.ActivitySequence
					}
				}
			}
			p.append(&r, c, f, raw, row.Timestamp)
			e := &r.Events[len(r.Events)-1]
			e.Extra["sql_evidence_form"] = "native_xel"
			if p.Audit {
				e.Extra["sql_evidence_form"] = "native_sqlaudit_experimental_NOT_VERIFIED"
			}
			e.Extra["sql_source_sha256"] = hash
			e.Extra["sql_xe_start_offset"] = row.Start
			e.Extra["sql_xe_end_offset"] = row.End
			e.Extra["sql_xe_size"] = row.Size
			e.Extra["sql_reader"] = "XELite/2024.2.5.1; checksum=true"
			e.Extra["sql_isolation"] = "bubblewrap network off; read-only runtime/reader/evidence; 40s deadline; 16MiB output; no total-process hard-memory bound"
			if activityID != "" {
				e.Extra["sql_activity_id"] = activityID
				e.Extra["sql_activity_sequence"] = activitySeq
			}
		case "final":
			if !header || row.Status != "complete" || row.Records != len(r.Events) {
				return r, fmt.Errorf("invalid final count/status")
			}
			final = true
		default:
			return r, fmt.Errorf("unknown reader message")
		}
	}
	if s.Err() != nil || lr.N <= 0 {
		return r, fmt.Errorf("reader output/line cap or IO error")
	}
	if !header || !final {
		return r, fmt.Errorf("reader missing terminal status")
	}
	r.Coverage.Notes = []string{"Offline XELite/2024.2.5.1 with checksum verification; no hard total-process memory bound; selective capture/rollover limit completeness"}
	if p.Audit {
		r.Coverage.Notes = append(r.Coverage.Notes, "Native binary SQL Audit experimental NOT-VERIFIED; genuine fixture still required")
	}
	r.Raw = append(r.Raw, model.RawEvidence{SourceReference: "reader:coverage", Raw: fmt.Sprintf("XELite/2024.2.5.1 checksum=true; complete records=%d; no hard process-memory bound; binary audit NOT-VERIFIED", len(r.Events))})
	return r, nil
}
