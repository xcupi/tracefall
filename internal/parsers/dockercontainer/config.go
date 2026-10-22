package dockercontainer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"tracefall/internal/cmdsem"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

const (
	maxJSONFile = 16 << 20 // config.v2.json / hostconfig.json
	maxListText = 8192     // one joined list in Extra
)

const configOutcome = "configuration as stored by the engine; it does not show what ran inside the container"

// secretName is the rule for an environment variable NAME that suggests the
// value is a secret. Names only are ever reported.
var secretName = regexp.MustCompile(`(?i)(pass(word)?|secret|token|key|credential|dsn|connection)`)

func readJSONFile(absPath string) ([]byte, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxJSONFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxJSONFile {
		return nil, fmt.Errorf("dockercontainer: file larger than %d bytes", maxJSONFile)
	}
	return bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), nil
}

// setList joins items with commas into Extra[key], bounded.
func setList(extra map[string]string, key string, items []string) {
	s := strings.Join(items, ",")
	if c, cut := clipRunes(s, maxListText); cut {
		s = c
		extra[key+"_truncated"] = "true"
	}
	extra[key] = s
}

func recordedTime(s string) (string, bool) {
	if s == "" || strings.HasPrefix(s, zeroTime) {
		return "", false
	}
	return s, true
}

const zeroTime = "0001-01-01T00:00:00"

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// portList renders host_ip:host_port->container_port, sorted.
func portList(m map[string][]portBinding) []string {
	var out []string
	for cport, bs := range m {
		for _, b := range bs {
			out = append(out, b.HostIP+":"+b.HostPort+"->"+cport)
		}
	}
	sort.Strings(out)
	return out
}

type configFile struct {
	ID           string
	Created      string
	Path         string
	Args         []string
	Name         string
	Driver       string
	OS           string
	LogPath      string
	RestartCount int
	Image        string
	State        struct {
		Status     string
		Running    bool
		Paused     bool
		Restarting bool
		Dead       bool
		ExitCode   int
		Error      string
		StartedAt  string
		FinishedAt string
	}
	Config struct {
		User       string
		Image      string
		Env        []string
		Entrypoint json.RawMessage
	}
	NetworkSettings struct {
		Ports map[string][]portBinding
	}
	MountPoints map[string]struct {
		Type        string
		Source      string
		Name        string
		Destination string
		RW          *bool
	}
}

// stringOrList reads a JSON value that is a string (old engines) or an array.
func stringOrList(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var l []string
	if json.Unmarshal(raw, &l) == nil {
		return l
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return []string{s}
	}
	return nil
}

// secretFlag matches an option whose NEXT argument is a secret (--token X).
// cmdsem.Redact covers the --opt=value and known-tool shapes; an exec-form
// argument list has the value as a separate element, which it cannot see.
var secretFlag = regexp.MustCompile(`(?i)^--?(?:[a-z0-9_-]*-)?(?:pass(?:word)?|pwd|secret|token|api-?key|access-?key|credentials?)$`)

// redactArgs masks the argument that follows a secret-looking option.
func redactArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i+1 < len(out); i++ {
		if secretFlag.MatchString(out[i]) {
			out[i+1] = "<redacted>"
			i++
		}
	}
	return out
}

func envName(entry string) string {
	if i := strings.IndexByte(entry, '='); i >= 0 {
		return entry[:i]
	}
	return entry
}

// sanitizedRaw is the file with every Config.Env value removed. It is not the
// untouched file; the original stays in the evidence store.
func sanitizedRaw(b []byte) string {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var top map[string]any
	if dec.Decode(&top) != nil {
		return "{}"
	}
	if c, ok := top["Config"].(map[string]any); ok {
		if env, ok := c["Env"].([]any); ok {
			for i, v := range env {
				s, _ := v.(string)
				env[i] = envName(s) + "=<value not stored>"
			}
		}
	}
	scrub := func(m map[string]any, key string) {
		args, ok := m[key].([]any)
		if !ok {
			return
		}
		strs := make([]string, len(args))
		for i, v := range args {
			strs[i], _ = v.(string)
		}
		red := redactArgs(strs)
		for i := range args {
			args[i] = cmdsem.Redact(red[i])
		}
	}
	scrub(top, "Args")
	if c, ok := top["Config"].(map[string]any); ok {
		scrub(c, "Cmd")
		scrub(c, "Entrypoint")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(top) != nil {
		return "{}"
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func parseConfig(absPath, id string) (parsers.ParseResult, error) {
	b, err := readJSONFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		return parsers.ParseResult{}, fmt.Errorf("dockercontainer: config.v2.json is not a JSON object: %w", err)
	}
	for _, k := range []string{"ID", "Config", "State"} {
		if _, ok := keys[k]; !ok {
			return parsers.ParseResult{}, fmt.Errorf("dockercontainer: config.v2.json has no %q key", k)
		}
	}
	var c configFile
	if err := json.Unmarshal(b, &c); err != nil {
		return parsers.ParseResult{}, fmt.Errorf("dockercontainer: config.v2.json: %w", err)
	}

	x := map[string]string{
		"container_id":    id,
		"container_name":  strings.TrimPrefix(c.Name, "/"),
		"image":           c.Config.Image,
		"image_id":        c.Image,
		"user":            c.Config.User,
		"exit_code":       strconv.Itoa(c.State.ExitCode),
		"restart_count":   strconv.Itoa(c.RestartCount),
		"driver":          c.Driver,
		"os":              c.OS,
		"log_path":        c.LogPath,
		"records_outcome": configOutcome,
		// the raw record kept with the event is not the untouched file
		"raw_env_values_removed": "true",
	}
	if !strings.EqualFold(c.ID, id) {
		x["id_in_file"] = c.ID
	}
	cmd := strings.TrimSpace(strings.Join(append([]string{c.Path}, redactArgs(c.Args)...), " "))
	x["command"] = cmdsem.Redact(cmd)
	x["entrypoint"] = cmdsem.Redact(strings.Join(redactArgs(stringOrList(c.Config.Entrypoint)), " "))
	for k, v := range map[string]string{"container_created": c.Created, "state_started_at": c.State.StartedAt, "state_finished_at": c.State.FinishedAt} {
		if t, ok := recordedTime(v); ok {
			x[k] = t
		}
	}
	if s := c.State.Error; s != "" {
		x["state_error"], _ = clipRunes(cmdsem.Redact(s), 512)
	}
	// State: the engine's own order of precedence.
	switch {
	case c.State.Status != "":
		x["state"] = c.State.Status
	case c.State.Running && c.State.Paused:
		x["state"] = "paused"
	case c.State.Running:
		x["state"] = "running"
	case c.State.Restarting:
		x["state"] = "restarting"
	case c.State.Dead:
		x["state"] = "dead"
	case x["state_started_at"] == "":
		x["state"] = "created"
	default:
		x["state"] = "exited"
	}

	names := make([]string, 0, len(c.Config.Env))
	var secrets []string
	for _, e := range c.Config.Env {
		n := envName(e)
		names = append(names, n)
		if secretName.MatchString(n) {
			secrets = append(secrets, n)
		}
	}
	sort.Strings(names)
	sort.Strings(secrets)
	setList(x, "env_names", names)
	setList(x, "env_secret_names", secrets)

	ports := portList(c.NetworkSettings.Ports)
	src := "NetworkSettings.Ports"
	if len(ports) == 0 {
		// A stopped container has no live ports; the bindings it was created
		// with are in the sibling hostconfig.json, when it was collected.
		if hb, err := readJSONFile(filepath.Join(filepath.Dir(absPath), "hostconfig.json")); err == nil {
			var h struct{ PortBindings map[string][]portBinding }
			if json.Unmarshal(hb, &h) == nil {
				if p := portList(h.PortBindings); len(p) > 0 {
					ports, src = p, "hostconfig.json"
				}
			}
		}
	}
	setList(x, "published_ports", ports)
	if len(ports) > 0 {
		x["published_ports_source"] = src
	}

	var mounts []string
	for _, m := range c.MountPoints {
		s := m.Source
		if s == "" {
			s = m.Name
		}
		t := m.Type
		if t == "" {
			t = "unspecified"
		}
		line := t + ":" + s + "->" + m.Destination
		if m.RW != nil && !*m.RW {
			line += ":ro"
		}
		mounts = append(mounts, line)
	}
	sort.Strings(mounts)
	setList(x, "mounts", mounts)

	ref := "config.v2.json"
	ev := model.Event{
		EventType:       model.EventContainerConfig,
		ArtifactType:    model.ArtifactContainerConfig,
		Parser:          parserName,
		FilePath:        id + "/config.v2.json",
		SourceReference: ref,
		Confidence:      1.0,
		Extra:           x,
	}
	res := parsers.ParseResult{
		Events: []model.Event{ev},
		Raw:    []model.RawEvidence{{SourceReference: ref, Raw: sanitizedRaw(b)}},
		Coverage: &model.ParseCoverage{
			RecordsRead: 1, Mapped: 1,
		},
	}
	return res, nil
}
