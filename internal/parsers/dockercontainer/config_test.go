package dockercontainer

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tracefall/internal/parsers"
)

// linuxConfig is config.v2.json laid out as Docker writes it: the secret is a
// fake value that must never appear in any output.
const secretPW = "Zq9-s3cret-Pw"

var linuxConfig = strings.NewReplacer("@ID@", cid, "@PW@", secretPW).Replace(`{"StreamConfig":{},"State":{"Running":true,"Paused":false,"Restarting":false,"OOMKilled":false,"Dead":false,"Pid":4242,"ExitCode":0,"Error":"","StartedAt":"2026-10-22T08:21:00.775908379Z","FinishedAt":"0001-01-01T00:00:00Z","Health":null},` +
	`"ID":"@ID@","Created":"2026-10-22T08:20:59.639438116Z","Managed":false,"Path":"/entry.sh","Args":["--serve","--token","@PW@","--db-password=@PW@"],` +
	`"Config":{"Hostname":"web01","User":"1000","Env":["DB_PASSWORD=@PW@","API_TOKEN=@PW@","APP_MODE=prod","PATH=/usr/bin","AWS_SECRET_ACCESS_KEY=@PW@","DATABASE_DSN=postgres://u:@PW@@db/x","WITHOUT_EQUALS"],"Cmd":["--api-key","@PW@"],"Image":"registry.example.test/team/web:1.4","Entrypoint":["/entry.sh","--init","--secret","@PW@"]},` +
	`"Image":"sha256:` + strings.Repeat("cd34", 16) + `","NetworkSettings":{"Ports":{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"18080"}],"9090/tcp":null}},` +
	`"LogPath":"/var/lib/docker/containers/@ID@/@ID@-json.log","Name":"/web01","Driver":"overlay2","OS":"linux","RestartCount":3,` +
	`"MountPoints":{"/data":{"Source":"/srv/data","Destination":"/data","RW":true,"Type":"bind"},"/cfg":{"Source":"/etc/app","Destination":"/cfg","RW":false,"Type":"bind"},"/var/lib/db":{"Name":"dbvol","Source":"/var/lib/docker/volumes/dbvol/_data","Destination":"/var/lib/db","RW":true,"Type":"volume","Driver":"local"}}}`)

func TestConfig_LinuxFields(t *testing.T) {
	p := writeIn(t, cid, "config.v2.json", linuxConfig)
	r := parse(t, p)
	if len(r.Events) != 1 {
		t.Fatalf("events = %d", len(r.Events))
	}
	e := r.Events[0]
	if e.EventType != "container_config" || e.ArtifactType != "container_config" {
		t.Errorf("types = %s / %s", e.EventType, e.ArtifactType)
	}
	if !e.Timestamp.IsZero() {
		t.Errorf("a configuration snapshot has no event time, got %v", e.Timestamp)
	}
	want := map[string]string{
		"container_id":      cid,
		"container_name":    "web01",
		"image":             "registry.example.test/team/web:1.4",
		"image_id":          "sha256:" + strings.Repeat("cd34", 16),
		"command":           "/entry.sh --serve --token <redacted> --db-password=<redacted>",
		"entrypoint":        "/entry.sh --init --secret <redacted>",
		"user":              "1000",
		"state":             "running",
		"exit_code":         "0",
		"restart_count":     "3",
		"driver":            "overlay2",
		"os":                "linux",
		"log_path":          "/var/lib/docker/containers/" + cid + "/" + cid + "-json.log",
		"container_created": "2026-10-22T08:20:59.639438116Z",
		"state_started_at":  "2026-10-22T08:21:00.775908379Z",
		"env_names":         "API_TOKEN,APP_MODE,AWS_SECRET_ACCESS_KEY,DATABASE_DSN,DB_PASSWORD,PATH,WITHOUT_EQUALS",
		"env_secret_names":  "API_TOKEN,AWS_SECRET_ACCESS_KEY,DATABASE_DSN,DB_PASSWORD",
		"published_ports":   "0.0.0.0:18080->8080/tcp",
		"mounts":            "bind:/etc/app->/cfg:ro,bind:/srv/data->/data,volume:/var/lib/docker/volumes/dbvol/_data->/var/lib/db",
	}
	for k, v := range want {
		if e.Extra[k] != v {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], v)
		}
	}
	if _, ok := e.Extra["state_finished_at"]; ok {
		t.Errorf("zero finished time must be omitted: %q", e.Extra["state_finished_at"])
	}
	if !strings.Contains(e.Extra["records_outcome"], "does not show what ran inside the container") ||
		!strings.HasPrefix(e.Extra["records_outcome"], "configuration as stored by the engine") {
		t.Errorf("records_outcome = %q", e.Extra["records_outcome"])
	}
	if e.Parser != "dockercontainer@1" || e.Confidence <= 0 || e.SourceReference == "" || r.Raw[0].SourceReference != e.SourceReference {
		t.Errorf("provenance = %+v", e)
	}
}

func TestConfig_NeverLeaksAValue(t *testing.T) {
	r := parse(t, writeIn(t, cid, "config.v2.json", linuxConfig))
	assertNoLeak(t, r, secretPW, "postgres://u:")
}

func assertNoLeak(t *testing.T, res parsers.ParseResult, needles ...string) {
	t.Helper()
	for i, e := range res.Events {
		var all []string
		for k, v := range e.Extra {
			all = append(all, k, v)
		}
		all = append(all, e.CommandLine, e.FilePath, e.User, e.Host, e.NetworkSource, e.SourceReference, res.Raw[i].Raw)
		for _, s := range all {
			for _, n := range needles {
				if strings.Contains(s, n) {
					t.Errorf("event %d leaks %q in %.80q", i, n, s)
				}
			}
		}
	}
	if res.Coverage != nil {
		for _, n := range res.Coverage.Notes {
			for _, nd := range needles {
				if strings.Contains(n, nd) {
					t.Errorf("coverage note leaks %q", nd)
				}
			}
		}
	}
}

var windowsConfig = strings.NewReplacer("@ID@", cid).Replace(`{"State":{"Running":false,"Paused":false,"Restarting":false,"Dead":false,"ExitCode":1,"Error":"","StartedAt":"0001-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"},` +
	`"ID":"@ID@","Created":"2026-10-22T08:20:59Z","Path":"C:\\app\\svc.exe","Args":["-run"],"Config":{"Image":"mcr.example.test/win/app:1","Env":["MODE=x"],"Entrypoint":null},"Image":"sha256:` + strings.Repeat("ef56", 16) + `",` +
	`"NetworkSettings":{"Ports":null},"LogPath":"","Name":"/web02","Driver":"windowsfilter","OS":"windows","RestartCount":0,` +
	`"MountPoints":{"C:\\app":{"Source":"C:\\data","Destination":"C:\\app","RW":true,"Type":"bind"},"\\\\.\\pipe\\docker_engine":{"Source":"\\\\.\\pipe\\docker_engine","Destination":"\\\\.\\pipe\\docker_engine","RW":true,"Type":"npipe"}}}`)

func TestConfig_WindowsLayoutAndZeroStateTimes(t *testing.T) {
	p := writeIn(t, cid, "config.v2.json", windowsConfig)
	r, err := New().ParseWithContext(p, parsers.ParseContext{EvidencePath: `C:\ProgramData\docker\containers\` + cid + `\config.v2.json`})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 1 {
		t.Fatalf("events = %d", len(r.Events))
	}
	e := r.Events[0]
	want := map[string]string{
		"os": "windows", "driver": "windowsfilter", "state": "created", "exit_code": "1", "container_name": "web02",
		"command": `C:\app\svc.exe -run`, "container_created": "2026-10-22T08:20:59Z", "entrypoint": "",
		"mounts":   `bind:C:\data->C:\app,npipe:\\.\pipe\docker_engine->\\.\pipe\docker_engine`,
		"log_path": "",
	}
	for k, v := range want {
		if e.Extra[k] != v {
			t.Errorf("Extra[%s] = %q, want %q", k, e.Extra[k], v)
		}
	}
	for k, v := range e.Extra {
		if strings.Contains(v, "0001-01-01") {
			t.Errorf("Extra[%s] prints the zero time: %q", k, v)
		}
	}
	for _, k := range []string{"state_started_at", "state_finished_at"} {
		if _, ok := e.Extra[k]; ok {
			t.Errorf("%s must be omitted", k)
		}
	}
	if !e.Timestamp.IsZero() {
		t.Errorf("timestamp = %v", e.Timestamp)
	}
}

func TestConfig_RejectsWhatIsNotAConfig(t *testing.T) {
	cases := map[string]string{
		"not json":       "{nope",
		"missing Config": `{"ID":"` + cid + `","State":{}}`,
		"missing State":  `{"ID":"` + cid + `","Config":{}}`,
		"missing ID":     `{"State":{},"Config":{}}`,
		"array":          `[1]`,
		"empty":          ``,
	}
	for name, body := range cases {
		if r, err := New().Parse(writeIn(t, cid, "config.v2.json", body)); err == nil {
			t.Errorf("%s: want error, got %d events", name, len(r.Events))
		}
	}
	// name says config.v2.json but the directory is not a container id
	if _, err := New().Parse(writeIn(t, "plain", "config.v2.json", linuxConfig)); err == nil {
		t.Error("a config.v2.json outside an id directory must not be parsed")
	}
}

func TestConfig_PublishedPortsFallBackToSiblingHostConfig(t *testing.T) {
	body := strings.Replace(linuxConfig, `"NetworkSettings":{"Ports":{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"18080"}],"9090/tcp":null}}`, `"NetworkSettings":{"Ports":null}`, 1)
	p := writeIn(t, cid, "config.v2.json", body)
	host := `{"NetworkMode":"bridge","PortBindings":{"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"13000"}]},"Privileged":false}`
	if err := writeSibling(p, "hostconfig.json", host); err != nil {
		t.Fatal(err)
	}
	e := parse(t, p).Events[0]
	if e.Extra["published_ports"] != "127.0.0.1:13000->3000/tcp" || e.Extra["published_ports_source"] != "hostconfig.json" {
		t.Errorf("ports = %q (%s)", e.Extra["published_ports"], e.Extra["published_ports_source"])
	}
	e2 := parse(t, writeIn(t, cid, "config.v2.json", linuxConfig)).Events[0]
	if e2.Extra["published_ports_source"] != "NetworkSettings.Ports" {
		t.Errorf("source = %q", e2.Extra["published_ports_source"])
	}
}

func TestConfig_DeterministicAndDistinctPerContainer(t *testing.T) {
	p := writeIn(t, cid, "config.v2.json", linuxConfig)
	a, b := parse(t, p), parse(t, p)
	if !reflect.DeepEqual(a, b) {
		t.Error("two parses differ")
	}
	other := strings.Repeat("cd34", 16)
	c := parse(t, writeIn(t, other, "config.v2.json", strings.ReplaceAll(linuxConfig, cid, other)))
	if a.Events[0].FilePath == c.Events[0].FilePath {
		t.Errorf("two containers' configs share FilePath %q and would dedup into one", a.Events[0].FilePath)
	}
}

func TestConfig_MismatchedIDInFileIsStated(t *testing.T) {
	other := strings.Repeat("cd34", 16)
	e := parse(t, writeIn(t, other, "config.v2.json", linuxConfig)).Events[0]
	if e.Extra["container_id"] != other || e.Extra["id_in_file"] != cid {
		t.Errorf("id = %q / %q", e.Extra["container_id"], e.Extra["id_in_file"])
	}
}

func writeSibling(p, name, body string) error {
	return os.WriteFile(filepath.Join(filepath.Dir(p), name), []byte(body), 0o600)
}
