package dockercontainer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

type hostConfigFile struct {
	Binds         []string
	NetworkMode   string
	PidMode       string
	IpcMode       string
	UsernsMode    string
	CapAdd        []string
	CapDrop       []string
	SecurityOpt   []string
	PortBindings  map[string][]portBinding
	RestartPolicy struct {
		Name              string
		MaximumRetryCount int
	}
	PublishAllPorts bool
	ReadonlyRootfs  bool
	Privileged      bool
	Devices         []json.RawMessage
	Memory          int64
	Mounts          []struct {
		Type     string
		Source   string
		Target   string
		ReadOnly bool
	}
}

// bindSource returns the host side of a "src:dst[:opts]" bind. A Windows
// drive letter ("C:\data:C:\app") is part of the source, not a separator.
func bindSource(bind string) string {
	if len(bind) >= 2 && bind[1] == ':' && isLetter(bind[0]) && (len(bind) == 2 || bind[2] == '\\' || bind[2] == '/') {
		if i := strings.IndexByte(bind[2:], ':'); i >= 0 {
			return bind[:2+i]
		}
		return bind
	}
	if i := strings.IndexByte(bind, ':'); i >= 0 {
		return bind[:i]
	}
	return bind
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// underPath reports whether p is dir or inside it (on a path boundary).
func underPath(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

// mountRisks returns the risk tags one host path source carries.
func mountRisks(source string) []string {
	s := strings.ReplaceAll(source, `\`, "/")
	low := strings.ToLower(s)
	var tags []string
	if low == "/var/run/docker.sock" || low == "/run/docker.sock" || strings.HasSuffix(low, "pipe/docker_engine") {
		tags = append(tags, "docker_socket_mount")
	}
	trim := strings.TrimRight(s, "/")
	if s == "/" || (len(s) >= 2 && s[1] == ':' && isLetter(s[0]) && strings.TrimRight(s[2:], "/") == "") {
		tags = append(tags, "host_root_mount")
	}
	for _, d := range []string{"/etc", "/root", "/proc", "/sys", "/var/lib/docker"} {
		if underPath(trim, d) {
			tags = append(tags, "sensitive_host_mount")
			break
		}
	}
	return tags
}

// riskyCaps are the capabilities worth a tag when ADDED to a container.
var riskyCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "SYS_RAWIO": true,
	"DAC_READ_SEARCH": true, "DAC_OVERRIDE": true, "NET_ADMIN": true, "SYS_BOOT": true, "MAC_ADMIN": true,
}

func parseHostConfig(absPath, id string) (parsers.ParseResult, error) {
	b, err := readJSONFile(absPath)
	if err != nil {
		return parsers.ParseResult{}, err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		return parsers.ParseResult{}, fmt.Errorf("dockercontainer: hostconfig.json is not a JSON object: %w", err)
	}
	_, hasNet := keys["NetworkMode"]
	_, hasPorts := keys["PortBindings"]
	_, hasPriv := keys["Privileged"]
	if !hasNet || !(hasPorts || hasPriv) {
		return parsers.ParseResult{}, fmt.Errorf("dockercontainer: hostconfig.json lacks NetworkMode with PortBindings or Privileged")
	}
	var h hostConfigFile
	if err := json.Unmarshal(b, &h); err != nil {
		return parsers.ParseResult{}, fmt.Errorf("dockercontainer: hostconfig.json: %w", err)
	}

	risk := map[string]bool{}
	if h.Privileged {
		risk["privileged"] = true
	}
	if h.PidMode == "host" {
		risk["host_pid"] = true
	}
	if h.NetworkMode == "host" {
		risk["host_network"] = true
	}
	for _, bind := range h.Binds {
		for _, t := range mountRisks(bindSource(bind)) {
			risk[t] = true
		}
	}
	var hostMounts []string
	for _, m := range h.Mounts {
		line := m.Type + ":" + m.Source + "->" + m.Target
		if m.ReadOnly {
			line += ":ro"
		}
		hostMounts = append(hostMounts, line)
		if strings.EqualFold(m.Type, "bind") || strings.EqualFold(m.Type, "npipe") {
			for _, t := range mountRisks(m.Source) {
				risk[t] = true
			}
		}
	}
	for _, c := range h.CapAdd {
		n := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_")
		if riskyCaps[n] {
			risk["cap_"+strings.ToLower(n)] = true
		}
	}
	for _, bs := range h.PortBindings {
		for _, pb := range bs {
			if pb.HostIP == "" || pb.HostIP == "0.0.0.0" || pb.HostIP == "::" {
				risk["published_all_interfaces"] = true
			}
		}
	}
	tags := make([]string, 0, len(risk))
	for t := range risk {
		tags = append(tags, t)
	}
	sort.Strings(tags)

	binds := append([]string(nil), h.Binds...)
	sort.Strings(binds)
	sort.Strings(hostMounts)
	restart := h.RestartPolicy.Name
	if restart != "" && h.RestartPolicy.MaximumRetryCount > 0 {
		restart += ":" + strconv.Itoa(h.RestartPolicy.MaximumRetryCount)
	}
	x := map[string]string{
		"container_id":       id,
		"privileged":         strconv.FormatBool(h.Privileged),
		"network_mode":       h.NetworkMode,
		"pid_mode":           h.PidMode,
		"ipc_mode":           h.IpcMode,
		"userns_mode":        h.UsernsMode,
		"restart_policy":     restart,
		"readonly_rootfs":    strconv.FormatBool(h.ReadonlyRootfs),
		"publish_all_ports":  strconv.FormatBool(h.PublishAllPorts),
		"devices":            strconv.Itoa(len(h.Devices)),
		"memory_limit_bytes": strconv.FormatInt(h.Memory, 10),
		"records_outcome":    configOutcome,
	}
	setList(x, "cap_add", h.CapAdd)
	setList(x, "cap_drop", h.CapDrop)
	setList(x, "security_opt", h.SecurityOpt)
	setList(x, "binds", binds)
	setList(x, "port_bindings", portList(h.PortBindings))
	setList(x, "risky", tags)
	if len(hostMounts) > 0 {
		setList(x, "host_mounts", hostMounts)
	}

	ref := "hostconfig.json"
	return parsers.ParseResult{
		Events: []model.Event{{
			EventType:       model.EventContainerHostConfig,
			ArtifactType:    model.ArtifactContainerConfig,
			Parser:          parserName,
			FilePath:        id + "/hostconfig.json",
			SourceReference: ref,
			Confidence:      1.0,
			Extra:           x,
		}},
		Raw:      []model.RawEvidence{{SourceReference: ref, Raw: strings.TrimSpace(string(b))}},
		Coverage: &model.ParseCoverage{RecordsRead: 1, Mapped: 1},
	}, nil
}
