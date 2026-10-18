package detect

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/procclass"
)

type memoryProcessSignals struct{}

func (memoryProcessSignals) ID() string { return "memory-process-signals" }

type memoryProcessKey struct {
	caseID, collection, host string
	pid                      int64
}

func memoryKey(e model.Event) memoryProcessKey {
	return memoryProcessKey{e.CaseID, e.CollectionID, strings.ToUpper(e.Host), e.PID}
}

// Memory plugins belong to one acquisition, not a five-minute execution
// window. Join by image, host and PID, checking the recorded process name and
// creation time too. A socket's owner may be the kernel-truncated image name.
func memoryOwner(p, observation model.Event, processes []model.Event) bool {
	if !strings.EqualFold(p.ProcessName, observation.ProcessName) &&
		(p.Extra["image_file_name"] == "" || !strings.EqualFold(p.Extra["image_file_name"], observation.ProcessName)) {
		return false
	}
	if observation.Timestamp.IsZero() || observation.Timestamp.Before(p.Timestamp) {
		return false
	}
	for _, other := range processes {
		if other.Timestamp.After(p.Timestamp) && !other.Timestamp.After(observation.Timestamp) {
			return false
		}
	}
	return true
}

func memoryRemoteSocket(e model.Event) bool {
	if e.EventType != model.EventNetworkConnection || e.NetworkDestPort <= 0 || e.NetworkDestPort > 65535 {
		return false
	}
	ip, err := netip.ParseAddr(e.NetworkDest)
	return err == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

var memoryRiskyCommand = regexp.MustCompile(`(?i)-enc\b|-encodedcommand\b|frombase64string|downloadstring|downloadfile|net\.webclient|\biex\b|invoke-expression|\b(?:rundll32|regsvr32|mshta)(?:\.exe)?\s+["']?\\{2,}[^\\\s]+\\`)

func (r memoryProcessSignals) Evaluate(events []model.Event) []model.Finding {
	processes := map[memoryProcessKey][]model.Event{}
	observations := map[memoryProcessKey][]model.Event{}
	snapshots := map[memoryProcessKey]model.Event{}
	var pivots []model.Event
	for _, e := range events {
		if e.ArtifactType != model.ArtifactMemoryAnalysis || e.CollectionID == "" {
			continue
		}
		k := memoryKey(e)
		if e.EventType == model.EventMemorySnapshot {
			k.pid = 0
			snapshots[k] = e
			continue
		}
		if e.PID <= 0 {
			continue
		}
		switch e.EventType {
		case model.EventProcessCreate:
			processes[k] = append(processes[k], e)
			if !e.Timestamp.IsZero() && e.Extra["exit_time"] == "" {
				pivots = append(pivots, e)
			}
		case model.EventNetworkConnection, model.EventMemoryInjection:
			observations[k] = append(observations[k], e)
		}
	}
	sort.Slice(pivots, func(i, j int) bool { return pivots[i].ID < pivots[j].ID })
	var findings []model.Finding
	for _, p := range pivots {
		var sockets, regions []model.Event
		pe := false
		for _, o := range observations[memoryKey(p)] {
			if !memoryOwner(p, o, processes[memoryKey(p)]) {
				continue
			}
			if memoryRemoteSocket(o) {
				sockets = append(sockets, o)
			}
			if o.EventType == model.EventMemoryInjection && o.Extra["private_memory"] == "1" && strings.Contains(o.Extra["protection"], "EXECUTE") {
				regions = append(regions, o)
				pe = pe || o.Extra["pe_header"] == "true"
			}
		}
		writable := procclass.HasSuspiciousPath(p.ProcessPath)
		risky := memoryRiskyCommand.MatchString(p.CommandLine)
		corroboratedRegion := len(regions) > 0 && risky
		sk := memoryKey(p)
		sk.pid = 0
		snapshot := snapshots[sk]
		plugins := "," + snapshot.Extra["plugins"] + ","
		hidden := p.Extra["hidden_process"] == "true" && p.Extra["memory_source"] == "psscan" &&
			strings.Contains(plugins, ",pslist:ok,") && strings.Contains(plugins, ",psscan:ok,") && !snapshot.Timestamp.Before(p.Timestamp)
		if !pe && !corroboratedRegion && !hidden && !(writable && len(sockets) > 0) {
			continue
		}
		severity, confidence := model.SeverityMedium, model.ConfidenceLow
		reasons := []string{}
		supporting := []model.Event{p}
		if hidden {
			reasons = append(reasons, "a pool-scan-only process absent from a successfully read active process list (not proof of a rootkit)")
			supporting = append(supporting, snapshot)
		}
		if pe {
			reasons = append(reasons, "private executable memory containing a PE header (a malfind heuristic)")
			supporting = append(supporting, regions...)
			if writable || len(sockets) > 0 {
				severity, confidence = model.SeverityHigh, model.ConfidenceMedium
			}
		}
		if corroboratedRegion {
			reasons = append(reasons, "private executable memory together with encoded/dynamic/download or remote execution command indicators")
			severity, confidence = model.SeverityHigh, model.ConfidenceMedium
			if !pe {
				supporting = append(supporting, regions...)
			}
		}
		if writable {
			reasons = append(reasons, "a user-writable image path")
		}
		if len(sockets) > 0 {
			reasons = append(reasons, "a remote socket")
			supporting = append(supporting, sockets...)
		}
		sort.Slice(supporting, func(i, j int) bool { return supporting[i].ID < supporting[j].ID })
		desc := fmt.Sprintf("Process %s (PID %d), image path %q, was observed in memory with %s. This is a review lead, not a malware or C2 verdict: legitimate installers also use writable paths and network sockets, and legitimate unpackers may contain PE headers. Socket states are observations; SYN_SENT is an attempt and CLOSED does not establish successful transfer. Destination reputation and port number were not used to classify the process.", p.ProcessName, p.PID, p.ProcessPath, strings.Join(reasons, "; "))
		var socketDetails []string
		for _, socket := range sockets {
			socketDetails = append(socketDetails, fmt.Sprintf("%s:%d [%s]", socket.NetworkDest, socket.NetworkDestPort, socket.Extra["state"]))
		}
		sort.Strings(socketDetails)
		if len(socketDetails) > 5 {
			socketDetails = socketDetails[:5]
		}
		desc += fmt.Sprintf(" Observed executable regions: %d. Command line: %q. Remote sockets (up to five): %s. Region observations describe snapshot state, not when injection occurred.", len(regions), truncate(p.CommandLine, 300), strings.Join(socketDetails, ", "))
		findings = append(findings, newFinding(p.CaseID, r.ID(), fmt.Sprintf("Memory process review: %s (PID %d)", p.ProcessName, p.PID), severity, confidence, desc, nil, supporting))
	}
	return findings
}
