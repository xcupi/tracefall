package correlate

import (
	"fmt"
	"github.com/google/uuid"
	"sort"
	"strconv"
	"strings"
	"time"
	"tracefall/internal/model"
)

func taskContext(caseID, typ, title string, events []model.Event) model.Correlation {
	c := model.Correlation{CaseID: caseID, Type: typ, Title: title}
	// Known-time presentation first, stable IDs break ties, never causal order.
	ordered := append([]model.Event(nil), events...)
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.Timestamp.IsZero() != b.Timestamp.IsZero() {
			return !a.Timestamp.IsZero()
		}
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		return a.ID < b.ID
	})
	for _, e := range ordered {
		c.EventIDs = append(c.EventIDs, e.ID)
		if e.Timestamp.IsZero() {
			continue
		}
		if c.FirstSeen.IsZero() || e.Timestamp.Before(c.FirstSeen) {
			c.FirstSeen = e.Timestamp
		}
		if c.LastSeen.IsZero() || e.Timestamp.After(c.LastSeen) {
			c.LastSeen = e.Timestamp
		}
	}
	c.ID = model.StableID("corr", append([]string{caseID, typ}, c.EventIDs...)...)
	return c
}

// taskPID accepts a complete recorded decimal/hex Windows PID, never EnginePID.
func taskPID(s string) int64 {
	base := 10
	token := s
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		token = s[2:]
	}
	if token == "" {
		return 0
	}
	for _, r := range token {
		if !(r >= '0' && r <= '9') && !(base == 16 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F')) {
			return 0
		}
	}
	n, err := strconv.ParseUint(token, base, 32)
	if err != nil || n == 0 {
		return 0
	}
	return int64(n)
}

// Comparison is case/slash only. Reject uncertain command targets rather than
// expanding environment variables, resolving aliases or cleaning dot segments.
func taskPath(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, "\\", "/"))
	if s == "" || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\"%~<>|?*\x00\r\n\t") {
		return ""
	}
	start := 0
	if len(s) > 3 && s[0] >= 'a' && s[0] <= 'z' && s[1:3] == ":/" {
		start = 3
	} else if strings.HasPrefix(s, "//") {
		start = 2
	} else {
		return ""
	}
	if strings.Contains(s[start:], ":") {
		return ""
	}
	parts := strings.Split(s[start:], "/")
	if start == 2 && len(parts) < 3 {
		return ""
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part {
			return ""
		}
	}
	// A command/arguments value is not a literal executable target. This
	// deliberately excludes unknown extensions instead of guessing their role.
	ext := []string{".exe", ".com", ".cmd", ".bat"}
	valid := false
	for _, x := range ext {
		if strings.Contains(s, x+" ") {
			return ""
		}
		if strings.HasSuffix(s, x) {
			valid = true
		}
	}
	if !valid {
		return ""
	}
	return s
}

// BuildTaskProcessContexts is a bounded association, separate from instance
// GUID context: event 129 has no recorded instance identifier.
func BuildTaskProcessContexts(caseID string, events []model.Event) []model.Correlation {
	return buildTaskProcessContexts(caseID, events, nil)
}
func buildTaskProcessContexts(caseID string, events []model.Event, counts map[string]int) []model.Correlation {
	events, counts = taskInput(events, counts)
	byPID := map[string][]model.Event{}
	for _, p := range events {
		if p.EventType == model.EventProcessCreate && p.PID > 0 {
			k := fmt.Sprintf("%s\x00%d", processScope(p), p.PID)
			byPID[k] = append(byPID[k], p)
		}
	}
	var out []model.Correlation
	for _, a := range sortedChainEvents(events) {
		if !recordedTask(a) || a.EventID != 129 || !taskScope(a, caseID, counts) || !processTime(a) {
			continue
		}
		pid := taskPID(a.Extra["process_id"])
		path := taskPath(a.Extra["process_path"])
		if pid == 0 || path == "" {
			continue
		}
		candidates := byPID[fmt.Sprintf("%s\x00%d", processScope(a), pid)]
		// Fail closed on any observed PID reuse in this acquisition, including
		// starts outside the clock-local matching window; never choose nearest.
		if len(candidates) != 1 {
			continue
		}
		p := candidates[0]
		if !taskScope(p, caseID, counts) || !processTime(p) || taskPath(p.ProcessPath) != path {
			continue
		}
		dt := p.Timestamp.Sub(a.Timestamp)
		if dt < -2*time.Second || dt > 2*time.Second {
			continue
		}
		if g := a.Extra["process_guid"]; g != "" && (taskGUIDKey(g) == "" || taskGUIDKey(g) != taskGUIDKey(p.Extra["process_guid"])) {
			continue
		}
		if s := p.Extra["exit_time"]; s != "" {
			end, err := time.Parse(time.RFC3339Nano, s)
			if err != nil || !end.After(p.Timestamp) || !end.After(a.Timestamp) {
				continue
			}
		}
		c := taskContext(caseID, model.CorrelationTaskProcessContext, "Task process context", []model.Event{a, p})
		c.Description = "Context only: Task Scheduler reported a process launch (129), and one compatible process creation records the same positive payload PID and literal full executable path in the same validated host/acquisition, within two seconds in either direction. This clock-local association is not causal ordering, program success, intent or a particular task instance. No observed competing PID creation was present in the acquisition; unobserved reuse and missing exits remain uncertain."
		out = append(out, c)
	}
	return out
}

var taskActions = map[int]string{100: "task_started", 102: "task_completed", 129: "task_process_launched", 200: "task_action_started", 201: "task_action_completed", 202: "task_action_failed"}

func recordedTask(e model.Event) bool {
	// Event.Provider is the adapter's channel label (not System.Provider).
	if e.Provider != "" && !strings.EqualFold(e.Provider, "Microsoft-Windows-TaskScheduler/Operational") {
		return false
	}
	outcome := "observed"
	if e.EventID == 202 {
		outcome = "failure"
	}
	if e.Extra["outcome"] != outcome {
		return false
	}
	return e.EventType == model.EventScheduledTaskRun && strings.EqualFold(e.Extra["event_provider"], "Microsoft-Windows-TaskScheduler") && strings.EqualFold(e.Extra["event_channel"], "Microsoft-Windows-TaskScheduler/Operational") && taskActions[e.EventID] != "" && taskActions[e.EventID] == e.Extra["action"]
}
func taskScope(e model.Event, caseID string, counts map[string]int) bool {
	return caseID != "" && e.CaseID == caseID && e.CollectionID != "" && e.Host != "" && e.ID != "" && counts[e.ID] == 1 && e.ArtifactType != model.ArtifactMemoryAnalysis && e.Extra["timestamp_basis"] != "memory_snapshot"
}
func taskInput(events []model.Event, counts map[string]int) ([]model.Event, map[string]int) {
	if counts == nil {
		counts = map[string]int{}
		for _, e := range events {
			if e.EventType != "" {
				counts[e.ID]++
			}
		}
	}
	return chainHostKeys(events), counts
}
func taskGUIDKey(s string) string {
	// Parse only literal dashed GUIDs (optionally braced), not UUID URNs or compact strings.
	if len(s) == 38 && s[0] == '{' && s[37] == '}' {
		s = s[1:37]
	}
	if len(s) != 36 {
		return ""
	}
	u, err := uuid.Parse(s)
	if err != nil || u == uuid.Nil {
		return ""
	}
	return u.String()
}

// BuildTaskInstanceContexts associates only recorded instance identities within
// a validated machine and acquisition. Source records are never rewritten.
func BuildTaskInstanceContexts(caseID string, events []model.Event) []model.Correlation {
	return buildTaskInstanceContexts(caseID, events, nil)
}
func buildTaskInstanceContexts(caseID string, events []model.Event, counts map[string]int) []model.Correlation {
	events, counts = taskInput(events, counts)
	groups := map[string][]model.Event{}
	for _, e := range events {
		g := taskGUIDKey(e.Extra["task_instance_id"])
		if !taskScope(e, caseID, counts) || !recordedTask(e) || e.EventID == 129 || g == "" {
			continue
		}
		k := processScope(e) + "\x00" + g
		groups[k] = append(groups[k], e)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []model.Correlation
	for _, k := range keys {
		g := groups[k]
		if len(g) < 2 {
			continue
		}
		name := ""
		user := ""
		ambiguous := false
		starts, completes := 0, 0
		for _, e := range g {
			n := strings.ToLower(e.Extra["task_name"])
			if n != "" {
				if name != "" && n != name {
					ambiguous = true
				}
				name = n
			}
			u := strings.ToLower(e.Extra["user_context"])
			if u != "" {
				if user != "" && u != user {
					ambiguous = true
				}
				user = u
			}
			if e.EventID == 100 {
				starts++
			}
			if e.EventID == 102 {
				completes++
			}
		}
		// Repeated task-level endpoints may describe disjoint captures/episodes;
		// action-level multiplicity is legitimate and is retained without folding.
		if ambiguous || starts > 1 || completes > 1 {
			continue
		}
		c := taskContext(caseID, model.CorrelationTaskInstanceContext, "Task instance context", g)
		observed := map[int]int{}
		undated := 0
		for _, e := range g {
			observed[e.EventID]++
			if e.Timestamp.IsZero() {
				undated++
			}
		}
		c.Description = fmt.Sprintf("Context only: recorded instance GUID in one validated host/acquisition. Observations: task started=%d; task completed=%d; action started=%d; action completed=%d; action failure=%d; undated=%d. Action completion is not program success; task completion does not establish that all actions succeeded. Failure is scheduler-reported independently of result codes. A missing record is not proof the step did not happen. Recorded identifiers associate observations, not effects or causal order.", observed[100], observed[102], observed[200], observed[201], observed[202], undated)
		if c.FirstSeen.IsZero() {
			c.Description += " Observation time not recorded."
		} else if undated > 0 {
			c.Description += " Window includes known timestamps only; undated observations have no temporal placement."
		}
		out = append(out, c)
	}
	return out
}
