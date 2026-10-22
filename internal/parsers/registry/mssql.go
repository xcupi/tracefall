package registry

import (
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"tracefall/internal/model"
	"tracefall/internal/regf"
)

var sqlEngineInstanceID = regexp.MustCompile(`^mssql(?:[0-9]+(?:_[0-9]+)?)?\..+$`)

// sqlInstanceEvents emits registry snapshot values, not install/start events.
// Names are joined only by the instance mapping actually present in this hive.
func sqlInstanceEvents(h *regf.Hive) ([]model.Event, []model.RawEvidence, error) {
	const base = `Microsoft\Microsoft SQL Server`
	names := map[string]string{}
	k, err := h.OpenKey(base + `\Instance Names\SQL`)
	if err == nil {
		for _, v := range k.Values {
			if v.String() != "" {
				id := strings.ToLower(v.String())
				if old, exists := names[id]; exists && !strings.EqualFold(old, v.Name) {
					names[id] = ""
				} else if !exists {
					names[id] = v.Name
				}
			}
		}
	}
	var events []model.Event
	var raw []model.RawEvidence
	_, err = h.Walk(func(k regf.Key) error {
		low := strings.ToLower(k.Path)
		prefix := strings.ToLower(base) + `\`
		if !strings.HasPrefix(low, prefix) {
			return nil
		}
		rest := strings.TrimPrefix(low, prefix)
		parts := strings.Split(rest, `\`)
		isNames := rest == `instance names\sql`
		isConfig := len(parts) == 2 && parts[1] == "setup" || len(parts) == 3 && parts[1] == "mssqlserver" && parts[2] == "parameters"
		if len(parts) == 2 && parts[1] == "setup" {
			if _, mapped := names[parts[0]]; !mapped && !sqlEngineInstanceID.MatchString(parts[0]) {
				return nil
			}
		}
		if !isNames && !isConfig {
			return nil
		}
		for _, v := range k.Values {
			id, name := "", ""
			if isNames {
				id = v.String()
				name = v.Name
			} else {
				id = strings.Split(k.Path[len(base)+1:], `\`)[0]
				name = names[strings.ToLower(id)]
			}
			key := rootedPath(HiveSoftware, k.Path)
			ref := "value:" + key + `\` + v.Name
			extra := map[string]string{"instance_id": id, "instance": name, "registry_key": key, "registry_value_name": v.Name, "registry_value_data": v.String(), "records_execution": "false", "observation": "recorded SQL instance configuration; not observed execution"}
			if !k.LastWrite.IsZero() {
				extra["registry_last_write"] = k.LastWrite.Format(time.RFC3339Nano)
			}
			events = append(events, model.Event{EventType: model.EventSQLInstance, ArtifactType: model.ArtifactSQLInstance, RegistryPath: key, SourceReference: ref, Parser: parserName, Confidence: 1, Extra: extra})
			data, _ := json.Marshal(map[string]any{"key": key, "value_name": v.Name, "value_type": v.Type, "data_hex": hex.EncodeToString(v.Data)})
			raw = append(raw, model.RawEvidence{SourceReference: ref, Raw: string(data)})
		}
		return nil
	})
	return events, raw, err
}
