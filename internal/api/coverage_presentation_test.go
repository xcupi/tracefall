package api

import (
	"encoding/json"
	"strings"
	"testing"

	"tracefall/internal/model"
)

func TestReport_MetadataCoveragePresentation(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
		measured        bool
	}{
		{"clean", `{"hive_replay":{"state":"clean"}}`, "hive transaction logs: clean", false},
		{"replayed", `{"hive_replay":{"state":"replayed","logs_applied":["SYSTEM.LOG1"]}}`, "hive transaction logs: replayed", false},
		{"unrecoverable", `{"hive_replay":{"state":"not_recoverable"},"notes":["recovery caveat"]}`, "recovery caveat", false},
		{"notes", `{"notes":["reader caveat"]}`, "reader caveat", false},
		{"historical", `{}`, "read=0 mapped=0", true},
		{"explicit-zero", `{"emitted_events":0,"hive_replay":{"state":"clean"}}`, "read=0 mapped=0", true},
		{"nonzero", `{"records_read":3,"mapped":2,"unmapped":1}`, "read=3 mapped=2 unmapped=1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c *model.ParseCoverage
			if err := json.Unmarshal([]byte(tc.raw), &c); err != nil {
				t.Fatal(err)
			}
			got := reportCoverage([]model.SourceFile{{Path: "vol1/SYSTEM", ArtifactType: model.ArtifactRegistryHive, ParseCoverage: c}})
			if len(got.ParserDiagnostics) != 1 {
				t.Fatalf("lost source diagnostic: %+v", got)
			}
			text := got.ParserDiagnostics[0].Value
			if !strings.Contains(text, tc.want) {
				t.Errorf("lost %q: %s", tc.want, text)
			}
			if !tc.measured && (!strings.Contains(text, "parse coverage: not recorded") || strings.Contains(text, "read=0")) {
				t.Errorf("metadata fabricated measured zero: %s", text)
			}
		})
	}
}
