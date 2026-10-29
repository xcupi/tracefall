package authseq

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
	"tracefall/internal/model"
)

func TestSourceComparisonLiteralBoundaries(t *testing.T) {
	cases := []struct {
		name, a, b string
		want       int
	}{
		{"plain", "10.0.0.5", "10.0.0.5", 1},
		{"mapped", "::ffff:10.0.0.5", "10.0.0.5", 1},
		{"mapped hex", "::ffff:a00:5", "10.0.0.5", 1},
		{"IPv6 spelling", "2001:0DB8:0:0:0:0:0:5", "2001:db8::5", 1},
		{"same zone", "fe80:0:0:0:0:0:0:1%ifaceA", "fe80::1%ifaceA", 1},
		{"different zone", "fe80::1%ifaceA", "fe80::1%ifaceB", 0},
		{"mapped zone distinct", "::ffff:10.0.0.5%ifaceA", "::ffff:10.0.0.5%ifaceB", 0},
		{"mapped zone not plain", "::ffff:10.0.0.5%ifaceA", "10.0.0.5", 0},
		{"mapped zone equivalent", "::ffff:a00:5%ifaceA", "::ffff:10.0.0.5%ifaceA", 1},
		{"invalid zoned v4 not inferred", "::ffff:10.0.0.5%ifaceA", "10.0.0.5%ifaceA", 0},
		{"zone casing", "fe80::1%ifaceA", "fe80::1%IFACEA", 0},
		{"different IP", "10.0.0.5", "10.0.0.6", 0},
		{"different mapped IP", "::ffff:10.0.0.5", "10.0.0.6", 0},
		{"compatible not mapped", "::10.0.0.5", "10.0.0.5", 0},
		{"malformed", "10.0.0.999", "10.0.0.5", 0},
		{"malformed exact", "10.0.0.999", "10.0.0.999", 1},
		{"whitespace", " 10.0.0.5", "10.0.0.5", 0},
		{"port", "10.0.0.5:443", "10.0.0.5", 0},
		{"hostname case", "HOST01", "host01", 0},
		{"hostname exact", "HOST01", "HOST01", 1},
		{"missing source uncertainty", "", "10.0.0.5", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var es []model.Event
			for i := 0; i < 4; i++ {
				typ, ip := model.EventLogonFailure, tc.a
				if i == 3 {
					typ, ip = model.EventLogonSuccess, tc.b
				}
				es = append(es, model.Event{ID: fmt.Sprint(i), CaseID: "case", Host: "host01", User: "alice", EventType: typ, Timestamp: time.Date(2026, 1, 1, 0, i, 0, 0, time.UTC), NetworkSource: ip, Extra: map[string]string{"raw": "unchanged"}})
			}
			before, _ := json.Marshal(es)
			got := BeforeSuccess(es, 3, 10*time.Minute, 30*time.Minute)
			after, _ := json.Marshal(es)
			if len(got) != tc.want {
				t.Fatalf("sequences=%d want=%d", len(got), tc.want)
			}
			if string(before) != string(after) {
				t.Fatal("recorded source mutated")
			}
		})
	}
}

func TestEquivalentSourceKeepsAccountContextContradictions(t *testing.T) {
	for _, field := range []string{"target_domain", "subject_logon_id"} {
		t.Run(field, func(t *testing.T) {
			var es []model.Event
			for i := 0; i < 4; i++ {
				typ, ip, value := model.EventLogonFailure, "::ffff:10.0.0.5", "one"
				if i == 3 {
					typ, ip, value = model.EventLogonSuccess, "10.0.0.5", "two"
				}
				es = append(es, model.Event{ID: fmt.Sprint(i), CaseID: "case", Host: "host01", User: "alice", EventType: typ, Timestamp: time.Date(2026, 1, 1, 0, i, 0, 0, time.UTC), NetworkSource: ip, Extra: map[string]string{field: value}})
			}
			if got := BeforeSuccess(es, 3, 10*time.Minute, 30*time.Minute); len(got) != 0 {
				t.Fatal("contradictory context joined", got)
			}
		})
	}
}
