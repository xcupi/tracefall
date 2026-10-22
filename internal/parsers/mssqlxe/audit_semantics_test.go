package mssqlxe

import (
	"fmt"
	"strings"
	"testing"
)

func TestAuditUserDefinedOutcomeIsNotPermissionCheck(t *testing.T) {
	for _, tc := range []struct{ flag, want string }{{"1", "user_defined_reported_success"}, {"0", "user_defined_reported_failure"}} {
		t.Run(tc.flag, func(t *testing.T) {
			raw := fmt.Sprintf("event_time,action_id,succeeded,user_defined_event_id\n2026-01-02 03:04:05,UDAU,%s,41\n", tc.flag)
			r, err := NewAudit().Parse(fixture(t, "user-defined.sqlaudit.csv", raw))
			if err != nil {
				t.Fatal(err)
			}
			e := r.Events[0]
			if e.Extra["sql_outcome"] != tc.want || !strings.Contains(e.Extra["sql_outcome_basis"], "caller-supplied") {
				t.Fatalf("caller flag misrepresented: %+v", e.Extra)
			}
			if !strings.Contains(r.Raw[0].Raw, "UDAU,"+tc.flag) {
				t.Fatal("original flag lost")
			}
		})
	}
}
