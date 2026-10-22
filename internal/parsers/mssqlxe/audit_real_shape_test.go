package mssqlxe

import (
	"fmt"
	"testing"
)

// fn_get_audit_file returns user_defined_event_id (0) and a space-padded
// four-character action_id on EVERY row. Only the user-defined action carries a
// caller-supplied outcome; the presence of the column proves nothing.
func TestAudit_RealRowShapeKeepsDocumentedLoginOutcomes(t *testing.T) {
	cases := []struct {
		action, succeeded, wantAction, wantOutcome string
	}{
		{"LGIF", "0", "LGIF", "login_failed"},
		{"LGIS", "1", "LGIS", "login_success"},
		{"AL  ", "1", "AL", "permission_check_allowed"},
		{"CR  ", "0", "CR", "permission_check_denied"},
		{"UDAU", "1", "UDAU", "user_defined_reported_success"},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			raw := fmt.Sprintf("event_time,sequence_number,action_id,succeeded,user_defined_event_id,server_principal_name\n2026-01-02 03:04:05,1,%s,%s,0,alice\n", tc.action, tc.succeeded)
			r, err := NewAudit().Parse(fixture(t, "real.sqlaudit.csv", raw))
			if err != nil || len(r.Events) != 1 {
				t.Fatalf("err=%v events=%d", err, len(r.Events))
			}
			e := r.Events[0]
			if e.Extra["sql_action"] != tc.wantAction {
				t.Errorf("action = %q, want %q (padding trimmed)", e.Extra["sql_action"], tc.wantAction)
			}
			if e.Extra["sql_outcome"] != tc.wantOutcome {
				t.Errorf("outcome = %q, want %q (basis %q)", e.Extra["sql_outcome"], tc.wantOutcome, e.Extra["sql_outcome_basis"])
			}
		})
	}
}
