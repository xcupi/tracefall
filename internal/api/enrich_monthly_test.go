package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"tracefall/internal/model"
)

func withLimits(t *testing.T, daily, monthly int) {
	t.Helper()
	od, om := vtDailyLimit, vtMonthlyLimit
	vtDailyLimit, vtMonthlyLimit = daily, monthly
	t.Cleanup(func() { vtDailyLimit, vtMonthlyLimit = od, om })
}

func record(t *testing.T, svc *Service, at time.Time, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := svc.store.RecordProviderRequest(model.EnrichmentVirusTotal, at); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVTAllowance_DayIsRollingAndMonthIsTheCalendarMonthInUTC(t *testing.T) {
	_, svc := newTestRouterWithService(t)
	withLimits(t, 10, 100)
	now := time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC)
	record(t, svc, time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC), 7) // last month: in no window but not this month
	record(t, svc, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), 5)     // first instant of the month
	record(t, svc, now.Add(-25*time.Hour), 2)                          // this month, not today
	record(t, svc, now.Add(-time.Hour), 3)                             // today
	al, err := svc.vtAllowance(now)
	if err != nil {
		t.Fatal(err)
	}
	if al.dailyUsed != 3 || al.monthlyUsed != 10 || al.remaining != 7 {
		t.Errorf("allowance = %+v; want day 3, month 10 (the February requests do not count), remaining 7", al)
	}
	// the month is what limits when it is the tighter one
	withLimits(t, 10, 12)
	al, _ = svc.vtAllowance(now)
	if al.remaining != 2 || al.limiting() != "month" || al.err() != ErrEnrichMonthlyLimit {
		t.Errorf("allowance = %+v limiting %s", al, al.limiting())
	}
	withLimits(t, 4, 100)
	al, _ = svc.vtAllowance(now)
	if al.remaining != 1 || al.limiting() != "day" || al.err() != ErrEnrichDailyLimit {
		t.Errorf("allowance = %+v limiting %s", al, al.limiting())
	}
	withLimits(t, 2, 100)
	if al, _ = svc.vtAllowance(now); al.remaining != 0 {
		t.Errorf("an overdrawn allowance must read as 0 remaining, got %d", al.remaining)
	}
}

func TestVirusTotal_MonthlyAllowanceUsedUpRefusesAndSendsNothing(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	withLimits(t, 500, 4)
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA})
	setLevel(t, mux, id, "hashes")
	record(t, svc, time.Now().UTC(), 4)
	rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "monthly") || stub.count() != 0 {
		t.Errorf("status %d body %s requests %d", rec.Code, rec.Body.String(), stub.count())
	}
	var st struct {
		Status VTStatus `json:"status"`
	}
	doJSON(t, mux, "GET", "/api/cases/"+id+"/enrich/virustotal", nil, &st)
	if st.Status.MonthlyUsed != 4 || st.Status.MonthlyLimit != 4 || st.Status.Remaining != 0 {
		t.Errorf("status = %+v", st.Status)
	}
}

func TestVirusTotal_ARunIsCutToTheAllowanceAndEveryRequestIsCounted(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	stub.answers[hA] = ok(vtKnown)
	stub.answers[hC] = status(500, "boom", nil) // a failed request still counts
	withLimits(t, 500, 12)
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA}, map[string]string{"sha1": hB}, map[string]string{"md5": hC})
	setLevel(t, mux, id, "hashes")
	record(t, svc, time.Now().UTC(), 10) // 2 left this month, 3 wanted
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil); rec.Code != 202 {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	run := waitRun(t, svc, id)
	if run.Total != 2 || run.Done != 2 || !strings.Contains(run.Reason, "month's remaining allowance") {
		t.Errorf("run = %+v", run)
	}
	if stub.count() != 2 {
		t.Errorf("%d requests, want 2", stub.count())
	}
	al, _ := svc.vtAllowance(time.Now().UTC())
	if al.monthlyUsed != 12 || al.remaining != 0 {
		t.Errorf("after the run: %+v; every request, answered or not, must be counted", al)
	}
	// the second run asks only for what is unanswered (hC), and hC fails with
	// a 500: a failed request still counts against the allowance
	withLimits(t, 500, 14)
	before := stub.count()
	if rec := doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil); rec.Code != 202 {
		t.Fatalf("second start: %d %s", rec.Code, rec.Body.String())
	}
	run = waitRun(t, svc, id)
	al, _ = svc.vtAllowance(time.Now().UTC())
	if run.Errors != 1 || stub.count()-before != 1 || al.monthlyUsed != 13 {
		t.Errorf("run %+v, requests %d, monthly used %d; want 1 failed request counted (13)", run, stub.count()-before, al.monthlyUsed)
	}
}

func TestVirusTotal_ARunStopsWhenAnotherRunUsesTheAllowanceFirst(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	stub.answers[hA] = ok(vtKnown)
	stub.delay = 120 * time.Millisecond
	withLimits(t, 500, 3)
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA}, map[string]string{"sha1": hB}, map[string]string{"md5": hC})
	setLevel(t, mux, id, "hashes")
	doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil)
	time.Sleep(60 * time.Millisecond)
	record(t, svc, time.Now().UTC(), 2) // another case's run takes the rest
	run := waitRun(t, svc, id)
	if run.State != "stopped" || !strings.Contains(run.Reason, "month request allowance is used up") {
		t.Errorf("run = %+v", run)
	}
	if stub.count() >= 3 {
		t.Errorf("%d requests went out after the allowance was gone", stub.count())
	}
}

func TestVirusTotal_DeletingACaseDoesNotGiveRequestsBack(t *testing.T) {
	mux, svc := newTestRouterWithService(t)
	stub := newVTStub(t, svc)
	withLimits(t, 500, 500)
	id := caseWithHashes(t, svc, mux, map[string]string{"sha256": hA}, map[string]string{"sha1": hB})
	setLevel(t, mux, id, "hashes")
	doJSON(t, mux, "POST", "/api/cases/"+id+"/enrich/virustotal", nil, nil)
	waitRun(t, svc, id)
	if stub.count() != 2 {
		t.Fatalf("requests = %d", stub.count())
	}
	if err := svc.store.DeleteCase(id); err != nil {
		t.Fatal(err)
	}
	al, _ := svc.vtAllowance(time.Now().UTC())
	if al.monthlyUsed != 2 || al.dailyUsed != 2 {
		t.Errorf("after deleting the case: %+v", al)
	}
}
