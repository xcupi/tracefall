package clockskew

import (
	"strings"
	"testing"
	"time"
)

func obs(subject string, lo, hi time.Duration) Observation {
	return Observation{Subject: subject, Reference: "cap", Method: "m", Lo: lo, Hi: hi, EventIDs: []string{"e"}}
}

func TestEstimates_AgreeingObservationsIntersect(t *testing.T) {
	got := Estimates([]Observation{
		obs("a", 3597*time.Second, 3603*time.Second),
		obs("a", 3599*time.Second, 3605*time.Second),
		obs("a", 3596*time.Second, 3601*time.Second),
	})
	if len(got) != 1 {
		t.Fatalf("%d estimates", len(got))
	}
	e := got[0]
	if !e.Consistent || e.Lo != 3599*time.Second || e.Hi != 3601*time.Second || e.Count != 3 {
		t.Fatalf("%+v", e)
	}
	if e.Offset() != 3600*time.Second || e.Uncertainty() != time.Second {
		t.Errorf("offset %v ± %v", e.Offset(), e.Uncertainty())
	}
	if !e.Significant() {
		t.Error("an hour is distinguishable from zero")
	}
	if !strings.Contains(e.Quarter, "quarter hours") {
		t.Errorf("an hour is a time-zone-sized offset: %q", e.Quarter)
	}
}

func TestEstimates_AnIntervalContainingZeroIsNotSignificant(t *testing.T) {
	e := Estimates([]Observation{obs("a", -2*time.Second, 3*time.Second)})[0]
	if e.Significant() || e.Quarter != "" {
		t.Errorf("%+v", e)
	}
}

func TestEstimates_DisagreementIsAResultNotAnError(t *testing.T) {
	e := Estimates([]Observation{obs("a", -time.Hour, -time.Hour+time.Second), obs("a", 0, time.Second), obs("a", time.Hour, time.Hour+time.Second)})[0]
	if e.Consistent || e.Steady() {
		t.Fatalf("%+v", e)
	}
	if e.Median != 0+time.Second/2 || e.MidLo >= e.MidHi {
		t.Errorf("median %v, mids %v..%v", e.Median, e.MidLo, e.MidHi)
	}
}

func TestSteady_ASpreadOfASecondIsNoise_AMinuteIsNot(t *testing.T) {
	noise := Estimates([]Observation{obs("a", 3597*time.Second, 3599*time.Second), obs("a", 3600*time.Second, 3602*time.Second)})[0]
	if noise.Consistent || !noise.Steady() {
		t.Fatalf("a 2-second spread is one steady offset: %+v", noise)
	}
	if lo, hi := noise.Shift(time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)); !lo.Before(hi) {
		t.Errorf("shift %v..%v", lo, hi)
	}
	// Everything either observation allows, not just the gap between them.
	if noise.SpanLo != 3597*time.Second || noise.SpanHi != 3602*time.Second || noise.Uncertainty() != 2500*time.Millisecond {
		t.Errorf("span %v..%v ±%v", noise.SpanLo, noise.SpanHi, noise.Uncertainty())
	}
	if !noise.Significant() {
		t.Error("an hour is not zero")
	}
	moved := Estimates([]Observation{obs("a", 0, time.Second), obs("a", time.Minute, time.Minute+time.Second)})[0]
	if moved.Steady() {
		t.Errorf("a minute apart is not steady: %+v", moved)
	}
}

func TestEstimates_SeparateSubjectsAndReferencesAreSeparate_AndBadInputIsIgnored(t *testing.T) {
	got := Estimates([]Observation{
		obs("b", 0, 1), obs("a", 0, 1),
		{Subject: "a", Reference: "other", Lo: 0, Hi: 1},
		{Subject: "a", Reference: "a", Lo: 0, Hi: 1}, // a clock against itself
		{Subject: "", Reference: "cap", Lo: 0, Hi: 1},
		{Subject: "c", Reference: "cap", Lo: 5, Hi: 1}, // inverted
	})
	if len(got) != 3 || got[0].Subject != "a" || got[0].Reference != "cap" || got[1].Reference != "other" || got[2].Subject != "b" {
		t.Fatalf("%+v", got)
	}
}

func TestShift_ExpressesTheSubjectsTimeOnTheReferenceScale(t *testing.T) {
	e := Estimates([]Observation{obs("a", 3599*time.Second, 3601*time.Second)})[0]
	at := time.Date(2020, 9, 19, 3, 0, 0, 0, time.UTC)
	lo, hi := e.Shift(at)
	if lo != at.Add(-3601*time.Second) || hi != at.Add(-3599*time.Second) {
		t.Errorf("%v..%v", lo, hi)
	}
}

func TestQuarter_OnlyATightMatchCountsAsTimeZoneSized(t *testing.T) {
	odd := Estimates([]Observation{obs("a", 2000*time.Second, 2002*time.Second)})[0]
	if odd.Quarter != "" {
		t.Errorf("33m21s is not a time-zone size: %q", odd.Quarter)
	}
	neg := Estimates([]Observation{obs("a", -5*time.Hour-time.Second, -5*time.Hour+time.Second)})[0]
	if !strings.Contains(neg.Quarter, "-5h0m0s") {
		t.Errorf("%q", neg.Quarter)
	}
}

func TestFormat(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Hour: "+1h0m0s", -4*time.Minute - 12*time.Second: "-4m12s", 0: "+0s", 1500 * time.Millisecond: "+2s"} {
		if got := Format(d); got != want {
			t.Errorf("Format(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestMajority_WrongClocksAreOutvoted(t *testing.T) {
	var all []Observation
	for i := 0; i < 9; i++ { // nine servers agree the capture is an hour behind them
		all = append(all, obs("web", 3599*time.Second+time.Duration(i)*100*time.Millisecond, 3603*time.Second))
	}
	all = append(all, obs("web", -4000*time.Hour, -4000*time.Hour+time.Second)) // one wrong clock
	e, ok := Majority(all, 0.8)
	if !ok || e.Count != 9 || e.Of != 10 || !e.Consistent {
		t.Fatalf("%+v ok=%v", e, ok)
	}
	if e.Offset() < 3599*time.Second || e.Offset() > 3603*time.Second {
		t.Errorf("offset %v", e.Offset())
	}
}

func TestMajority_NoAgreementIsNoEstimate(t *testing.T) {
	var all []Observation
	for i := 0; i < 10; i++ {
		d := time.Duration(i) * 100 * time.Hour
		all = append(all, obs("web", d, d+time.Second))
	}
	if _, ok := Majority(all, 0.8); ok {
		t.Error("ten different clocks agree on nothing")
	}
	if _, ok := Majority(all[:2], 0.8); ok {
		t.Error("two observations are not a majority of anything")
	}
	// Closed intervals that touch count as agreeing.
	touch := []Observation{obs("w", 0, 5), obs("w", 5, 9), obs("w", 5, 5)}
	if e, ok := Majority(touch, 0.8); !ok || e.Count != 3 {
		t.Errorf("touching intervals: %+v %v", e, ok)
	}
}
