// Package clockskew estimates how far one clock is from another from pairs of
// observations of the same instant, and says how sure it is.
//
// # Why this exists
//
// Evidence from different machines is stamped by different clocks. A packet
// capture is stamped by the capturing machine, a Windows event by the host
// that logged it, an HTTP response by the server that sent it. If one clock is
// wrong, an event can appear to happen before its own cause. Reading the
// timeline correctly needs to know by how much.
//
// # The model
//
// Every observation is an INTERVAL for the offset (subject clock minus
// reference clock), not a number: the instant a packet crossed a wire is not
// exactly the instant a server wrote its Date header, and a logon happens
// somewhere inside the TCP connection that carried it. An interval states
// that uncertainty and lets observations of different quality be combined
// honestly.
//
// For one subject and one reference the estimate is the intersection of its
// intervals. An empty intersection is a result, not an error: it means the
// offset was not constant (a clock was corrected or drifted) or an
// observation was mismatched, and the estimate says so instead of averaging
// the disagreement away.
//
// # What it does not do
//
// It never changes a timestamp. The estimate is a separate statement the
// reader can apply or not. It does not say WHY a clock is off: an offset that
// is a multiple of fifteen minutes is the size of a time-zone difference, and
// that is recorded as a hypothesis, not a finding.
package clockskew

import (
	"fmt"
	"sort"
	"time"
)

// Observation constrains offset = subject − reference to [Lo, Hi].
type Observation struct {
	Subject   string
	Reference string
	Method    string
	Lo, Hi    time.Duration
	EventIDs  []string
}

// Mid is the middle of the interval.
func (o Observation) Mid() time.Duration { return o.Lo + (o.Hi-o.Lo)/2 }

// Estimate is what the observations of one subject against one reference say.
type Estimate struct {
	Subject   string
	Reference string
	Count     int
	Methods   []string
	// Consistent is true when every observation agrees: the intersection of
	// the intervals is not empty. Lo and Hi are then that intersection.
	Consistent bool
	Lo, Hi     time.Duration
	// For an inconsistent set, MidLo and MidHi are the smallest and largest
	// interval midpoints, and Median the median midpoint.
	MidLo, MidHi, Median time.Duration
	// SpanLo and SpanHi are the lowest lower bound and the highest upper
	// bound over all observations: every offset any of them allows.
	SpanLo, SpanHi time.Duration
	EventIDs       []string
	// Quarter is set when the offset equals a whole number of quarter hours
	// within the estimate's own uncertainty -- the size of a time-zone
	// difference. It is a hypothesis about cause, nothing more.
	Quarter string
	// Of is, for an estimate taken from the agreeing majority of a larger
	// set, how many observations that set had; Count is how many agreed. Zero
	// when every observation was used.
	Of int
}

// SteadyTolerance is how far apart the midpoints of observations that do not
// intersect can be and still be one steady offset. Timestamps are whole
// seconds, packets are delayed, and real clocks drift by a fraction of a
// second over hours; a spread within a few seconds is that noise, and
// calling it a changing offset would alarm a reader about nothing.
const SteadyTolerance = 5 * time.Second

// Steady reports whether the observations describe one offset: either they all
// agree, or they disagree only by less than SteadyTolerance.
func (e Estimate) Steady() bool {
	return e.Consistent || e.MidHi-e.MidLo <= SteadyTolerance
}

// Majority estimates the offset of a subject whose observations come from many
// independent sources, some of which are simply wrong (web servers whose
// clocks are off, caches that replay an old Date). It finds the offset the
// most intervals allow and keeps the estimate only if at least minFraction of
// all observations agree on it, and at least three do. The rest are reported
// in Of, not hidden.
func Majority(obs []Observation, minFraction float64) (Estimate, bool) {
	var valid []Observation
	for _, o := range obs {
		if o.Hi >= o.Lo {
			valid = append(valid, o)
		}
	}
	if len(valid) < 3 {
		return Estimate{}, false
	}
	type edge struct {
		at    time.Duration
		delta int
	}
	edges := make([]edge, 0, 2*len(valid))
	for _, o := range valid {
		edges = append(edges, edge{o.Lo, +1}, edge{o.Hi, -1})
	}
	// An interval is closed, so at equal positions a start is processed
	// before an end.
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].at != edges[j].at {
			return edges[i].at < edges[j].at
		}
		return edges[i].delta > edges[j].delta
	})
	best, cur, at := 0, 0, time.Duration(0)
	for _, e := range edges {
		cur += e.delta
		if cur > best {
			best, at = cur, e.at
		}
	}
	if best < 3 || float64(best) < minFraction*float64(len(valid)) {
		return Estimate{}, false
	}
	var agree []Observation
	for _, o := range valid {
		if o.Lo <= at && at <= o.Hi {
			agree = append(agree, o)
		}
	}
	est := combine(agree[0].Subject, agree[0].Reference, agree)
	est.Of = len(valid)
	return est, true
}

// Offset is the best single value: the middle of the intersection; for
// observations that differ only by noise, the middle of everything they allow;
// otherwise the median midpoint.
func (e Estimate) Offset() time.Duration {
	switch {
	case e.Consistent:
		return e.Lo + (e.Hi-e.Lo)/2
	case e.Steady():
		return e.SpanLo + (e.SpanHi-e.SpanLo)/2
	}
	return e.Median
}

// Uncertainty is half the width of the range Offset is the middle of.
func (e Estimate) Uncertainty() time.Duration {
	switch {
	case e.Consistent:
		return (e.Hi - e.Lo) / 2
	case e.Steady():
		return (e.SpanHi - e.SpanLo) / 2
	}
	return (e.MidHi - e.MidLo) / 2
}

// Significant reports whether the offset is distinguishable from zero: zero
// lies outside the estimate. A subject whose interval contains zero has not
// been shown to be off.
func (e Estimate) Significant() bool {
	switch {
	case e.Consistent:
		return e.Lo > 0 || e.Hi < 0
	case e.Steady():
		return e.SpanLo > 0 || e.SpanHi < 0
	}
	return e.MidLo > 0 || e.MidHi < 0
}

// Estimates groups observations by (subject, reference) and combines each
// group. The result is ordered by subject then reference.
func Estimates(obs []Observation) []Estimate {
	type key struct{ s, r string }
	groups := map[key][]Observation{}
	for _, o := range obs {
		if o.Hi < o.Lo || o.Subject == "" || o.Reference == "" || o.Subject == o.Reference {
			continue
		}
		k := key{o.Subject, o.Reference}
		groups[k] = append(groups[k], o)
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].s != keys[j].s {
			return keys[i].s < keys[j].s
		}
		return keys[i].r < keys[j].r
	})
	out := make([]Estimate, 0, len(keys))
	for _, k := range keys {
		out = append(out, combine(k.s, k.r, groups[k]))
	}
	return out
}

const evidenceCap = 12

func combine(subject, reference string, obs []Observation) Estimate {
	e := Estimate{Subject: subject, Reference: reference, Count: len(obs)}
	lo, hi := obs[0].Lo, obs[0].Hi
	e.SpanLo, e.SpanHi = obs[0].Lo, obs[0].Hi
	mids := make([]time.Duration, len(obs))
	methods := map[string]bool{}
	for i, o := range obs {
		if o.Lo > lo {
			lo = o.Lo
		}
		if o.Hi < hi {
			hi = o.Hi
		}
		if o.Lo < e.SpanLo {
			e.SpanLo = o.Lo
		}
		if o.Hi > e.SpanHi {
			e.SpanHi = o.Hi
		}
		mids[i] = o.Mid()
		methods[o.Method] = true
		if len(e.EventIDs) < evidenceCap {
			e.EventIDs = append(e.EventIDs, o.EventIDs...)
		}
	}
	for m := range methods {
		e.Methods = append(e.Methods, m)
	}
	sort.Strings(e.Methods)
	sort.Slice(mids, func(i, j int) bool { return mids[i] < mids[j] })
	e.MidLo, e.MidHi, e.Median = mids[0], mids[len(mids)-1], mids[len(mids)/2]
	if lo <= hi {
		e.Consistent, e.Lo, e.Hi = true, lo, hi
	}
	if q := quarterHours(e); q != "" {
		e.Quarter = q
	}
	if len(e.EventIDs) > evidenceCap*4 {
		e.EventIDs = e.EventIDs[:evidenceCap*4]
	}
	return e
}

// quarterHours returns a description when the offset is a non-zero whole
// number of quarter hours within the estimate's uncertainty.
func quarterHours(e Estimate) string {
	off, unc := e.Offset(), e.Uncertainty()
	const q = 15 * time.Minute
	n := (off + q/2).Truncate(q) // nearest quarter hour
	if off < 0 {
		n = -((-off + q/2).Truncate(q))
	}
	if n == 0 {
		return ""
	}
	diff := off - n
	if diff < 0 {
		diff = -diff
	}
	// The match must be tight: closer to the quarter hour than a minute plus
	// the estimate's own uncertainty, so that a random offset is not described
	// as a time-zone size by accident.
	if diff > time.Minute+unc {
		return ""
	}
	return fmt.Sprintf("%s is a whole number of quarter hours, the size of a time-zone difference", Format(n))
}

// Format renders a signed duration the way a reader wants it: +1h0m0s, -4m12s.
func Format(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign, d = "-", -d
	}
	d = d.Round(time.Second)
	return sign + d.String()
}

// Shift expresses a time stamped by the subject's clock on the reference
// clock's scale: the subject is ahead by the offset, so subtract it. The
// result is an interval, because the offset is.
func (e Estimate) Shift(t time.Time) (lo, hi time.Time) {
	switch {
	case e.Consistent:
		return t.Add(-e.Hi), t.Add(-e.Lo)
	case e.Steady():
		return t.Add(-e.SpanHi), t.Add(-e.SpanLo)
	}
	return t.Add(-e.MidHi), t.Add(-e.MidLo)
}
