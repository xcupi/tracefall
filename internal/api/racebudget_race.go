//go:build race

package api

// See racebudget.go. Measured on this suite: the race detector costs
// roughly 13x on the deletion path, so the budget is scaled by 15 to
// leave headroom without letting a reverted per-row loop through.
const timingBudgetFactor = 15

// raceEnabled reports whether this binary was built with the race
// detector.
const raceEnabled = true
