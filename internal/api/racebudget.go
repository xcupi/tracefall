//go:build !race

package api

// timingBudgetFactor scales the performance guards in the test suite.
//
// The guards assert that a bulk operation has not silently reverted to a
// per-row one, which is a ~20x difference. The race detector adds its own
// order-of-magnitude overhead on top, so a single absolute budget is
// either flaky under -race or too loose to catch anything without it.
// Scaling keeps one threshold meaningful in both modes.
const timingBudgetFactor = 1

// raceEnabled reports whether this binary was built with the race
// detector.
const raceEnabled = false
