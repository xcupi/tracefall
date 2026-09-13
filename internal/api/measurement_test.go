package api

import "testing"

// skipMeasurementUnderRace skips a test whose only purpose is to MEASURE
// wall-clock cost.
//
// The race detector multiplies every timing by roughly an order of
// magnitude, so a number produced under it describes the detector rather
// than the code -- and building the large fixtures these tests need costs
// minutes, which is what pushed the package past its timeout.
//
// Correctness tests are deliberately NOT skipped: the concurrent ones are
// exactly what -race exists to check, and they are cheap.
func skipMeasurementUnderRace(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("measurement skipped under -race: the detector's overhead makes the timing meaningless")
	}
}
