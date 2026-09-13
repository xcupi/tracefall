package sam_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/regf"
	"tracefall/internal/sam"
	"tracefall/internal/sam/samgen"
)

// Parsing cost against account count. The point is the SHAPE of the
// curve, not the absolute numbers: enumeration uses regf.ChildKeys,
// which walks the subkey list once, so cost must rise roughly linearly.
// The Subkeys-then-OpenKey-per-child shape this replaced re-walked the
// list for every child and was quadratic -- with 5,000 accounts that is
// the difference between a moment and minutes.
func TestPerf_ParsingScalesLinearlyWithAccountCount(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	sysPath := filepath.Join(t.TempDir(), "SYSTEM")
	if err := os.WriteFile(sysPath, samgen.SystemHive(nil), 0o600); err != nil {
		t.Fatal(err)
	}
	sh, err := regf.Open(sysPath, regf.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	bk := sam.BootKey(sh)
	sh.Close()
	if !bk.OK() {
		t.Fatalf("BootKey: %s (%s)", bk.Status, bk.Reason)
	}

	timeFor := func(n int) (time.Duration, int64) {
		accts := make([]samgen.Account, n)
		for i := range accts {
			accts[i] = samgen.Account{
				RID: uint32(1000 + i), Username: "user" + itoa(i),
				ACBFlags: 0x0010, NTLM: mustHex(t, hashSvc),
			}
		}
		p := filepath.Join(t.TempDir(), "SAM")
		hive := samgen.SAMHive(samgen.Options{Accounts: accts})
		if err := os.WriteFile(p, hive, 0o600); err != nil {
			t.Fatal(err)
		}
		h, err := regf.Open(p, regf.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		start := time.Now()
		res, err := sam.Accounts(h, bk)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Accounts) != n {
			t.Fatalf("%d accounts read, want %d", len(res.Accounts), n)
		}
		return elapsed, int64(len(hive))
	}

	// A small SAM: what a real workstation looks like. The AfricanFalls
	// hive is 64 KiB with five accounts.
	small, smallSize := timeFor(5)
	t.Logf("small SAM   (5 accounts, %d bytes): %s", smallSize, small)

	mid, midSize := timeFor(500)
	t.Logf("medium SAM  (500 accounts, %d bytes): %s", midSize, mid)

	large, largeSize := timeFor(5000)
	t.Logf("large SAM   (5000 accounts, %d bytes): %s", largeSize, large)

	if large > 30*time.Second {
		t.Fatalf("5000 accounts took %s", large)
	}
	// Ten times the accounts must not cost anywhere near a hundred times
	// the work. The bound is loose because these are wall-clock timings
	// on a shared machine -- it is there to catch a quadratic
	// regression, not to police a few percent.
	if mid > 0 && large > 40*mid {
		t.Errorf("500 accounts took %s but 5000 took %s (%.1fx for 10x the accounts); "+
			"traversal looks quadratic", mid, large, float64(large)/float64(mid))
	}
}
