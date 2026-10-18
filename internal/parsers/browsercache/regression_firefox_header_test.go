package browsercache_test

import (
	"encoding/binary"
	"testing"

	bc "tracefall/internal/browsercache"
	parser "tracefall/internal/parsers/browsercache"
)

// headerThatFirefoxSniffAccepts builds a 512-byte header that the Firefox
// cache2 check accepts when it reads the trailing metadata offset from the
// header itself: version 1 at the start, a plausible key size, and a zero
// offset in the last four bytes. Ordinary files can look like this to that
// check, which is why a header alone must never claim a Firefox entry.
func headerThatFirefoxSniffAccepts() []byte {
	h := make([]byte, 512)
	binary.BigEndian.PutUint32(h[0:4], 1)   // version
	binary.BigEndian.PutUint32(h[24:28], 4) // key size
	return h                                // last four bytes stay zero
}

// Regression: an .m4a (Skype sample from a Windows 10 image) was claimed as
// browser cache by DetectContent through the Firefox check, then failed at
// import. The precondition guards against the fixture quietly stopping to
// exercise the bug.
func TestDetectContent_DoesNotClaimFromFirefoxHeaderAlone(t *testing.T) {
	h := headerThatFirefoxSniffAccepts()
	if !bc.SniffFirefoxCache2(h) {
		t.Fatal("fixture no longer passes the Firefox sniff, so this test would prove nothing; rebuild the header")
	}
	if (parser.Parser{}).DetectContent(h) {
		t.Fatal("DetectContent claimed a header on the Firefox check alone, which reads bytes that are not the trailing offset")
	}
}
