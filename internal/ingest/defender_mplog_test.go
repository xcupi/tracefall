package ingest

import (
	"testing"
	"unicode/utf16"

	"tracefall/internal/model"
)

func utf16Header(s string) []byte {
	b := []byte{0xff, 0xfe}
	for _, c := range utf16.Encode([]rune(s)) {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

// An engine support log is claimed by name AND by the layout of its first line,
// so an unrelated file with the same name is not read as one.
func TestMatchParser_DefenderSupportLog(t *testing.T) {
	good := utf16Header("\r\n2026-03-01T10:00:00.100 Engine:Setting original file name \"x.exe\"\r\n")
	for _, p := range []string{"ProgramData/Microsoft/Windows Defender/Support/MPLog-20260301-100000.log", "MPDetection-20260301-100000.log"} {
		got := MatchParser(p, good, Registry())
		if got == nil || got.ArtifactType() != model.ArtifactDefenderMPLog {
			t.Errorf("%s: matched %v", p, got)
		}
	}
	for name, header := range map[string][]byte{
		"not a log":    []byte("hello, this is just text\n"),
		"empty header": nil,
	} {
		if got := MatchParser("Support/MPLog-20260301-100000.log", header, Registry()); got != nil && got.ArtifactType() == model.ArtifactDefenderMPLog {
			t.Errorf("%s was claimed as a support log", name)
		}
	}
	if got := MatchParser("Support/other.log", good, Registry()); got != nil && got.ArtifactType() == model.ArtifactDefenderMPLog {
		t.Error("a differently named file was claimed")
	}
}
