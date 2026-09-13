package userassist_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"tracefall/internal/userassist"
	"tracefall/internal/userassist/uagen"
)

const executablesGUID = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"

var runAt = time.Date(2021, 4, 29, 18, 17, 38, 0, time.UTC)

// ROT13 is its own inverse, and must leave everything that is not an
// ASCII letter exactly as it found it -- a GUID's braces and digits, a
// path's separators, and any non-ASCII character in a filename.
func TestROT13_IsSelfInverseAndTouchesOnlyASCIILetters(t *testing.T) {
	cases := []string{
		`C:\Windows\System32\notepad.exe`,
		`{6D809377-6AF0-444B-8957-A3773F02200E}\Vendor\app.exe`,
		"Microsoft.Windows.Explorer",
		"файл.exe",
		"日本語ファイル.exe",
		"MiXeD CaSe 12345 !@#$%^&*()",
		"",
	}
	for _, in := range cases {
		enc := userassist.ROT13(in)
		if got := userassist.ROT13(enc); got != in {
			t.Errorf("ROT13 is not self-inverse for %q: got %q", in, got)
		}
		// Every non-letter must survive untouched.
		inRunes, encRunes := []rune(in), []rune(enc)
		if len(inRunes) != len(encRunes) {
			t.Fatalf("ROT13 changed the length of %q", in)
		}
		for i, r := range inRunes {
			isASCIILetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			if !isASCIILetter && encRunes[i] != r {
				t.Errorf("ROT13 altered non-letter %q in %q", r, in)
			}
		}
	}
}

func TestDecode_Version5RoundTrip(t *testing.T) {
	plain := `{6D809377-6AF0-444B-8957-A3773F02200E}\Vendor\tool.exe`
	data := uagen.BuildV5(uagen.Entry{
		SessionID: 7, RunCount: 12, FocusCount: 30,
		FocusTime: 90 * time.Second, LastExecuted: runAt,
	})

	e, err := userassist.Decode(executablesGUID, uagen.Name(plain), data, userassist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if e.Version != 5 {
		t.Errorf("version = %d, want 5", e.Version)
	}
	if e.DecodedName != plain {
		t.Errorf("decoded name = %q, want %q", e.DecodedName, plain)
	}
	if e.EncodedName == e.DecodedName {
		t.Error("the encoded name was retained as the decoded one; both forms must be kept distinctly")
	}
	if e.SessionID != 7 || e.RunCount != 12 || e.RunCountRaw != 12 {
		t.Errorf("session=%d run=%d raw=%d, want 7/12/12", e.SessionID, e.RunCount, e.RunCountRaw)
	}
	if e.FocusCount != 30 || e.FocusTime != 90*time.Second || !e.HasFocusData {
		t.Errorf("focus = %d/%s/%v", e.FocusCount, e.FocusTime, e.HasFocusData)
	}
	if !e.LastExecuted.Equal(runAt) {
		t.Errorf("last executed = %s, want %s", e.LastExecuted, runAt)
	}
	// The known-folder prefix must be expanded, and the rest preserved.
	if want := `C:\Program Files (x86)\Vendor\tool.exe`; e.ResolvedPath != want {
		t.Errorf("resolved path = %q, want %q", e.ResolvedPath, want)
	}
	if e.GUIDMeaning == "" {
		t.Error("the documented executables GUID was not recognized")
	}
	if len(e.Warnings) != 0 {
		t.Errorf("unexpected warnings on a clean record: %v", e.Warnings)
	}
}

// Version 3's counter starts at 5, so the interpreted count and the
// stored one differ -- and both must be reported.
func TestDecode_Version3ReportsStoredAndAdjustedCounts(t *testing.T) {
	data := uagen.BuildV3(uagen.Entry{SessionID: 1, RunCount: 8, LastExecuted: runAt})
	e, err := userassist.Decode(executablesGUID, uagen.Name("notepad.exe"), data, userassist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if e.Version != 3 {
		t.Errorf("version = %d, want 3", e.Version)
	}
	if e.RunCountRaw != 8 {
		t.Errorf("raw count = %d, want the stored 8", e.RunCountRaw)
	}
	if e.RunCount != 3 {
		t.Errorf("interpreted count = %d, want 3 (8 minus the base of 5)", e.RunCount)
	}
	if e.HasFocusData {
		t.Error("version 3 records no focus data, but HasFocusData is set")
	}
	if !e.LastExecuted.Equal(runAt) {
		t.Errorf("last executed = %s, want %s", e.LastExecuted, runAt)
	}
}

// A counter below the version 3 base cannot be a launch tally. It must
// be reported as stored with a warning, never turned into a wrapped
// unsigned number by subtraction.
func TestDecode_Version3CounterBelowBaseWarnsInsteadOfUnderflowing(t *testing.T) {
	data := uagen.BuildV3(uagen.Entry{RunCount: 2, LastExecuted: runAt})
	e, err := userassist.Decode(executablesGUID, uagen.Name("odd.exe"), data, userassist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if e.RunCount != 2 {
		t.Errorf("count = %d, want the stored 2 reported unchanged", e.RunCount)
	}
	if e.RunCount > 1<<31 {
		t.Errorf("count underflowed to %d", e.RunCount)
	}
	if len(e.Warnings) == 0 {
		t.Error("a below-base counter was adjusted silently; it must warn")
	}
}

// An unrecognized record length is an unsupported layout, NOT corruption
// and NOT something to decode on a guess.
func TestDecode_UnknownLayoutIsDistinctFromCorruption(t *testing.T) {
	for _, size := range []int{1, 8, 15, 17, 40, 71, 73, 200} {
		data := make([]byte, size)
		_, err := userassist.Decode(executablesGUID, "abc", data, userassist.Limits{})
		if !errors.Is(err, userassist.ErrUnknownLayout) {
			t.Errorf("%d-byte record: err = %v, want ErrUnknownLayout", size, err)
		}
	}
	if _, err := userassist.Decode(executablesGUID, "abc", nil, userassist.Limits{}); !errors.Is(err, userassist.ErrEmptyValue) {
		t.Errorf("empty value: err = %v, want ErrEmptyValue", err)
	}
}

func TestDecode_TruncatedRecordIsRejected(t *testing.T) {
	full := uagen.BuildV5(uagen.Entry{RunCount: 3, LastExecuted: runAt})
	for _, keep := range []int{0, 1, 16, 60, 71} {
		_, err := userassist.Decode(executablesGUID, "abc", uagen.Truncate(full, keep), userassist.Limits{})
		if keep == 16 {
			// 16 bytes IS a valid version 3 record; a truncation that
			// lands on another layout's length is indistinguishable from
			// that layout, and must be read as it, not guessed at.
			if err != nil {
				t.Errorf("a 16-byte record must decode as version 3: %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("a %d-byte truncation was accepted", keep)
		}
	}
}

// A zero FILETIME means "not recorded". It must never become a date in
// 1601, and the entry must say so.
func TestDecode_MissingTimestampIsReportedNotFabricated(t *testing.T) {
	data := uagen.BuildV5(uagen.Entry{RunCount: 4}) // zero LastExecuted
	e, err := userassist.Decode(executablesGUID, uagen.Name("x.exe"), data, userassist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !e.LastExecuted.IsZero() {
		t.Errorf("a zero FILETIME became %s", e.LastExecuted)
	}
	if e.RunCount != 4 {
		t.Errorf("run count lost: %d", e.RunCount)
	}
	found := false
	for _, w := range e.Warnings {
		if strings.Contains(w, "timestamp") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning explains the missing timestamp: %v", e.Warnings)
	}
}

// An implausible FILETIME is treated as absent rather than surfaced as a
// date thousands of years away.
func TestDecode_ImplausibleTimestampIsTreatedAsAbsent(t *testing.T) {
	for _, ft := range []uint64{1, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF} {
		data := uagen.BuildV5(uagen.Entry{RunCount: 1})
		// Overwrite the timestamp field directly with the hostile value.
		for i := 0; i < 8; i++ {
			data[60+i] = byte(ft >> (8 * i))
		}
		e, err := userassist.Decode(executablesGUID, "abc", data, userassist.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if !e.LastExecuted.IsZero() {
			t.Errorf("FILETIME %#x produced %s; an implausible time must be treated as absent", ft, e.LastExecuted)
		}
	}
}

// An unknown GUID must not be given an invented meaning.
func TestDecode_UnknownGUIDIsNotNamed(t *testing.T) {
	e, err := userassist.Decode("{00000000-1111-2222-3333-444444444444}",
		uagen.Name("thing.exe"), uagen.BuildV5(uagen.Entry{RunCount: 1, LastExecuted: runAt}), userassist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if e.GUIDMeaning != "" {
		t.Errorf("an unknown GUID was named %q", e.GUIDMeaning)
	}
	if e.GUID == "" {
		t.Error("the GUID itself must still be reported")
	}
}

// Likewise an unknown known-folder prefix is left as decoded.
func TestDecode_UnknownFolderPrefixIsLeftAlone(t *testing.T) {
	plain := `{DEADBEEF-0000-0000-0000-000000000000}\app.exe`
	e, err := userassist.Decode(executablesGUID, uagen.Name(plain),
		uagen.BuildV5(uagen.Entry{RunCount: 1, LastExecuted: runAt}), userassist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if e.ResolvedPath != "" {
		t.Errorf("an unknown folder GUID was expanded to %q", e.ResolvedPath)
	}
	if e.DecodedName != plain {
		t.Errorf("decoded name = %q, want %q", e.DecodedName, plain)
	}
}

func TestDecode_LongNameIsBounded(t *testing.T) {
	huge := strings.Repeat("A", 100000)
	e, err := userassist.Decode(executablesGUID, huge,
		uagen.BuildV5(uagen.Entry{RunCount: 1, LastExecuted: runAt}),
		userassist.Limits{MaxNameBytes: 256})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.DecodedName) > 256 || len(e.EncodedName) > 256 {
		t.Errorf("names not bounded: encoded=%d decoded=%d", len(e.EncodedName), len(e.DecodedName))
	}
}

// CountKeyGUID must match the key's SHAPE, not merely the presence of
// the word "UserAssist" -- otherwise an unrelated key could be decoded
// as UserAssist.
func TestCountKeyGUID_MatchesShapeNotSubstring(t *testing.T) {
	good := `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\` + executablesGUID + `\Count`
	guid, ok := userassist.CountKeyGUID(good)
	if !ok || guid != strings.ToUpper(executablesGUID) {
		t.Errorf("valid Count key not matched: %q %v", guid, ok)
	}

	bad := []string{
		`Software\UserAssist`,
		`Software\UserAssist\Count`,
		`Software\UserAssist\{not-a-guid}\Count`,
		`Software\Evil\UserAssistData\` + executablesGUID + `\Count`,
		`Software\Microsoft\UserAssist\` + executablesGUID + `\Settings`,
		`Software\UserAssist\` + executablesGUID,
		"",
		`Count`,
	}
	for _, p := range bad {
		if _, ok := userassist.CountKeyGUID(p); ok {
			t.Errorf("non-UserAssist path %q was matched", p)
		}
	}
}

// Decoding must never panic on arbitrary bytes.
func TestDecode_NeverPanicsOnArbitraryData(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 17, 71, 72, 73}
	patterns := []byte{0x00, 0xFF, 0x41, 0x80}
	for _, size := range sizes {
		for _, p := range patterns {
			data := make([]byte, size)
			for i := range data {
				data[i] = p
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic on %d bytes of 0x%02X: %v", size, p, r)
					}
				}()
				_, _ = userassist.Decode("{}", "name", data, userassist.Limits{})
			}()
		}
	}
}

// The same input must always decode to the same output.
func TestDecode_IsDeterministic(t *testing.T) {
	data := uagen.BuildV5(uagen.Entry{SessionID: 2, RunCount: 9, FocusCount: 5,
		FocusTime: time.Second, LastExecuted: runAt})
	first, err := userassist.Decode(executablesGUID, uagen.Name("a.exe"), data, userassist.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := userassist.Decode(executablesGUID, uagen.Name("a.exe"), data, userassist.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if got.DecodedName != first.DecodedName || got.RunCount != first.RunCount ||
			!got.LastExecuted.Equal(first.LastExecuted) || got.SessionID != first.SessionID {
			t.Fatalf("iteration %d differs from the first decode", i)
		}
	}
}
