package prefetch_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracefall/internal/prefetch"
	"tracefall/internal/prefetch/prefetchgen"
)

var runTime = time.Date(2026, 3, 1, 9, 15, 30, 0, time.UTC)

func sample(version uint32) prefetchgen.File {
	return prefetchgen.File{
		Version:        version,
		ExecutableName: "POWERSHELL.EXE",
		PrefetchHash:   0xA1B2C3D4,
		RunCount:       7,
		LastRunTimes: []time.Time{
			runTime, runTime.Add(-time.Hour), runTime.Add(-2 * time.Hour),
		},
		Filenames: []string{
			`\VOLUME{01d7}\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE`,
			`\VOLUME{01d7}\WINDOWS\SYSTEM32\NTDLL.DLL`,
			`\VOLUME{01d7}\USERS\JDOE\APPDATA\LOCAL\TEMP\STAGE.PS1`,
		},
		VolumeDevicePath: `\DEVICE\HARDDISKVOLUME2`,
		VolumeSerial:     0xDEADBEEF,
		VolumeCreated:    runTime.Add(-1000 * time.Hour),
	}
}

func writePF(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "POWERSHELL.EXE-A1B2C3D4.pf")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSniff(t *testing.T) {
	valid := prefetchgen.Build(sample(30))
	if !prefetch.Sniff(valid) {
		t.Error("Sniff rejected a valid Prefetch file")
	}
	// A compressed file must still be RECOGNIZED as Prefetch, so it is
	// reported as an unreadable Prefetch rather than an unknown artifact.
	if !prefetch.Sniff(prefetchgen.Compressed(4096)) {
		t.Error("Sniff rejected a MAM-compressed Prefetch")
	}
	if prefetch.Sniff([]byte("regf....")) {
		t.Error("Sniff accepted a registry hive")
	}
	if prefetch.Sniff(nil) {
		t.Error("Sniff accepted an empty header")
	}
}

// Every supported version must round-trip the fields an investigator
// actually uses.
func TestParse_AllSupportedVersions(t *testing.T) {
	for _, v := range []uint32{17, 23, 26, 30, 31} {
		t.Run(versionName(v), func(t *testing.T) {
			got, err := prefetch.Parse(writePF(t, prefetchgen.Build(sample(v))), prefetch.Limits{})
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got.Version != v {
				t.Errorf("Version = %d, want %d", got.Version, v)
			}
			if got.ExecutableName != "POWERSHELL.EXE" {
				t.Errorf("ExecutableName = %q", got.ExecutableName)
			}
			if got.RunCount != 7 {
				t.Errorf("RunCount = %d, want 7", got.RunCount)
			}
			if got.PrefetchHash != 0xA1B2C3D4 {
				t.Errorf("PrefetchHash = %#x", got.PrefetchHash)
			}
			if len(got.Filenames) != 3 {
				t.Fatalf("Filenames = %d, want 3: %v", len(got.Filenames), got.Filenames)
			}
			// The executable's own path must be identified from the
			// referenced files, not guessed.
			if got.ExecutablePath == "" {
				t.Error("ExecutablePath not identified from the referenced files")
			}
			if len(got.LastRunTimes) == 0 {
				t.Fatal("no last-run times")
			}
			if !got.LastRunTimes[0].Equal(runTime) {
				t.Errorf("most recent run = %v, want %v", got.LastRunTimes[0], runTime)
			}
			// v17/v23 record one run time; v26+ record up to eight.
			wantTimes := 1
			if v >= 26 {
				wantTimes = 3
			}
			if len(got.LastRunTimes) != wantTimes {
				t.Errorf("LastRunTimes = %d, want %d for version %d", len(got.LastRunTimes), wantTimes, v)
			}
			if len(got.Volumes) != 1 || got.Volumes[0].DevicePath != `\DEVICE\HARDDISKVOLUME2` {
				t.Errorf("volume not read: %+v", got.Volumes)
			}
			if got.Volumes[0].SerialNumber != 0xDEADBEEF {
				t.Errorf("volume serial = %#x", got.Volumes[0].SerialNumber)
			}
		})
	}
}

func versionName(v uint32) string {
	switch v {
	case 17:
		return "v17_WinXP"
	case 23:
		return "v23_Vista_Win7"
	case 26:
		return "v26_Win8"
	case 30:
		return "v30_Win10"
	default:
		return "v31_Win11"
	}
}

// Empty run-time slots must be dropped, not reported as 1601 timestamps.
func TestParse_EmptyRunTimeSlotsAreNotInventedTimestamps(t *testing.T) {
	f := sample(30)
	f.LastRunTimes = []time.Time{runTime} // one real run; seven empty slots
	got, err := prefetch.Parse(writePF(t, prefetchgen.Build(f)), prefetch.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.LastRunTimes) != 1 {
		t.Fatalf("LastRunTimes = %v, want exactly the one real run", got.LastRunTimes)
	}
	for _, ts := range got.LastRunTimes {
		if ts.Year() < 1990 {
			t.Errorf("an empty slot became timestamp %v", ts)
		}
	}
}

// ---------- malformed input ----------

func TestParse_MalformedIsAStructuredError(t *testing.T) {
	valid := prefetchgen.Build(sample(30))

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"bad signature", prefetchgen.CorruptSignature(valid), prefetch.ErrNotPrefetch},
		{"empty file", nil, prefetch.ErrCorrupt},
		{"truncated header", prefetchgen.Truncate(valid, 40), prefetch.ErrCorrupt},
		{"truncated file information", prefetchgen.Truncate(valid, 120), prefetch.ErrCorrupt},
		{"unsupported version", prefetchgen.SetVersion(valid, 99), prefetch.ErrUnsupportedVersion},
		// A MAM container announcing LZXPRESS Huffman whose stream is
		// not decodable. Compression is supported now, so this is a
		// CORRUPT stream rather than a capability gap.
		{"MAM with undecodable stream", prefetchgen.Compressed(4096), prefetch.ErrDecompress},
		{"MAM with unknown compression method", prefetchgen.CompressedMethod(4096, 0x03), prefetch.ErrUnsupportedCompression},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prefetch.Parse(writePF(t, tc.data), prefetch.Limits{})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want one wrapping %v", err, tc.want)
			}
		})
	}
}

// A filename-section offset pointing outside the file must be rejected,
// not followed.
func TestParse_FilenameOffsetOutsideFileIsRejected(t *testing.T) {
	bad := prefetchgen.CorruptFilenameOffset(prefetchgen.Build(sample(30)))
	if _, err := prefetch.Parse(writePF(t, bad), prefetch.Limits{}); !errors.Is(err, prefetch.ErrCorrupt) {
		t.Errorf("error = %v, want ErrCorrupt", err)
	}
}

func TestParse_RespectsFileSizeLimit(t *testing.T) {
	_, err := prefetch.Parse(writePF(t, prefetchgen.Build(sample(30))), prefetch.Limits{MaxFileBytes: 16})
	if !errors.Is(err, prefetch.ErrLimitExceeded) {
		t.Errorf("error = %v, want ErrLimitExceeded", err)
	}
}

// Every byte is attacker-controlled: flipping any of them must never
// panic or hang.
func TestFuzzedPrefetchNeverPanics(t *testing.T) {
	valid := prefetchgen.Build(sample(30))
	for offset := 0; offset < len(valid); offset += 7 {
		for _, b := range []byte{0x00, 0xff, 0x7f} {
			corrupt := append([]byte(nil), valid...)
			corrupt[offset] = b
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic with byte %d set to %#x: %v", offset, b, r)
					}
				}()
				_, _ = prefetch.ParseBytes(corrupt, prefetch.Limits{})
			}()
		}
	}
}

func TestParse_IsDeterministic(t *testing.T) {
	path := writePF(t, prefetchgen.Build(sample(30)))
	first, err := prefetch.Parse(path, prefetch.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := prefetch.Parse(path, prefetch.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := fmtPF(again), fmtPF(first); got != want {
			t.Fatalf("run %d differed:\n%s\n%s", i, want, got)
		}
	}
}

func fmtPF(p prefetch.Prefetch) string {
	s := p.ExecutableName + "|" + p.ExecutablePath
	for _, t := range p.LastRunTimes {
		s += "|" + t.Format(time.RFC3339Nano)
	}
	for _, f := range p.Filenames {
		s += "|" + f
	}
	for _, v := range p.Volumes {
		s += "|" + v.DevicePath
	}
	return s
}
