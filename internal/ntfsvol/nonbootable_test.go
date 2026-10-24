package ntfsvol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// Derive only the omitted DOS boot fields from the independently generated
// mkntfs/ntfs-3g fixture. The complete filesystem and its manifest stay intact.
func nonbootableFixture(t *testing.T) ([]byte, manifest) {
	t.Helper()
	data, m := load(t)
	clear(data[:3])
	clear(data[510:512])
	return data, m
}

func TestOpen_NonbootableVolumeRetainsEveryManifestFile(t *testing.T) {
	data, m := nonbootableFixture(t)
	before := sum(data)
	v, err := Open(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("valid filesystem with absent DOS boot fields: %v", err)
	}
	if len(v.Info().Warnings) != 1 {
		t.Fatalf("missing format warning: %+v", v.Info())
	}
	original, _ := load(t)
	if got := openVol(t, original).Info().Warnings; len(got) != 0 {
		t.Fatalf("ordinary fixture gained a warning: %v", got)
	}
	files, stats := walkAll(t, v)
	if stats.CorruptCount != 0 {
		t.Fatalf("corrupt records: %+v", stats)
	}
	for path, want := range m.Volume.Files {
		f, ok := files[path]
		if !ok {
			t.Errorf("missing %s", path)
			continue
		}
		if f.Size != want.Size || sum(readStream(t, v, f.Record, "")) != want.SHA256 {
			t.Errorf("changed contents: %s", path)
		}
	}
	if sum(data) != before {
		t.Fatal("reader changed the input")
	}
}

func TestOpen_NonbootableVolumeRejectsInvalidStructures(t *testing.T) {
	clean, _ := nonbootableFixture(t)
	original, _ := load(t)
	v := openVol(t, original)
	rootOff := v.mftByteOffsetForTest(rootRecord)
	mftOff := int(binary.LittleEndian.Uint64(clean[48:])) * v.cluster
	cases := []struct {
		name   string
		change func([]byte)
		want   error
	}{
		{"nonzero_marker", func(b []byte) { b[510] = 1 }, ErrNotNTFS},
		{"half_signature", func(b []byte) { b[510] = 0x55 }, ErrNotNTFS},
		{"missing_marker_with_jump", func(b []byte) { b[0] = 0xeb }, ErrNotNTFS},
		{"wrong_oem", func(b []byte) { b[3] = 'X' }, ErrNotNTFS},
		{"geometry", func(b []byte) { b[13] = 3 }, ErrCorrupt},
		{"mft_fixup", func(b []byte) { b[mftOff+510] ^= 1 }, ErrCorrupt},
		{"root_fixup", func(b []byte) { b[rootOff+510] ^= 1 }, ErrCorrupt},
		{"root_not_directory", func(b []byte) { b[rootOff+22] = recInUse }, ErrCorrupt},
		{"root_not_in_use", func(b []byte) { b[rootOff+22] = recDir }, ErrCorrupt},
		{"root_blank", func(b []byte) { clear(b[rootOff : rootOff+4]) }, ErrCorrupt},
		{"root_sequence_mismatch", func(b []byte) { b[rootOff+16] ^= 1 }, ErrCorrupt},
		{"root_extension_record", func(b []byte) { b[rootOff+32] = 1 }, ErrCorrupt},
		{"mft_outside_volume", func(b []byte) { binary.LittleEndian.PutUint64(b[48:], uint64(len(b))) }, ErrCorrupt},
		{"truncated_volume", func(b []byte) { binary.LittleEndian.PutUint64(b[40:], uint64(len(b))) }, ErrCorrupt},
		{"oem_only", func(b []byte) { clear(b[11:510]) }, ErrCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := bytes.Clone(clean)
			tc.change(b)
			if _, err := Open(bytes.NewReader(b), int64(len(b))); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
