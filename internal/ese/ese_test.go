package ese_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/rand"
	"runtime"
	"strings"
	"testing"
	"time"

	"tracefall/internal/ese"
	"tracefall/internal/ese/esegen"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func open(t *testing.T, raw []byte) *ese.DB {
	t.Helper()
	db, err := ese.Open(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return db
}

func openErr(raw []byte) (*ese.DB, error) {
	return ese.Open(bytes.NewReader(raw), int64(len(raw)))
}

func rowsOf(t *testing.T, tb *ese.Table) ([]ese.Row, ese.Stats) {
	t.Helper()
	var rows []ese.Row
	st, err := tb.Scan(func(r ese.Row) error { rows = append(rows, r); return nil })
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return rows, st
}

func val(t *testing.T, r ese.Row, name string) ese.Value {
	t.Helper()
	v, ok := r.Get(name)
	if !ok {
		t.Fatalf("no column %q", name)
	}
	return v
}

// the columns every table below uses.
func cols() []esegen.Column {
	return []esegen.Column{
		{ID: 1, Name: "Id", Type: esegen.Int32},
		{ID: 2, Name: "Big", Type: esegen.Int64},
		{ID: 3, Name: "When", Type: esegen.DateTime},
		{ID: 128, Name: "Name", Type: esegen.Text, Codepage: 1252, MaxLen: 255},
		{ID: 129, Name: "Wide", Type: esegen.Text, Codepage: 1200, MaxLen: 255},
		{ID: 130, Name: "Blob", Type: esegen.Binary, MaxLen: 255},
		{ID: 256, Name: "Note", Type: esegen.LongText, Codepage: 1200, Flags: 0x2},
		{ID: 257, Name: "Data", Type: esegen.LongBinary, Flags: 0x2},
		{ID: 258, Name: "Tags", Type: esegen.Text, Codepage: 1252, Flags: 0x402},
		{ID: 259, Name: "Packed", Type: esegen.LongText, Codepage: 1252, Flags: 0x2},
	}
}

func both(t *testing.T, fn func(t *testing.T, ps int)) {
	for _, ps := range []int{4096, 32768} {
		ps := ps
		t.Run(map[int]string{4096: "4k", 32768: "32k"}[ps], func(t *testing.T) { fn(t, ps) })
	}
}

func TestRows_FixedVariableAndNull(t *testing.T) {
	both(t, func(t *testing.T, ps int) {
		raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: []esegen.Record{
			{
				Fixed: map[uint32][]byte{1: esegen.Le32(0xFFFFFFFE), 2: esegen.Le64(1 << 40), 3: esegen.Le64(0x40E5EFF000000000)},
				Var:   map[uint32][]byte{128: []byte("alice"), 129: esegen.UTF16("héllo"), 130: {0xde, 0xad}},
			},
			{Fixed: map[uint32][]byte{1: esegen.Le32(7)}}, // everything else null
			{Var: map[uint32][]byte{129: esegen.UTF16("only-wide")}},
		}}}, esegen.Options{PageSize: ps})
		db := open(t, raw)
		if db.PageSize != ps || db.State != ese.StateCleanShutdown || !db.HeaderChecksumOK {
			t.Fatalf("header: page=%d state=%v checksum=%v", db.PageSize, db.State, db.HeaderChecksumOK)
		}
		tb := db.Table("T")
		if tb == nil {
			t.Fatalf("table T not in catalog: %v", db.Tables())
		}
		rows, st := rowsOf(t, tb)
		if len(rows) != 3 || st.Live != 3 || st.Defunct != 0 || st.Unreadable != 0 {
			t.Fatalf("rows=%d stats=%+v", len(rows), st)
		}
		r := rows[0]
		if v := val(t, r, "Id"); v.Null || v.Int() != int64(int32(-2)) {
			t.Errorf("Id = %+v / %d, want -2 (signed)", v, v.Int())
		}
		if v := val(t, r, "Big"); v.Int() != 1<<40 {
			t.Errorf("Big = %d", v.Int())
		}
		if v := val(t, r, "When"); true {
			tm, ok := v.Time()
			want := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
			if !ok || !tm.Equal(want) {
				t.Errorf("When = %v ok=%v, want %v", tm, ok, want)
			}
		}
		if got := val(t, r, "Name").Text(); got != "alice" {
			t.Errorf("Name = %q", got)
		}
		if got := val(t, r, "Wide").Text(); got != "héllo" {
			t.Errorf("Wide = %q (UTF-16 not decoded)", got)
		}
		if got := val(t, r, "Blob").Raw; !bytes.Equal(got, []byte{0xde, 0xad}) {
			t.Errorf("Blob = %x", got)
		}
		r2 := rows[1]
		if val(t, r2, "Id").Int() != 7 {
			t.Errorf("row 2 Id = %d", val(t, r2, "Id").Int())
		}
		for _, n := range []string{"Big", "When", "Name", "Wide", "Blob", "Note"} {
			if !val(t, r2, n).Null {
				t.Errorf("row 2 %s should be null, got %+v", n, val(t, r2, n))
			}
		}
		// fixed columns past the record's last stored one are null, and a
		// variable column in the middle that was skipped is null.
		if n := val(t, rows[2], "Name"); n.Err != nil || !n.Null {
			t.Errorf("row 3 Name: a skipped variable column must be a clean null, got err=%v null=%v", n.Err, n.Null)
		}
		if !val(t, rows[2], "Id").Null || !val(t, rows[2], "Name").Null || val(t, rows[2], "Wide").Text() != "only-wide" {
			t.Errorf("row 3: Id null=%v Name null=%v Wide=%q", val(t, rows[2], "Id").Null, val(t, rows[2], "Name").Null, val(t, rows[2], "Wide").Text())
		}
	})
}

func TestRows_DefunctRecordIsFlaggedAndCounted(t *testing.T) {
	both(t, func(t *testing.T, ps int) {
		raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: []esegen.Record{
			{Fixed: map[uint32][]byte{1: esegen.Le32(1)}},
			{Fixed: map[uint32][]byte{1: esegen.Le32(2)}, Defunct: true},
			{Fixed: map[uint32][]byte{1: esegen.Le32(3)}},
		}}}, esegen.Options{PageSize: ps})
		rows, st := rowsOf(t, open(t, raw).Table("T"))
		if st.Live != 2 || st.Defunct != 1 || len(rows) != 3 {
			t.Fatalf("stats=%+v rows=%d", st, len(rows))
		}
		var defunct []int64
		for _, r := range rows {
			if r.Defunct {
				defunct = append(defunct, val(t, r, "Id").Int())
			}
		}
		if len(defunct) != 1 || defunct[0] != 2 {
			t.Errorf("defunct ids = %v, want [2]", defunct)
		}
	})
}

func TestRows_UnreadableEntriesAreCountedNotReturned(t *testing.T) {
	both(t, func(t *testing.T, ps int) {
		raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: []esegen.Record{
			{Fixed: map[uint32][]byte{1: esegen.Le32(1)}},
			{Raw: []byte{0}},                // a live entry too short to be a record
			{Raw: []byte{0}, Defunct: true}, // the stub a deletion leaves
			{Fixed: map[uint32][]byte{1: esegen.Le32(4)}},
		}}}, esegen.Options{PageSize: ps})
		rows, st := rowsOf(t, open(t, raw).Table("T"))
		if len(rows) != 2 || st.Live != 2 || st.Unreadable != 1 || st.DefunctUnreadable != 1 {
			t.Fatalf("rows=%d stats=%+v", len(rows), st)
		}
	})
}

func TestTree_RecordsAcrossLeafPagesKeepKeyOrder(t *testing.T) {
	for _, common := range []bool{false, true} {
		var recs []esegen.Record
		for i := 0; i < 40; i++ {
			k := append([]byte("shared-prefix-"), byte('a'+i/10), byte('0'+i%10))
			recs = append(recs, esegen.Record{Key: k, Fixed: map[uint32][]byte{1: esegen.Le32(uint32(i))}})
		}
		raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: recs, LeafCapacity: 7, CommonKeys: common}}, esegen.Options{})
		rows, st := rowsOf(t, open(t, raw).Table("T"))
		if len(rows) != 40 || st.Live != 40 {
			t.Fatalf("common=%v rows=%d stats=%+v", common, len(rows), st)
		}
		for i, r := range rows {
			if val(t, r, "Id").Int() != int64(i) {
				t.Fatalf("common=%v row %d has Id %d", common, i, val(t, r, "Id").Int())
			}
		}
	}
}

func TestCompression_SevenBitXpressAndNone(t *testing.T) {
	sevenAscii := mustHex("c8329bfd0699e5ef36280c9a97ed6537489ca683c66f76bded66818ad322684e7fcbcb73101d9d9e83e0e1f1ba4c7601")
	const sentence = "Hello from a seven bit column, ESE stores this packed."
	// vectors made by an independent encoder and decoded back by dissect.util.
	xp := func(stream string, n int) []byte {
		b := []byte{3 << 3, byte(n), byte(n >> 8)}
		return append(b, mustHex(stream)...)
	}
	cases := []struct {
		name string
		col  uint32
		data []byte
		want string
	}{
		{"7bit ascii", 259, append([]byte{1 << 3}, sevenAscii...), sentence},
		{"xpress short repeat", 259, xp("0000001861626317000f02", 30), "abcabcabcabcabcabcabcabcabcabc"},
		{"xpress long match", 259, xp("0000001861626317000fff2601", 300), string(bytes.Repeat([]byte("abc"), 100))},
		{"xpress very long run", 259, xp("000000604107000fffb40b", 3000), string(bytes.Repeat([]byte("A"), 3000))},
		{"xpress text with several matches", 259, xp("0000000054686520717569636b2062726f776e20666f78206a756d7073206f766572207440011080f0006c617a7920646f672e2067017f1220616761696e2c20616e6457002e", 117),
			"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog again, and again, and again."},
		{"scheme none", 259, append([]byte{0}, []byte("plain")...), "\x00plain"},
	}
	both(t, func(t *testing.T, ps int) {
		for _, c := range cases {
			raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: []esegen.Record{
				{Fixed: map[uint32][]byte{1: esegen.Le32(1)}, Tagged: []esegen.Tagged{{ID: c.col, Flags: esegen.TagCompressed, Data: c.data}}},
			}}}, esegen.Options{PageSize: ps})
			rows, _ := rowsOf(t, open(t, raw).Table("T"))
			v := val(t, rows[0], "Packed")
			if v.Err != nil || v.Text() != c.want {
				t.Errorf("%s: err=%v got %q", c.name, v.Err, v.Text())
			}
		}
	})
	t.Run("7bit unicode", func(t *testing.T) {
		raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: []esegen.Record{
			{Tagged: []esegen.Tagged{{ID: 256, Flags: esegen.TagCompressed, Data: append([]byte{2 << 3}, sevenAscii...)}}},
		}}}, esegen.Options{})
		rows, _ := rowsOf(t, open(t, raw).Table("T"))
		if v := val(t, rows[0], "Note"); v.Err != nil || v.Text() != sentence {
			t.Errorf("err=%v got %q", v.Err, v.Text())
		}
	})
}

func TestCompression_RejectsWhatItCannotDecode(t *testing.T) {
	bad := map[string][]byte{
		"xpress9":                   {5 << 3, 1, 2, 3},
		"xpress10":                  {6 << 3, 1, 2, 3},
		"xpress match before start": {3 << 3, 9, 0, 0, 0, 0, 0x80, 8, 0},
		// a literal, then a match whose long form announces a length below the minimum
		"xpress impossible long length": {3 << 3, 9, 0, 0, 0, 0, 0x40, 'a', 7, 0, 0x0F, 255, 10, 0},
		"xpress cut flags":              {3 << 3, 9, 0, 0xff},
		"xpress cut literal":            {3 << 3, 9, 0, 0, 0, 0, 0},
	}
	for name, data := range bad {
		raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: []esegen.Record{
			{Fixed: map[uint32][]byte{1: esegen.Le32(1)}, Tagged: []esegen.Tagged{{ID: 259, Flags: esegen.TagCompressed, Data: data}}},
		}}}, esegen.Options{})
		rows, _ := rowsOf(t, open(t, raw).Table("T"))
		v := val(t, rows[0], "Packed")
		if v.Err == nil {
			t.Errorf("%s: decoded to %q instead of failing", name, v.Raw)
		}
		if name == "xpress9" && (v.Err == nil || !errors.Is(v.Err, ese.ErrUnsupported) || !strings.Contains(v.Err.Error(), "XPRESS9")) {
			t.Errorf("xpress9 must say what it is, got %v", v.Err)
		}
		if val(t, rows[0], "Id").Int() != 1 {
			t.Errorf("%s: a bad column must not spoil the rest of the row", name)
		}
	}
}

func TestMultiValue_RegularTwoValueAndSeparatedParts(t *testing.T) {
	raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), HasLVTree: true,
		LongValues: []esegen.LongValue{{ID: 9, Total: 5, Segments: []esegen.Segment{{Offset: 0, Data: []byte("SEPAR")}}}},
		Records: []esegen.Record{
			{Tagged: []esegen.Tagged{{ID: 258, Flags: esegen.TagMulti, Data: esegen.Multi([]byte("one"), []byte("two"), []byte("three"))}}},
			{Tagged: []esegen.Tagged{{ID: 258, Flags: esegen.TagMulti | esegen.TagTwoValues, Data: esegen.TwoValues([]byte("left"), []byte("right"))}}},
			{Tagged: []esegen.Tagged{{ID: 258, Flags: esegen.TagMulti, Data: markSeparated(esegen.Multi([]byte("a"), esegen.LongValueRef(9), []byte("c")), 1)}}},
		}}}, esegen.Options{})
	rows, _ := rowsOf(t, open(t, raw).Table("T"))
	want := [][]string{{"one", "two", "three"}, {"left", "right"}, {"a", "SEPAR", "c"}}
	for i, r := range rows {
		v := val(t, r, "Tags")
		if v.Err != nil {
			t.Fatalf("row %d: %v", i, v.Err)
		}
		var got []string
		for _, m := range v.Multi {
			got = append(got, string(m))
		}
		if len(got) != len(want[i]) {
			t.Fatalf("row %d: %q, want %q", i, got, want[i])
		}
		for j := range got {
			if got[j] != want[i][j] {
				t.Errorf("row %d value %d = %q, want %q", i, j, got[j], want[i][j])
			}
		}
	}
}

// markSeparated sets the "stored in the long value tree" bit on the offset of
// the n-th value of a multi-value blob.
func markSeparated(b []byte, n int) []byte {
	b = append([]byte(nil), b...)
	b[2*n+1] |= 0x80
	return b
}

func TestLongValue_SeparatedSegmentsAndTheirFaults(t *testing.T) {
	seg := func(off uint32, s string) esegen.Segment { return esegen.Segment{Offset: off, Data: []byte(s)} }
	table := func(lv esegen.LongValue) []byte {
		return esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), HasLVTree: true, LongValues: []esegen.LongValue{lv},
			Records: []esegen.Record{{Fixed: map[uint32][]byte{1: esegen.Le32(1)},
				Tagged: []esegen.Tagged{{ID: 257, Flags: esegen.TagLongValue | esegen.TagSeparated, Data: esegen.LongValueRef(lv.ID)}}}}}}, esegen.Options{})
	}
	get := func(raw []byte) ese.Value {
		rows, _ := rowsOf(t, open(t, raw).Table("T"))
		return val(t, rows[0], "Data")
	}
	if v := get(table(esegen.LongValue{ID: 5, Total: 9, Segments: []esegen.Segment{seg(0, "abc"), seg(3, "def"), seg(6, "ghi")}})); v.Err != nil || string(v.Raw) != "abcdefghi" {
		t.Errorf("good value: err=%v %q", v.Err, v.Raw)
	}
	faults := map[string]esegen.LongValue{
		"gap between segments":        {ID: 5, Total: 9, Segments: []esegen.Segment{seg(0, "abc"), seg(4, "efghi")}},
		"short against the header":    {ID: 5, Total: 12, Segments: []esegen.Segment{seg(0, "abc")}},
		"no segments":                 {ID: 5, Total: 3},
		"larger than the allowed cap": {ID: 5, Total: 1 << 30, Segments: []esegen.Segment{seg(0, "abc")}},
	}
	// a header that claims a gigabyte must be refused before anything that size
	// is allocated
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	get(table(faults["larger than the allowed cap"]))
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("a long value header claiming 1 GiB made the reader allocate %d MiB", grew>>20)
	}
	for name, lv := range faults {
		if v := get(table(lv)); v.Err == nil {
			t.Errorf("%s: returned %q instead of an error", name, v.Raw)
		} else if !errors.Is(v.Err, ese.ErrCorrupt) {
			t.Errorf("%s: error %v is not ErrCorrupt", name, v.Err)
		}
	}
	// a reference to a value that is not in the tree
	raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), HasLVTree: true,
		LongValues: []esegen.LongValue{{ID: 5, Total: 3, Segments: []esegen.Segment{seg(0, "abc")}}},
		Records:    []esegen.Record{{Tagged: []esegen.Tagged{{ID: 257, Flags: esegen.TagLongValue | esegen.TagSeparated, Data: esegen.LongValueRef(77)}}}}}}, esegen.Options{})
	if v := get(raw); v.Err == nil {
		t.Errorf("dangling reference returned %q", v.Raw)
	}
}

func TestCatalog_FallsBackToTheShadowCopy(t *testing.T) {
	tb := []esegen.Table{{Name: "T", Columns: cols(), Records: []esegen.Record{{Fixed: map[uint32][]byte{1: esegen.Le32(5)}}}}}
	db := open(t, esegen.Build(tb, esegen.Options{BrokenCatalog: true}))
	rows, _ := rowsOf(t, db.Table("T"))
	if len(rows) != 1 || val(t, rows[0], "Id").Int() != 5 {
		t.Fatalf("rows via shadow catalog: %d", len(rows))
	}
	// with neither readable the open fails with a reason
	raw := esegen.Build(tb, esegen.Options{BrokenCatalog: true})
	for i := 25 * 4096; i < 26*4096; i++ {
		raw[i] = 0
	}
	if _, err := openErr(raw); !errors.Is(err, ese.ErrCorrupt) {
		t.Errorf("no catalog at all: err = %v, want ErrCorrupt", err)
	}
}

func TestTemplateTable_DerivedTableInheritsColumns(t *testing.T) {
	tmpl := esegen.Table{Name: "Tmpl", Columns: cols()}
	derived := esegen.Table{Name: "T-1", Template: "Tmpl", Columns: []esegen.Column{{ID: 260, Name: "Extra", Type: esegen.LongBinary}},
		Records: []esegen.Record{{Fixed: map[uint32][]byte{1: esegen.Le32(3)}, Var: map[uint32][]byte{128: []byte("inherited")}}}}
	db := open(t, esegen.Build([]esegen.Table{tmpl, derived}, esegen.Options{}))
	rows, _ := rowsOf(t, db.Table("T-1"))
	if got := val(t, rows[0], "Name").Text(); got != "inherited" {
		t.Errorf("Name = %q", got)
	}
	if db.Table("T-1").Column("Extra") == nil {
		t.Errorf("own column lost")
	}
}

func TestOpen_RefusesWhatItCannotRead(t *testing.T) {
	good := esegen.Build([]esegen.Table{{Name: "T", Columns: cols()}}, esegen.Options{})
	mut := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty", nil, ese.ErrCorrupt},
		{"not ESE", bytes.Repeat([]byte("MZ"), 4096), ese.ErrNotESE},
		{"streaming file", mut(func(b []byte) []byte { b[12] = 1; return b }), ese.ErrUnsupported},
		{"unknown format version", mut(func(b []byte) []byte { b[8] = 0x30; return b }), ese.ErrUnsupported},
		{"absurd page size", mut(func(b []byte) []byte { b[236], b[237] = 0x11, 0x11; return b }), ese.ErrCorrupt},
		{"file ends in the header pages", good[:6000], ese.ErrCorrupt},
	}
	for _, c := range cases {
		if _, err := openErr(c.raw); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	// a dirty database opens and says so
	dirty := open(t, esegen.Build([]esegen.Table{{Name: "T", Columns: cols()}}, esegen.Options{State: 2}))
	if dirty.State != ese.StateDirtyShutdown {
		t.Errorf("state = %v", dirty.State)
	}
	// a damaged header checksum is reported, not fatal
	bad := mut(func(b []byte) []byte { b[300] ^= 0xFF; return b })
	if db := open(t, bad); db.HeaderChecksumOK {
		t.Errorf("a changed header still passes its checksum")
	}
}

func TestHostile_TreeThatLoopsOrPointsOutsideTheFile(t *testing.T) {
	recs := []esegen.Record{{Key: []byte{1}, Fixed: map[uint32][]byte{1: esegen.Le32(1)}}, {Key: []byte{2}, Fixed: map[uint32][]byte{1: esegen.Le32(2)}}}
	raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: recs, LeafCapacity: 1}}, esegen.Options{})
	db := open(t, raw)
	root := db.Table("T").FDP
	patch := func(from, to uint32) []byte {
		b := append([]byte(nil), raw...)
		page := b[(int(root)+1)*4096 : (int(root)+2)*4096]
		old := esegen.Le32(from)
		i := bytes.Index(page[40:], old)
		if i < 0 {
			t.Fatalf("child pointer %d not found in root page %d", from, root)
		}
		copy(page[40+i:], esegen.Le32(to))
		return b
	}
	child := root + 1
	// the root's child is the root itself: a cycle
	loop := open(t, patch(child, root))
	if _, err := loop.Table("T").Scan(func(ese.Row) error { return nil }); !errors.Is(err, ese.ErrCorrupt) {
		t.Errorf("cycle: err = %v, want ErrCorrupt", err)
	}
	// two entries of the root lead to the same child: its rows would be
	// reported twice if the tree were followed blindly
	diamond := open(t, patch(child+1, child))
	n := 0
	if _, err := diamond.Table("T").Scan(func(ese.Row) error { n++; return nil }); !errors.Is(err, ese.ErrCorrupt) {
		t.Errorf("shared child: err = %v after %d rows, want ErrCorrupt", err, n)
	}
	// a child number beyond the end of the file
	far := open(t, patch(child, 9_000_000))
	if _, err := far.Table("T").Scan(func(ese.Row) error { return nil }); !errors.Is(err, ese.ErrCorrupt) {
		t.Errorf("out of file: err = %v, want ErrCorrupt", err)
	}
	// page 0 does not exist
	zero := open(t, patch(child, 0))
	if _, err := zero.Table("T").Scan(func(ese.Row) error { return nil }); !errors.Is(err, ese.ErrCorrupt) {
		t.Errorf("page 0: err = %v, want ErrCorrupt", err)
	}
}

func TestHostile_PageClaimingMoreTagsThanItCanHold(t *testing.T) {
	raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: []esegen.Record{{Fixed: map[uint32][]byte{1: esegen.Le32(1)}}}}}, esegen.Options{})
	db := open(t, raw)
	fdp := db.Table("T").FDP
	b := append([]byte(nil), raw...)
	b[(int(fdp)+1)*4096+34], b[(int(fdp)+1)*4096+35] = 0xFF, 0x0F
	db2 := open(t, b)
	if _, err := db2.Table("T").Scan(func(ese.Row) error { return nil }); !errors.Is(err, ese.ErrCorrupt) {
		t.Errorf("err = %v, want ErrCorrupt", err)
	}
}

func TestHostile_RecordBodiesThatLie(t *testing.T) {
	lies := map[string][]byte{
		"variable data offset past the end":  {1, 128, 0xFF, 0xFF, 0, 0, 0, 0},
		"variable offset before the header":  {1, 128, 1, 0, 0, 0, 0, 0},
		"null bitmap larger than the record": {200, 0, 8, 0, 0, 0, 0, 0},
		"size array runs past the record":    {0, 255, 4, 0},
		"tagged table claims more than fits": {0, 0, 4, 0, 1, 1, 0xFF, 0x7F},
	}
	for name, body := range lies {
		raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: []esegen.Record{
			{Fixed: map[uint32][]byte{1: esegen.Le32(1)}}, {Raw: body}, {Fixed: map[uint32][]byte{1: esegen.Le32(3)}},
		}}}, esegen.Options{})
		rows, st := rowsOf(t, open(t, raw).Table("T"))
		good := 0
		for _, r := range rows {
			if v := val(t, r, "Id"); !v.Null && v.Err == nil && (v.Int() == 1 || v.Int() == 3) {
				good++
			}
		}
		if good != 2 {
			t.Errorf("%s: the two honest records around it were not both returned (%d)", name, good)
		}
		if st.Live+st.Unreadable != 3 {
			t.Errorf("%s: %+v does not account for all three entries", name, st)
		}
	}
}

func TestLongValue_TreeSplitAcrossLeavesWithCommonKeys(t *testing.T) {
	var lvs []esegen.LongValue
	var recs []esegen.Record
	for i := uint32(1); i <= 30; i++ {
		body := bytes.Repeat([]byte{byte('a' + i%26)}, 10+int(i))
		half := len(body) / 2
		lvs = append(lvs, esegen.LongValue{ID: 0x01020300 + i, Total: uint32(len(body)), Segments: []esegen.Segment{
			{Offset: 0, Data: body[:half]}, {Offset: uint32(half), Data: body[half:]}}})
		recs = append(recs, esegen.Record{Fixed: map[uint32][]byte{1: esegen.Le32(i)},
			Tagged: []esegen.Tagged{{ID: 257, Flags: esegen.TagLongValue | esegen.TagSeparated, Data: esegen.LongValueRef(0x01020300 + i)}}})
	}
	for _, common := range []bool{false, true} {
		raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), HasLVTree: true, LongValues: lvs, Records: recs, CommonKeys: common, LVLeafCapacity: 5}}, esegen.Options{})
		rows, _ := rowsOf(t, open(t, raw).Table("T"))
		if len(rows) != 30 {
			t.Fatalf("common=%v rows = %d", common, len(rows))
		}
		for _, r := range rows {
			i := uint32(val(t, r, "Id").Int())
			v := val(t, r, "Data")
			want := bytes.Repeat([]byte{byte('a' + i%26)}, 10+int(i))
			if v.Err != nil || !bytes.Equal(v.Raw, want) {
				t.Fatalf("common=%v value %d: err=%v got %d bytes, want %d", common, i, v.Err, len(v.Raw), len(want))
			}
		}
	}
}

func TestRows_ColumnAddedAfterTheRecordWasWrittenReadsAsItsDefault(t *testing.T) {
	c := cols()
	c = append(c,
		esegen.Column{ID: 4, Name: "AddedFixed", Type: esegen.Int32, Default: esegen.Le32(42)},
		esegen.Column{ID: 131, Name: "AddedVar", Type: esegen.Text, Codepage: 1252, Default: []byte("dflt")},
		esegen.Column{ID: 131 + 1, Name: "AddedVar2", Type: esegen.Text, Codepage: 1252})
	raw := esegen.Build([]esegen.Table{{Name: "T", Columns: c, Records: []esegen.Record{{Fixed: map[uint32][]byte{1: esegen.Le32(1)}}}}}, esegen.Options{})
	rows, _ := rowsOf(t, open(t, raw).Table("T"))
	if v := val(t, rows[0], "AddedFixed"); v.Null || v.Int() != 42 {
		t.Errorf("fixed default: %+v", v)
	}
	if v := val(t, rows[0], "AddedVar"); v.Null || v.Text() != "dflt" {
		t.Errorf("variable default: %+v", v)
	}
	if v := val(t, rows[0], "AddedVar2"); !v.Null {
		t.Errorf("no default means null: %+v", v)
	}
}

func TestCatalog_DroppedTableIsNotListed(t *testing.T) {
	db := open(t, esegen.Build([]esegen.Table{
		{Name: "Keep", Columns: cols()},
		{Name: "Gone", Columns: cols(), Dropped: true},
	}, esegen.Options{}))
	if db.Table("Gone") != nil {
		t.Errorf("a dropped table is listed")
	}
	if db.Table("Keep") == nil || len(db.Tables()) != 1 {
		t.Errorf("tables = %v", db.Tables())
	}
}

// TestFuzz_CorruptedDatabasesNeverPanicOrHang damages a database that uses
// every feature (both page sizes, split trees, common keys, long values,
// compression, multi-values, deleted records) in thousands of ways and reads
// all of it. Any outcome is acceptable except a panic or a runaway.
func TestFuzz_CorruptedDatabasesNeverPanicOrHang(t *testing.T) {
	var lvs []esegen.LongValue
	var recs []esegen.Record
	for i := uint32(1); i <= 25; i++ {
		body := bytes.Repeat([]byte{byte('a' + i%26)}, 20+int(i))
		lvs = append(lvs, esegen.LongValue{ID: 100 + i, Total: uint32(len(body)), Segments: []esegen.Segment{{Offset: 0, Data: body[:10]}, {Offset: 10, Data: body[10:]}}})
		r := esegen.Record{Key: append([]byte("key-"), byte('a'+i/10), byte('0'+i%10)),
			Fixed: map[uint32][]byte{1: esegen.Le32(i), 2: esegen.Le64(uint64(i) << 33)},
			Var:   map[uint32][]byte{128: []byte("name"), 129: esegen.UTF16("wide")},
			Tagged: []esegen.Tagged{
				{ID: 257, Flags: esegen.TagLongValue | esegen.TagSeparated, Data: esegen.LongValueRef(100 + i)},
				{ID: 258, Flags: esegen.TagMulti, Data: esegen.Multi([]byte("a"), []byte("bb"), []byte("ccc"))},
				{ID: 259, Flags: esegen.TagCompressed, Data: append([]byte{3 << 3, 30, 0}, mustHex("0000001861626317000f02")...)},
			},
			Defunct: i%7 == 0}
		recs = append(recs, r)
	}
	recs = append(recs, esegen.Record{Raw: []byte{9, 9}})
	read := func(raw []byte) {
		db, err := ese.Open(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return
		}
		for _, tb := range db.Tables() {
			tb.Scan(func(r ese.Row) error {
				for _, v := range r.Values {
					_ = v.Text()
					_ = v.Int()
					_, _ = v.Time()
				}
				return nil
			})
		}
	}
	for _, ps := range []int{4096, 32768} {
		base := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: recs, HasLVTree: true, LongValues: lvs, LeafCapacity: 6, CommonKeys: true, LVLeafCapacity: 8}}, esegen.Options{PageSize: ps, Shadow: true})
		read(base)
		rng := rand.New(rand.NewSource(int64(ps)))
		for i := 0; i < 1500; i++ {
			b := append([]byte(nil), base...)
			switch rng.Intn(4) {
			case 0: // flip bytes anywhere
				for k := 0; k < 1+rng.Intn(8); k++ {
					b[rng.Intn(len(b))] = byte(rng.Intn(256))
				}
			case 1: // damage the tag area and headers of one page
				pg := 2 + rng.Intn(len(b)/ps-2)
				for k := 0; k < 6; k++ {
					off := pg*ps + rng.Intn(48)
					b[off] = byte(rng.Intn(256))
					b[(pg+1)*ps-1-rng.Intn(64)] = byte(rng.Intn(256))
				}
			case 2: // truncate
				b = b[:rng.Intn(len(b))]
			case 3: // zero a whole page
				pg := 2 + rng.Intn(len(b)/ps-2)
				for k := pg * ps; k < (pg+1)*ps; k++ {
					b[k] = 0
				}
			}
			read(b)
		}
	}
}

func TestTree_EntryWhoseSharedKeyPrefixIsMissingIsNotInvented(t *testing.T) {
	var recs []esegen.Record
	for i := 0; i < 8; i++ {
		recs = append(recs, esegen.Record{Key: []byte{'p', 'r', 'e', byte('0' + i)}, Fixed: map[uint32][]byte{1: esegen.Le32(uint32(i))}})
	}
	raw := esegen.Build([]esegen.Table{{Name: "T", Columns: cols(), Records: recs, LeafCapacity: 4, CommonKeys: true}}, esegen.Options{})
	db := open(t, raw)
	rows, _ := rowsOf(t, db.Table("T"))
	if len(rows) != 8 {
		t.Fatalf("intact: %d rows", len(rows))
	}
	// shrink the first leaf's tag 0 (the prefix) to one byte: its entries now
	// share more than the page can supply
	root, _ := db.Table("T").FDP, 0
	b := append([]byte(nil), raw...)
	leaf := int(root) + 1
	tag0 := (leaf+2)*4096 - 4
	b[tag0], b[tag0+1] = 1, 0
	rows, st := rowsOf(t, open(t, b).Table("T"))
	if len(rows) != 4 || st.Unreadable != 4 {
		t.Errorf("rows=%d stats=%+v, want the 4 entries of the damaged leaf counted unreadable and the other 4 returned", len(rows), st)
	}
}
