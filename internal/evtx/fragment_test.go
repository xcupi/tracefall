package evtx

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"tracefall/internal/evtx/evtxgen"
)

// Encode the two documented element layouts independently of evtxgen:
// only an element in a template definition has a dependency identifier.
type fragmentEncoder struct {
	b        []byte
	base     int
	template bool
}

func (e *fragmentEncoder) u16(v uint16) { e.b = binary.LittleEndian.AppendUint16(e.b, v) }
func (e *fragmentEncoder) u32(v uint32) { e.b = binary.LittleEndian.AppendUint32(e.b, v) }
func (e *fragmentEncoder) text(s string) {
	u := utf16.Encode([]rune(s))
	e.u16(uint16(len(u)))
	for _, v := range u {
		e.u16(v)
	}
}
func (e *fragmentEncoder) name(s string) {
	e.u32(uint32(e.base + len(e.b) + 4))
	e.u32(0)
	e.u16(0)
	e.text(s)
	e.u16(0)
}
func (e *fragmentEncoder) open(s string, attr bool) {
	token := byte(1)
	if attr {
		token = 0x41
	}
	e.b = append(e.b, token)
	if e.template {
		e.u16(0xffff)
	}
	e.u32(0)
	e.name(s)
}
func (e *fragmentEncoder) value(s string) { e.b = append(e.b, 5, 1); e.text(s) }
func (e *fragmentEncoder) leaf(k, v string) {
	e.open(k, false)
	e.b = append(e.b, 2)
	e.value(v)
	e.b = append(e.b, 4)
}

func literalFragment(base int) []byte {
	e := fragmentEncoder{base: base}
	e.open("Notice", true)
	attrSize := len(e.b)
	e.u32(0)
	start := len(e.b)
	e.b = append(e.b, 6)
	e.name("xmlns")
	e.value("urn:example:notice")
	binary.LittleEndian.PutUint32(e.b[attrSize:], uint32(len(e.b)-start))
	e.b = append(e.b, 2)
	e.leaf("Status", "ready Ω")
	e.leaf("ResultCode", " 0 ")
	e.b = append(e.b, 4, 0)
	return e.b
}

func fragmentNativeFixture(t *testing.T, damage string, templated bool) string {
	t.Helper()
	const base = 512 + 24
	e := fragmentEncoder{base: base, template: templated}
	if templated {
		e.base += 10 + 24
	}
	e.open("Event", false)
	e.b = append(e.b, 2)
	e.open("System", false)
	e.b = append(e.b, 2)
	e.leaf("EventID", "9001")
	e.leaf("Channel", "Example/Operational")
	e.open("Provider", true)
	size := len(e.b)
	e.u32(0)
	start := len(e.b)
	e.b = append(e.b, 6)
	e.name("Name")
	e.value("Example-Provider")
	binary.LittleEndian.PutUint32(e.b[size:], uint32(len(e.b)-start))
	e.b = append(e.b, 3, 4)
	e.open("UserData", false)
	e.b = append(e.b, 2)
	var body []byte
	if templated {
		e.b = append(e.b, 0x0d, 0, 0, 0x21, 4, 4, 0)
		body = append(body, 0x0c, 1)
		body = binary.LittleEndian.AppendUint32(body, 1)
		body = binary.LittleEndian.AppendUint32(body, base+10)
		body = append(body, make([]byte, 20)...)
		body = binary.LittleEndian.AppendUint32(body, uint32(len(e.b)))
		body = append(body, e.b...)
		body = binary.LittleEndian.AppendUint32(body, 1)
		fragmentBase := base + len(body) + 4
		nested := literalFragment(fragmentBase)
		switch damage {
		case "truncated":
			nested = nested[:7]
		case "name_bounds":
			binary.LittleEndian.PutUint32(nested[5:], 65535)
		case "close_token":
			nested[len(nested)-2] = 0x3f
		}
		body = binary.LittleEndian.AppendUint16(body, uint16(len(nested)))
		body = append(body, 0x21, 0)
		body = append(body, nested...)
		body = append(body, 0) // end of the record's outer BinXML stream
	} else {
		e.b = append(e.b, literalFragment(e.base+len(e.b))...)
		// Replace the fragment EOF with the enclosing end tags.
		e.b = e.b[:len(e.b)-1]
		e.b = append(e.b, 4, 4, 0)
		body = e.b
	}
	data := evtxgen.Build([]evtxgen.Event{{RecordID: 1}})
	chunk := data[4096:]
	clear(chunk[512:])
	recSize := (24 + len(body) + 4 + 7) &^ 7
	rec := chunk[512 : 512+recSize]
	copy(rec, "\x2a\x2a\x00\x00")
	binary.LittleEndian.PutUint32(rec[4:], uint32(recSize))
	binary.LittleEndian.PutUint64(rec[8:], 1)
	binary.LittleEndian.PutUint64(rec[16:], 133801632001234567)
	copy(rec[24:], body)
	binary.LittleEndian.PutUint32(rec[recSize-4:], uint32(recSize))
	end := 512 + recSize
	binary.LittleEndian.PutUint32(chunk[44:], 512)
	binary.LittleEndian.PutUint32(chunk[48:], uint32(end))
	binary.LittleEndian.PutUint32(chunk[52:], crc32.ChecksumIEEE(chunk[512:end]))
	sum := crc32.Update(0, crc32.IEEETable, chunk[:120])
	sum = crc32.Update(sum, crc32.IEEETable, chunk[128:512])
	binary.LittleEndian.PutUint32(chunk[124:], sum)
	path := filepath.Join(t.TempDir(), "fragment.evtx")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNativeLiteralFragmentLayout(t *testing.T) {
	for _, templated := range []bool{false, true} {
		t.Run(map[bool]string{false: "standalone", true: "template_substitution"}[templated], func(t *testing.T) {
			f, err := Open(fragmentNativeFixture(t, "", templated), Limits{Strict: true})
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var rows []Record
			stats, err := f.Walk(func(r Record) error { rows = append(rows, r); return nil })
			if err != nil || stats.RecordsFailed != 0 || stats.RecordsRead != 1 || len(rows) != 1 {
				data, _ := os.ReadFile(f.f.Name())
				c := &chunk{data: data[4096:], templateCache: map[uint32]*template{}}
				size := int(binary.LittleEndian.Uint32(c.data[516:]))
				_, detail := f.parseRecord(c, c.data[512:512+size], 512, 0, 4608)
				t.Fatalf("literal fragment lost: rows=%d stats=%+v err=%v detail=%v", len(rows), stats, err, detail)
			}
			r := rows[0]
			if r.Data["Status"] != "ready Ω" || r.Data["ResultCode"] != " 0 " || r.System.EventID != 9001 || r.System.Provider != "Example-Provider" || r.System.Channel != "Example/Operational" || r.System.EventRecordID != 1 || r.Offset != 4608 || !r.System.TimeCreated.Equal(time.Date(2025, 1, 1, 0, 0, 0, 123456700, time.UTC)) {
				t.Fatalf("fragment fields or provenance changed: %+v", r)
			}
		})
	}
}

func TestNativeLiteralFragmentRejectsMalformed(t *testing.T) {
	for _, damage := range []string{"truncated", "name_bounds", "close_token"} {
		t.Run(damage, func(t *testing.T) {
			f, err := Open(fragmentNativeFixture(t, damage, true), Limits{Strict: true})
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			delivered := 0
			stats, err := f.Walk(func(Record) error { delivered++; return nil })
			if err != nil || stats.RecordsFailed != 1 || stats.RecordsRead != 0 || delivered != 0 {
				t.Fatalf("damaged fragment accepted: stats=%+v delivered=%d err=%v", stats, delivered, err)
			}
		})
	}
}

func TestTemplateDependencyIdentifierWithoutSubstitutions(t *testing.T) {
	e := fragmentEncoder{base: 512 + 34, template: true}
	e.leaf("Status", "ready")
	f := &File{lim: Limits{}.withDefaults()}
	c := &chunk{templateCache: map[uint32]*template{}}
	// A template can have no substitutions. Layout must not be guessed from
	// a nil/empty substitution array or by retrying a failed decode.
	// Enter through a real template instance, including a zero descriptor count.
	body := append([]byte{0x0c, 1, 1, 0, 0, 0}, make([]byte, 4)...)
	binary.LittleEndian.PutUint32(body[6:], uint32(512+10))
	body = append(body, make([]byte, 20)...)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(e.b)))
	body = append(body, e.b...)
	body = binary.LittleEndian.AppendUint32(body, 0)
	c.data = append(make([]byte, 512), body...)
	doc, err := f.parseBinXML(c, body, 512, nil)
	if err != nil || len(doc.children) != 1 || strings.TrimSpace(doc.children[0].text) != "ready" {
		t.Fatalf("zero-substitution template rejected: doc=%+v err=%v", doc, err)
	}
}
