package evtx_test

import (
	"encoding/binary"
	"hash/crc32"
	"testing"

	"tracefall/internal/evtx"
	"tracefall/internal/evtx/evtxgen"
)

func TestNativeResultCodeTypedNumericStringification(t *testing.T) {
	// Two UTF-16 characters occupy the same four bytes as UInt32. Replace that substitution's type/value, preserving all offsets.
	b := evtxgen.Build([]evtxgen.Event{{RecordID: 1, EventID: 202, Data: map[string]string{"ResultCode": "12"}}})
	chunk := b[4096:]
	body := 512 + 24
	definition := int(binary.LittleEndian.Uint32(chunk[body+10:]))
	table := definition + 24 + int(binary.LittleEndian.Uint32(chunk[definition+20:]))
	count := int(binary.LittleEndian.Uint32(chunk[table:]))
	if count != 14 {
		t.Fatalf("unexpected substitution count %d", count)
	}
	value := table + 4 + 4*count
	for i := 0; i < count-1; i++ {
		value += int(binary.LittleEndian.Uint16(chunk[table+4+4*i:]))
	}
	descriptor := table + 4 + 4*(count-1)
	if binary.LittleEndian.Uint16(chunk[descriptor:]) != 4 || chunk[descriptor+2] != 1 {
		t.Fatal("expected native string substitution")
	}
	chunk[descriptor+2] = 8 // BinXML UInt32, not a textual numeric token.
	binary.LittleEndian.PutUint32(chunk[value:], 2147942401)
	used := int(binary.LittleEndian.Uint32(chunk[48:]))
	binary.LittleEndian.PutUint32(chunk[52:], crc32.ChecksumIEEE(chunk[512:used]))
	sum := crc32.Update(0, crc32.IEEETable, chunk[:120])
	sum = crc32.Update(sum, crc32.IEEETable, chunk[128:512])
	binary.LittleEndian.PutUint32(chunk[124:], sum)
	records, stats := readAll(t, writeLog(t, b), evtx.Limits{Strict: true})
	if len(records) != 1 || stats.RecordsRead != 1 || records[0].Data["ResultCode"] != "2147942401" {
		t.Fatal("existing UInt32 decimal stringification changed")
	}
}
