package wmirepo

import (
	"encoding/binary"
	"math"
	"reflect"
	"testing"
)

func TestTypedValuesAndStringArrayReferences(t *testing.T) {
	region := append(words(1, 8), 0, 0)
	got, err := DecodeValue(region, words(0), CIMType{Code: 8, Array: true})
	if err != nil || !reflect.DeepEqual(got.Value, []any{""}) || len(got.ValueOffsets) != 2 {
		t.Fatalf("string array references not resolved: %+v %v", got, err)
	}
	got, err = DecodeValue(nil, []byte{0, 0}, CIMType{Code: 11})
	if err != nil || got.Value != false {
		t.Fatalf("zero bool not false: %+v %v", got, err)
	}
	got, err = DecodeValue(nil, []byte{255, 255}, CIMType{Code: 2})
	if err != nil || got.Value != int16(-1) {
		t.Fatalf("signed width lost: %+v %v", got, err)
	}
}
func TestTypedValuesRejectUnsupportedAndCorruption(t *testing.T) {
	for _, code := range []uint8{0, 13, 103, 255} {
		if _, err := DecodeValue(nil, words(0), CIMType{Code: code}); err == nil {
			t.Errorf("unknown code%d accepted", code)
		}
	}
	if _, err := DecodeValue(nil, []byte{1, 0}, CIMType{Code: 11}); err == nil {
		t.Fatal("noncanonical boolean accepted")
	}
	if _, err := DecodeValue(words(0xffffffff), words(0), CIMType{Code: 8, Array: true}); err == nil {
		t.Fatal("unbounded array accepted")
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, math.Float64bits(math.Inf(1)))
	if _, err := DecodeValue(nil, b, CIMType{Code: 5}); err == nil {
		t.Fatal("nonfinite JSON value accepted")
	}
	if _, err := DecodeValue([]byte{1, 0}, words(0), CIMType{Code: 8}); err == nil {
		t.Fatal("unknown string prefix accepted")
	}
}

func TestAllSupportedCIMScalarWidths(t *testing.T) {
	tests := []struct {
		code uint8
		raw  []byte
		want any
	}{
		{16, []byte{255}, int8(-1)}, {17, []byte{255}, uint8(255)},
		{2, []byte{255, 255}, int16(-1)}, {18, []byte{255, 255}, ^uint16(0)},
		{3, []byte{255, 255, 255, 255}, int32(-1)}, {19, []byte{255, 255, 255, 255}, ^uint32(0)},
		{20, []byte{255, 255, 255, 255, 255, 255, 255, 255}, int64(-1)}, {21, []byte{255, 255, 255, 255, 255, 255, 255, 255}, ^uint64(0)},
		{11, []byte{255, 255}, true},
		{4, binary.LittleEndian.AppendUint32(nil, math.Float32bits(1.5)), float64(1.5)},
		{5, binary.LittleEndian.AppendUint64(nil, math.Float64bits(1.5)), float64(1.5)},
	}
	for _, tt := range tests {
		got, err := DecodeValue(nil, tt.raw, CIMType{Code: tt.code})
		if err != nil || !reflect.DeepEqual(got.Value, tt.want) {
			t.Fatalf("CIM type%d exact scalar=%v err=%v", tt.code, got.Value, err)
		}
	}
	for _, code := range []uint8{8, 101, 102} {
		got, err := DecodeValue([]byte("\x00neutral\x00"), words(0), CIMType{Code: code})
		if err != nil || got.Value != "neutral" || len(got.ValueOffsets) != 1 {
			t.Fatalf("string/reference/datetime preservation type%d err=%v", code, err)
		}
	}
	region := append(words(2), 255, 1)
	got, err := DecodeValue(region, words(0), CIMType{Code: 16, Array: true})
	if err != nil || !reflect.DeepEqual(got.Value, []any{int8(-1), int8(1)}) {
		t.Fatal("signed scalar-array width lost")
	}
}
