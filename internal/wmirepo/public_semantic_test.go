package wmirepo

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestPublicSemanticFieldParity(t *testing.T) {
	p, keys := publicPhysical(t)
	b, err := os.ReadFile(os.Getenv("TRACEFALL_REAL_WMI_PROTOTYPE"))
	if err != nil {
		t.Fatal(err)
	}
	var proof struct {
		Objects []struct {
			NativeKey     string         `json:"native_key"`
			Class         string         `json:"class"`
			KeyProperties map[string]any `json:"key_properties"`
			Properties    map[string]struct {
				CIMType      uint8  `json:"cim_type"`
				Array        bool   `json:"array"`
				Index        int    `json:"index"`
				Offset       int    `json:"layout_offset"`
				State        byte   `json:"state_bits"`
				Presence     string `json:"presence"`
				RawSlot      string `json:"raw_slot_hex"`
				Value        any    `json:"value"`
				StateSpans   []Span `json:"state_spans"`
				SlotSpans    []Span `json:"slot_spans"`
				ValueSpans   []Span `json:"value_spans"`
				DefaultClass string `json:"default_class_native_key"`
			} `json:"properties"`
		} `json:"objects"`
	}
	if err = json.Unmarshal(b, &proof); err != nil {
		t.Fatal(err)
	}
	out, err := (SemanticReader{Keys: keys, ReadRecord: p.ReadRecord}).ReadSelected()
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Objects) != len(proof.Objects) {
		t.Fatalf("native selected count=%d prototype=%d", len(out.Objects), len(proof.Objects))
	}
	fields := 0
	for _, want := range proof.Objects {
		var got *Instance
		for i := range out.Objects {
			if out.Objects[i].NativeKey == want.NativeKey {
				got = &out.Objects[i]
				break
			}
		}
		if got == nil || got.Class != want.Class || len(got.Properties) != len(want.Properties) {
			t.Fatal("native selected class identity/property census mismatch")
		}
		keyJSON, _ := json.Marshal(got.KeyProperties)
		wantKeyJSON, _ := json.Marshal(want.KeyProperties)
		if string(keyJSON) != string(wantKeyJSON) {
			t.Fatal("native exact key values differ")
		}
		for name, w := range want.Properties {
			g, ok := got.Properties[name]
			if !ok {
				t.Fatal("prototype property missing")
			}
			valueJSON, _ := json.Marshal(g.Value)
			wantJSON, _ := json.Marshal(w.Value)
			if g.Type != (CIMType{w.CIMType, w.Array}) || g.Index != w.Index || g.LayoutOffset != w.Offset || g.StateBits != w.State || g.Presence != w.Presence || hex.EncodeToString(g.RawSlot) != w.RawSlot || string(valueJSON) != string(wantJSON) || g.DefaultClassNativeKey != w.DefaultClass {
				t.Fatalf("class=%s property=%s native value/state/default mismatch", want.Class, name)
			}
			normalize := func(s []Span) []Span {
				if len(s) == 0 {
					return nil
				}
				return s
			}
			if !reflect.DeepEqual(normalize(g.StateSpans), normalize(w.StateSpans)) || !reflect.DeepEqual(normalize(g.SlotSpans), normalize(w.SlotSpans)) || !reflect.DeepEqual(normalize(g.ValueSpans), normalize(w.ValueSpans)) {
				t.Fatalf("class=%s property=%s physical field span mismatch", want.Class, name)
			}
			fields++
		}
	}
	t.Logf("native selected objects=%d fields=%d namespace hash IDs=%d; exact values/state/default origin and field spans match saved public prototype", len(out.Objects), fields, len(out.NamespaceIDs))
}
