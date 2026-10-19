// Package timezone reads the host time zone basis from a SYSTEM hive.
//
// Windows writes the machine's time zone to
// SYSTEM\<ControlSet>\Control\TimeZoneInformation. The value that matters for
// converting local wall-clock readings is ActiveTimeBias (falling back to
// Bias): signed minutes with the convention
//
//	UTC = local + bias
//
// so Jakarta (UTC+7) has ActiveTimeBias = -420, and a local reading L is
// converted to UTC as L + bias.
//
// What this gives, and what it does not:
//
//   - It is ONE offset per SYSTEM hive: the bias in force when the hive was
//     last written. Windows keeps daylight-saving transitions out of this
//     key, so a reading taken on the other side of a DST change is off by
//     the DST difference. ToUTC does not apply DST history; the report says so.
//   - It is the machine's configured zone, not proof of where the machine
//     was. A laptop that travelled is described by the zone it was set to.
package timezone

import (
	"encoding/binary"
	"fmt"
	"time"

	"tracefall/internal/regf"
)

// Basis is the time zone a SYSTEM hive records. The zero value is "not
// recorded"; Reason then says why.
type Basis struct {
	Recorded bool `json:"recorded"`
	// KeyName is TimeZoneKeyName, e.g. "SE Asia Standard Time", when present.
	KeyName string `json:"key_name,omitempty"`
	// ActiveBiasMinutes is the bias in minutes with UTC = local + bias.
	ActiveBiasMinutes int `json:"active_bias_minutes"`
	// ValueUsed is the registry value the bias came from: ActiveTimeBias,
	// or Bias when the hive has no ActiveTimeBias.
	ValueUsed string `json:"value_used,omitempty"`
	// ControlSet is the control set the value was read from, e.g. ControlSet001.
	ControlSet string `json:"control_set,omitempty"`
	// Reason says why the basis is not recorded.
	Reason string `json:"reason,omitempty"`
}

// ToUTC converts a local wall-clock reading to UTC with this basis. It is an
// offset, so it is only as correct as the basis itself (see the package doc):
// DST is not applied. The caller must not call it on an unrecorded basis.
func (b Basis) ToUTC(local time.Time) time.Time {
	return local.Add(time.Duration(b.ActiveBiasMinutes) * time.Minute).UTC()
}

// FromSystemHive reads the basis from an opened SYSTEM hive. It never fails:
// a hive without the key is reported as not recorded, with the reason.
func FromSystemHive(h *regf.Hive) Basis {
	cs, err := currentControlSet(h)
	if err != nil {
		return Basis{Reason: err.Error()}
	}
	base := fmt.Sprintf("%s\\Control\\TimeZoneInformation", cs)
	key, err := h.OpenKey(base)
	if err != nil {
		return Basis{ControlSet: cs, Reason: fmt.Sprintf("%s has no TimeZoneInformation key", cs)}
	}

	b := Basis{ControlSet: cs}
	var haveBias bool
	for _, v := range key.Values {
		switch v.Name {
		case "TimeZoneKeyName":
			b.KeyName = v.String()
		case "ActiveTimeBias":
			if n, ok := dword(v); ok {
				b.ActiveBiasMinutes, b.ValueUsed, haveBias = n, "ActiveTimeBias", true
			}
		}
	}
	if !haveBias {
		for _, v := range key.Values {
			if v.Name == "Bias" {
				if n, ok := dword(v); ok {
					b.ActiveBiasMinutes, b.ValueUsed, haveBias = n, "Bias", true
				}
			}
		}
	}
	if !haveBias {
		b.Reason = fmt.Sprintf("%s\\TimeZoneInformation has neither ActiveTimeBias nor Bias as a DWORD", cs)
		return b
	}
	b.Recorded = true
	return b
}

// currentControlSet resolves SYSTEM\Select\Current to a control set name. A
// hive without Select is reported, not guessed at: ControlSet001 is only the
// usual value, and a guess would put a wrong zone on every event.
func currentControlSet(h *regf.Hive) (string, error) {
	key, err := h.OpenKey("Select")
	if err != nil {
		return "", fmt.Errorf("the SYSTEM hive has no Select key, so the active control set is unknown")
	}
	for _, v := range key.Values {
		if v.Name == "Current" {
			if n, ok := dword(v); ok && n > 0 {
				return fmt.Sprintf("ControlSet%03d", n), nil
			}
		}
	}
	return "", fmt.Errorf("the SYSTEM hive's Select key has no Current DWORD")
}

// dword decodes a REG_DWORD (little-endian) into a signed int. Bias values are
// signed; the registry stores them as the two's-complement bit pattern.
func dword(v regf.Value) (int, bool) {
	if len(v.Data) < 4 {
		return 0, false
	}
	var u uint32
	switch v.Type {
	case 4: // REG_DWORD
		u = binary.LittleEndian.Uint32(v.Data[:4])
	case 5: // REG_DWORD_BIG_ENDIAN
		u = binary.BigEndian.Uint32(v.Data[:4])
	default:
		return 0, false
	}
	return int(int32(u)), true
}
