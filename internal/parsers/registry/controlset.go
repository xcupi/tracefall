package registry

import (
	"encoding/binary"
	"fmt"
	"strings"

	"tracefall/internal/regf"
)

// selectedControlSet returns only the set named by Select\Current. Other
// selectors (Default and LastKnownGood) do not describe the active set.
func selectedControlSet(h *regf.Hive) (string, string) {
	k, err := h.OpenKey("Select")
	if err != nil {
		return "", "SYSTEM Select key missing; active control set unknown"
	}
	currentCount := 0
	for _, v := range k.Values {
		if strings.EqualFold(v.Name, "Current") {
			currentCount++
		}
	}
	if currentCount > 1 {
		return "", "duplicate Select Current values; active control set unknown"
	}
	for _, v := range k.Values {
		if !strings.EqualFold(v.Name, "Current") {
			continue
		}
		if len(v.Data) != 4 {
			return "", "Select Current is not a four-byte DWORD; active control set unknown"
		}
		var n uint32
		switch v.Type {
		case 4:
			n = binary.LittleEndian.Uint32(v.Data)
		case 5:
			n = binary.BigEndian.Uint32(v.Data)
		default:
			return "", "Select Current has a non-DWORD type; active control set unknown"
		}
		if n == 0 || n > 999 {
			return "", "Select Current is outside the control-set range; active control set unknown"
		}
		cs := fmt.Sprintf("ControlSet%03d", n)
		if _, err := h.OpenKey(cs); err != nil {
			return "", "Select Current names a missing control set; active control set unknown"
		}
		return cs, ""
	}
	return "", "Select Current missing; active control set unknown"
}
