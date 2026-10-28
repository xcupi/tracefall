package cmdsem

import "testing"

func TestRedactURLApostropheBoundaries(t *testing.T) {
	for i, tt := range []struct{ in, want string }{
		{`https://alice:Dummy'Secret42@host01/a`, `https://<redacted>@host01/a`},
		{`IEX (iwr "https://alice:Dummy'Secret42@host01/a")`, `IEX (iwr "https://<redacted>@host01/a")`},
		{`"https://alice:Dummy!$&'()*+,;=:Secret42@host01/a"`, `"https://<redacted>@host01/a"`},
		{`'https://alice:Dummy%27Secret42@host01';alice@host02`, `'https://<redacted>@host01';alice@host02`},
		{`'https://host01';alice@host02`, `'https://host01';alice@host02`},
		{`'https://host01';'https://alice:Dummy%27Secret42@host02'`, `'https://host01';'https://<redacted>@host02'`},
		{`alice:Dummy'Secret42@host01`, `alice:Dummy'Secret42@host01`},
		{`https://host01/a?email=alice@host01`, `https://host01/a?email=alice@host01`},
	} {
		if Redact(tt.in) != tt.want {
			t.Errorf("URL boundary control %d failed", i)
		}
	}
}
