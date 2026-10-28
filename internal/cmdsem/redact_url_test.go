package cmdsem

import (
	"strings"
	"testing"
)

func TestRedactURLUserinfo(t *testing.T) {
	for _, url := range []string{`https://alice:DummySecret42@host01/a?q=x`, `HTTP://alice:Dummy%40Secret%3A42@host01:8081/a`, `https://alice@host01/a`, `https://alice:Dummy%2FSecret%3F42@host01/a`} {
		got := Redact(`IEX (iwr '` + url + `')`)
		if strings.Contains(got, "alice") || strings.Contains(got, "Dummy") || !strings.Contains(got, "@host01") {
			t.Fatal("URL userinfo must be masked without damaging host")
		}
	}
	for _, s := range []string{`alice@host01`, `https://host01/a?email=alice@host01`, `https://host01/a#alice@host01`} {
		if Redact(s) != s {
			t.Fatal("non-userinfo text changed")
		}
	}
}
