package cmdsem

import (
	"fmt"
	"strings"
	"testing"
)

func TestURLBoundariesCertainEscapedWhitespace(t *testing.T) {
	for _, escape := range []string{`\`, "`"} {
		for n := 0; n <= 4; n++ {
			for _, space := range []string{" ", "\t", "\n", "\r", "\r\n"} {
				t.Run(fmt.Sprintf("%q_%d_%q", escape, n, space), func(t *testing.T) {
					command := "curl https://api.example.test/download?q=value" + strings.Repeat(escape, n) + space + "; echo keep"
					if got := URLBoundariesCertain(command); got != (n%2 == 0) {
						t.Errorf("certainty=%t want %t", got, n%2 == 0)
					}
					// Certainty metadata must not alter the generic redactor's established
					// preservation of host/path/query/fragment or following non-URL context.
					if got := MapURLs(command, func(raw string) string { return raw }); got != command {
						t.Fatal("span metadata changed text")
					}
					if got := Redact(command); got != command {
						t.Fatal("generic preservation contract changed")
					}
				})
			}
		}
	}
	for _, run := range []string{"\\`", "`\\"} {
		if URLBoundariesCertain("curl https://api.example.test/?q=x" + run + " suffix") {
			t.Error("mixed escape grammar should be uncertain")
		}
	}
}
