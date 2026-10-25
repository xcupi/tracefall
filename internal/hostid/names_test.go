package hostid

import "testing"

func TestResolve(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     []string
		want   string
		wantOK bool
	}{
		{"none", nil, "", false},
		{"blank only", []string{"", "  "}, "", false},
		{"single", []string{"host01"}, "host01", true},
		{"case variants of one name", []string{"HOST01", "host01"}, "HOST01", true},
		{"short and fqdn", []string{"HOST01", "host01.example.test"}, "host01.example.test", true},
		{"short and fqdn mixed case", []string{"host01.Example.test", "HOST01"}, "host01.Example.test", true},
		{"fqdn spellings of one name", []string{"host01.example.test", "HOST01.EXAMPLE.TEST"}, "HOST01.EXAMPLE.TEST", true},
		{"two fqdn same label", []string{"host01.a.test", "host01.b.test"}, "", false},
		{"short with two fqdn same label", []string{"host01", "host01.a.test", "host01.b.test"}, "", false},
		{"different shorts", []string{"host01", "host02"}, "", false},
		{"label is not a prefix match", []string{"host01", "host010.example.test"}, "", false},
		{"short unrelated to fqdn", []string{"host02", "host01.example.test"}, "", false},
		{"address is not a dns label", []string{"10.0.0.5", "10"}, "", false},
		{"two addresses", []string{"10.0.0.5", "10.0.0.6"}, "", false},
		{"same address", []string{"10.0.0.5", "10.0.0.5"}, "10.0.0.5", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Resolve(tc.in)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("Resolve(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
