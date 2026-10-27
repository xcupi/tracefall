package investigate

import "testing"

func TestIdentityAmbiguousShortNamesStayAcquisitionScoped(t *testing.T) {
	ids := newIdentities(map[string]member{
		"a": {host: "host01", coll: "one"}, "b": {host: "host01", coll: "two"},
		"fqdn-a": {host: "host01.domain-a.example", coll: "three"}, "fqdn-b": {host: "host01.domain-b.example", coll: "four"},
	})
	if ids.of("a").known || ids.of("b").known || ids.of("a").key == ids.of("b").key {
		t.Fatalf("ambiguous short attributed across acquisitions: %+v", ids)
	}
}
