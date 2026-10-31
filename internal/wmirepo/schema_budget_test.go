package wmirepo

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSelectedSchemaReadBudgetSpansNamespacesAndClasses(t *testing.T) {
	s := SemanticReader{}
	records := map[string]Record{}
	for i := 0; i < 600; i++ {
		ns := fixtureID("NS_", fmt.Sprintf("root\\branch%04d", i))
		for _, class := range selectedClasses() {
			key := ns + "/" + fixtureID("CD_", class) + ".0.1.200"
			s.Keys = append(s.Keys, IndexKey{Key: key})
			records[key] = renamedClass(class)
		}
	}
	reads := 0
	s.ReadRecord = func(k string) (Record, error) { reads++; return records[k], nil }
	_, err := s.ReadSelected()
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "aggregate schema") || reads > 4096 {
		t.Fatalf("schema reads unbounded across namespaces: reads=%d err=%v", reads, err)
	}
}
