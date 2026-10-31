package wmirepo

import (
	"strings"
	"testing"
)

func TestAllSevenSelectedClassNamesHaveNativePositiveInstances(t *testing.T) {
	for _, class := range []string{"__EventFilter", "__FilterToConsumerBinding", "CommandLineEventConsumer", "ActiveScriptEventConsumer", "NTEventLogEventConsumer", "LogFileEventConsumer", "SMTPEventConsumer"} {
		t.Run(class, func(t *testing.T) {
			s, records := semanticFixture()
			next := map[string]Record{}
			for i, k := range s.Keys {
				key := strings.ReplaceAll(strings.ReplaceAll(k.Key, fixtureID("CD_", "__EventFilter"), fixtureID("CD_", class)), fixtureID("CI_", "__EventFilter"), fixtureID("CI_", class))
				s.Keys[i].Key = key
				if strings.Contains(key, "/CD_") {
					next[key] = renamedClass(class)
				} else {
					next[key] = renamedInstance(class)
				}
			}
			s.ReadRecord = func(key string) (Record, error) {
				r, ok := next[key]
				if !ok {
					return Record{}, ErrCorrupt
				}
				return r, nil
			}
			_ = records
			got, err := s.ReadSelected()
			if err != nil || len(got.Objects) != 2 {
				t.Fatalf("selected native class %s count=%d err=%v", class, len(got.Objects), err)
			}
			for _, o := range got.Objects {
				if o.Class != class || o.Properties["Count"].Value != uint32(7) {
					t.Fatal("class identity or typed default lost")
				}
			}
		})
	}
}
