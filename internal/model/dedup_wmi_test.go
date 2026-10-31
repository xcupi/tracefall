package model

import "testing"

func TestWMISnapshotDedupNativeIdentityAndRepositoryState(t *testing.T) {
	e := Event{ArtifactType: ArtifactWMIRepository, EventType: EventWMISnapshot, Host: "host01", SourceReference: "native-key", Extra: map[string]string{"wmi_native_key": "native-key", "wmi_repository_sha256": "repository-a", "wmi_record_sha256": "object-a"}}
	for _, key := range []string{"wmi_native_key", "wmi_repository_sha256", "wmi_record_sha256"} {
		other := e
		other.Extra = map[string]string{}
		for k, v := range e.Extra {
			other.Extra[k] = v
		}
		other.Extra[key] += "-changed"
		if other.ComputeDedupHash() == e.ComputeDedupHash() {
			t.Fatalf("changed native snapshot state collapsed: %s", key)
		}
	}
	other := e
	other.CollectionID = "recollected"
	other.SourceFileID = "source02"
	if other.ComputeDedupHash() != e.ComputeDedupHash() {
		t.Fatal("identical recollection cannot add observation")
	}
}
