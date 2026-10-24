package api

import (
	"fmt"
	"testing"
)

func TestReviewBatchesProviderBindingIsNotAddressAndRevisionOnly(t *testing.T) {
	m := newLLMConfiguration()
	got := m.batchBinding()
	if got == payloadHash(fmt.Sprintf("%p", m), fmt.Sprintf("%d", m.revision)) {
		t.Fatal("provider generation derives only from reusable process address and revision")
	}
	if got != m.batchBinding() {
		t.Fatal("unchanged configuration invalidated its plan")
	}
	other := newLLMConfiguration()
	if got == other.batchBinding() {
		t.Fatal("new provider generation reused a binding")
	}
	m.revision++
	if got == m.batchBinding() {
		t.Fatal("provider revision failed to invalidate its plan")
	}
}
