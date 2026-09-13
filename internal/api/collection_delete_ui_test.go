package api

import (
	"strings"
	"testing"
)

// The collection Delete control's in-flight state. The investigation's
// question was whether "Deleting..." can be left on screen forever by
// frontend state that is never reset -- these assert that it cannot, on
// any path.

func collectionDeleteHandler(t *testing.T) string {
	t.Helper()
	src := string(appJS(t))
	return sectionBetween(t, src, `const btn = root.querySelector(".delete-collection-btn");`,
		"\n// ---------------- Integrity verification")
}

func TestCollectionDeleteUI_StateIsResetOnEveryPath(t *testing.T) {
	fn := collectionDeleteHandler(t)

	if !strings.Contains(fn, `btn.textContent = "Deleting...";`) {
		t.Fatal("the control does not enter an in-flight state")
	}
	if !strings.Contains(fn, "btn.disabled = true;") {
		t.Error("the control is not disabled while the request runs")
	}

	// The reset must be in a finally, so no later throw can skip it.
	finallyIdx := strings.Index(fn, "} finally {")
	if finallyIdx < 0 {
		t.Fatal("the in-flight state is not reset in a finally block; a throw after the " +
			"response would leave the control stuck on \"Deleting...\"")
	}
	tail := fn[finallyIdx:]
	for _, want := range []string{"btn.disabled = false;", "btn.textContent = original;"} {
		if !strings.Contains(tail, want) {
			t.Errorf("the finally block does not restore %q", want)
		}
	}

	// Success must be signalled only after the await, and the re-render
	// must happen after the state is restored.
	awaitIdx := strings.Index(fn, "await api(")
	deletedIdx := strings.Index(fn, "deleted = true;")
	routeIdx := strings.Index(fn, "route();")
	if awaitIdx < 0 || deletedIdx < awaitIdx {
		t.Error("success is recorded before the server responded")
	}
	if routeIdx < finallyIdx {
		t.Error("the view is re-rendered before the control's state is restored")
	}
}

func TestCollectionDeleteUI_FailureShowsTheErrorAndDoesNotNavigate(t *testing.T) {
	fn := collectionDeleteHandler(t)

	catchIdx := strings.Index(fn, "} catch (err) {")
	if catchIdx < 0 {
		t.Fatal("the delete has no failure path")
	}
	finallyIdx := strings.Index(fn, "} finally {")
	catchBody := fn[catchIdx:finallyIdx]

	if !strings.Contains(catchBody, "errorBox(err)") {
		t.Error("a failed deletion shows no error")
	}
	// The re-render must be gated on success, not run regardless.
	if strings.Contains(catchBody, "route()") {
		t.Error("a failed deletion navigates as though it had succeeded")
	}
	if !strings.Contains(fn, "if (deleted) {") {
		t.Error("the re-render is not gated on the request having succeeded")
	}
	// Repeated failures must not stack error boxes on the card.
	if !strings.Contains(fn, "previousError.remove()") {
		t.Error("a second failure adds another error box instead of replacing the first")
	}
}

// A timeout or transport failure reaches the same catch, so the control
// is restored and the collection is NOT reported as deleted.
func TestCollectionDeleteUI_TimeoutIsTreatedAsFailureNotSuccess(t *testing.T) {
	fn := collectionDeleteHandler(t)

	// `deleted` starts false and is only ever set after the await
	// resolves, so a rejected request -- which is what a timeout or a
	// dropped connection looks like to fetch -- can never take the
	// success path.
	if !strings.Contains(fn, "let deleted = false;") {
		t.Fatal("there is no explicit success flag; a rejected request could fall through to the success path")
	}
	if strings.Count(fn, "deleted = true;") != 1 {
		t.Error("success is recorded in more than one place")
	}
	awaitIdx := strings.Index(fn, "await api(")
	setIdx := strings.Index(fn, "deleted = true;")
	if setIdx < awaitIdx {
		t.Error("the success flag is set before the request resolves")
	}
}

// The control must say that deletion is synchronous and can be slow for
// a collection with many discovered files -- the case this
// investigation was about.
func TestCollectionDeleteUI_ExplainsWhatItIsWaitingFor(t *testing.T) {
	fn := collectionDeleteHandler(t)
	if !strings.Contains(fn, "SYNCHRONOUS") {
		t.Error("the handler does not record that deletion is synchronous")
	}
	if !strings.Contains(fn, "catalog row") {
		t.Error("the handler does not record why a pending collection is the slow case")
	}
}
