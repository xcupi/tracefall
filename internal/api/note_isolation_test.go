package api

import (
	"net/http"
	"testing"

	"tracefall/internal/model"
)

// F-1: before Phase 12, PATCH/DELETE /api/notes/{noteID} took a bare
// note id with no case in the route and no ownership predicate in the
// store (`UPDATE notes ... WHERE id = ?`). Anyone who knew or guessed a
// note id could edit or delete a note in ANY case.
//
// The route is now case-scoped and the case is part of the SQL
// predicate, so a note id from another case matches no row.
func TestNotes_CannotBeEditedThroughAnotherCase(t *testing.T) {
	mux := newTestRouter(t)
	a := mustCreateCase(t, mux, "Case A")
	b := mustCreateCase(t, mux, "Case B")

	var note model.Note
	rec := doJSON(t, mux, "POST", "/api/cases/"+a.ID+"/notes",
		map[string]string{"target_type": model.TargetCase, "target_id": a.ID, "note": "case A private note"}, &note)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create note: status %d", rec.Code)
	}

	// Case B must not be able to reach case A's note by id.
	rec = doJSON(t, mux, "PATCH", "/api/cases/"+b.ID+"/notes/"+note.ID,
		map[string]string{"note": "tampered through another case"}, nil)
	if rec.Code == http.StatusOK {
		t.Errorf("PATCH through case B returned 200; a note id must not cross case boundaries")
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rec.Code)
	}

	rec = doJSON(t, mux, "DELETE", "/api/cases/"+b.ID+"/notes/"+note.ID, nil, nil)
	if rec.Code == http.StatusOK {
		t.Errorf("DELETE through case B returned 200; a note id must not cross case boundaries")
	}

	// The note is untouched, and still reachable from its own case.
	var notes []model.Note
	doJSON(t, mux, "GET", "/api/cases/"+a.ID+"/notes", nil, &notes)
	if len(notes) != 1 {
		t.Fatalf("case A has %d notes, want 1 -- the note was destroyed through another case", len(notes))
	}
	if notes[0].Text != "case A private note" {
		t.Errorf("note text = %q; it was modified through another case", notes[0].Text)
	}

	// And the legitimate owner can still edit and delete it.
	if rec := doJSON(t, mux, "PATCH", "/api/cases/"+a.ID+"/notes/"+note.ID,
		map[string]string{"note": "updated by its owner"}, nil); rec.Code != http.StatusOK {
		t.Errorf("owner PATCH: status %d, want 200", rec.Code)
	}
	if rec := doJSON(t, mux, "DELETE", "/api/cases/"+a.ID+"/notes/"+note.ID, nil, nil); rec.Code != http.StatusOK {
		t.Errorf("owner DELETE: status %d, want 200", rec.Code)
	}
}

// An unknown note id must be indistinguishable from one belonging to
// another case, so the API cannot be used to probe which ids exist.
func TestNotes_UnknownAndForeignIDsAreIndistinguishable(t *testing.T) {
	mux := newTestRouter(t)
	a := mustCreateCase(t, mux, "Probe A")
	b := mustCreateCase(t, mux, "Probe B")

	var note model.Note
	doJSON(t, mux, "POST", "/api/cases/"+a.ID+"/notes",
		map[string]string{"target_type": model.TargetCase, "target_id": a.ID, "note": "n"}, &note)

	foreign := doJSON(t, mux, "DELETE", "/api/cases/"+b.ID+"/notes/"+note.ID, nil, nil)
	unknown := doJSON(t, mux, "DELETE", "/api/cases/"+b.ID+"/notes/00000000-0000-0000-0000-000000000000", nil, nil)

	if foreign.Code != unknown.Code {
		t.Errorf("a foreign note id (%d) is distinguishable from an unknown one (%d); that is a probing oracle",
			foreign.Code, unknown.Code)
	}
	if foreign.Body.String() != unknown.Body.String() {
		t.Errorf("response bodies differ:\n foreign: %s\n unknown: %s", foreign.Body.String(), unknown.Body.String())
	}
}
