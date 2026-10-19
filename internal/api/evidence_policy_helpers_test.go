package api

import (
	"tracefall/internal/casefiles"
	"tracefall/internal/store"
)

// newPermissiveService is NewService with server-path ingest allowed for any
// path. Tests create evidence in t.TempDir, so they need that; production
// never does. The product default (NewService) refuses server-path ingest,
// and the tests that check the refusal use NewService directly.
func newPermissiveService(db *store.Store, files *casefiles.Store) *Service {
	s := NewService(db, files)
	if err := s.SetEvidencePathPolicy(nil, true); err != nil {
		panic(err)
	}
	return s
}
