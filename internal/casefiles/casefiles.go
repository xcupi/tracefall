// Package casefiles manages the on-disk layout for a case's uploaded and
// extracted evidence. It knows nothing about ZIP safety (internal/archive),
// forensic parsing (internal/parsers, internal/ingest), or collection
// metadata beyond what it writes to metadata.json -- it is purely "where
// do this case's files live on disk," kept separate so that layout can
// change without touching upload validation or ingestion logic.
package casefiles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Store resolves per-case, per-collection file paths under a root data
// directory:
//
//	<root>/cases/<caseID>/collections/<collectionID>/upload.zip     original archive, preserved unmodified
//	<root>/cases/<caseID>/collections/<collectionID>/evidence/      the archive's contents, safely extracted --
//	                                                                 this is what internal/ingest.Discover catalogs
//	                                                                 and internal/ingest.ParseFile reads from
//	<root>/cases/<caseID>/collections/<collectionID>/metadata.json  the collection's own self-description
//
// Every collection gets its own subtree so that adding a second (or
// third, ...) collection to a case never touches the first's files, and
// so a failed collection can be cleaned up without disturbing its
// siblings.
type Store struct {
	root string
}

// NewStore returns a Store rooted at root. Directories are created on
// first use (via EnsureCollectionDir), not eagerly here.
func NewStore(root string) *Store {
	return &Store{root: root}
}

// CaseDir returns the root directory for one case's files.
func (s *Store) CaseDir(caseID string) string {
	return filepath.Join(s.root, "cases", caseID)
}

// CollectionDir returns the root directory for one collection's files.
func (s *Store) CollectionDir(caseID, collectionID string) string {
	return filepath.Join(s.CaseDir(caseID), "collections", collectionID)
}

// UploadPath returns where a collection's original uploaded archive is
// stored.
func (s *Store) UploadPath(caseID, collectionID string) string {
	return filepath.Join(s.CollectionDir(caseID, collectionID), "upload.zip")
}

// EvidenceDir returns where a collection's extracted evidence lives --
// the directory internal/ingest.Discover/ParseFile are pointed at after
// a successful upload.
func (s *Store) EvidenceDir(caseID, collectionID string) string {
	return filepath.Join(s.CollectionDir(caseID, collectionID), "evidence")
}

// MetadataPath returns where a collection's self-describing metadata
// sidecar lives -- see WriteMetadata.
func (s *Store) MetadataPath(caseID, collectionID string) string {
	return filepath.Join(s.CollectionDir(caseID, collectionID), "metadata.json")
}

// EnsureCollectionDir removes any existing files for this specific
// collection (guaranteeing a clean slate -- relevant if a prior attempt
// was interrupted before its own cleanup ran) and creates a fresh, empty
// EvidenceDir. It never touches sibling collections under the same case.
func (s *Store) EnsureCollectionDir(caseID, collectionID string) error {
	dir := s.CollectionDir(caseID, collectionID)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("clearing existing collection directory: %w", err)
	}
	if err := os.MkdirAll(s.EvidenceDir(caseID, collectionID), 0o755); err != nil {
		return fmt.Errorf("creating collection evidence directory: %w", err)
	}
	return nil
}

// RemoveCaseDir deletes everything stored for one case -- every
// collection's upload/evidence/metadata, and the case directory itself.
// Used by case deletion (see internal/api.Service.DeleteCase) so no
// on-disk evidence survives the case it belonged to.
func (s *Store) RemoveCaseDir(caseID string) error {
	return os.RemoveAll(s.CaseDir(caseID))
}

// RemoveEvidenceFile deletes one file from within a collection's
// extracted evidence directory -- used when a single evidence file is
// deleted (see internal/api.Service.DeleteSourceFile) without touching
// any of that collection's other files. relPath is validated to resolve
// inside the collection's EvidenceDir before anything is removed, the
// same defense-in-depth safe-join check internal/archive uses during
// extraction -- a SourceFile's Path is always produced by
// internal/ingest.Discover walking that same directory, so this should
// never actually reject a legitimate call, but a deletion path is exactly
// where a defensive check against an unexpected ".." earns its keep.
// Removing a file that's already gone (e.g. a retried request) is not an
// error.
func (s *Store) RemoveEvidenceFile(caseID, collectionID, relPath string) error {
	dir := s.EvidenceDir(caseID, collectionID)
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving evidence directory: %w", err)
	}
	target := filepath.Join(dirAbs, filepath.FromSlash(relPath))
	rel, err := filepath.Rel(dirAbs, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("refusing to remove path outside evidence directory: %q", relPath)
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing evidence file: %w", err)
	}
	return nil
}

// RemoveCollectionDir deletes everything stored for one collection. Used
// to clean up after a failed or incomplete upload/ingest so no partial
// or untrusted data is left behind -- critically, this leaves every
// *other* collection in the case (including one already successfully
// ingested) completely untouched.
func (s *Store) RemoveCollectionDir(caseID, collectionID string) error {
	return os.RemoveAll(s.CollectionDir(caseID, collectionID))
}

// WriteMetadata marshals v (typically the collection's model.Collection
// record) as JSON to this collection's metadata.json. This is a
// self-contained, on-disk record of the collection's provenance
// independent of the database -- if the evidence directory is ever
// copied or archived elsewhere, its origin travels with it. Failing to
// write it is not treated as fatal by callers (see internal/api), since
// the authoritative record is always the database.
func (s *Store) WriteMetadata(caseID, collectionID string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling collection metadata: %w", err)
	}
	if err := os.WriteFile(s.MetadataPath(caseID, collectionID), data, 0o644); err != nil {
		return fmt.Errorf("writing collection metadata: %w", err)
	}
	return nil
}
