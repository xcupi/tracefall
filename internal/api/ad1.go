// AD1 forensic image ingestion (Phase 7). This file is the adapter layer
// between internal/ad1 (which only knows how to read the container
// format) and the rest of this package's existing Discover/Select/Import
// evidence workflow -- see docs/ad1-ingestion.md for the full design
// writeup. Nothing here duplicates that workflow: an AD1 collection is
// cataloged the same way a ZIP/local-path one is (a Collection row plus
// one SourceFile row per contained file, see catalogAD1), and imported
// the same way too (ImportEvidence's existing loop, with one small
// adapter -- extractAD1Entry, called from ImportEvidence -- that
// materializes exactly the selected entry's bytes on disk immediately
// before internal/ingest.ParseFile reads them, exactly as ParseFile
// already expects for every other collection type).
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/ad1"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
)

// sniffStagedFile peeks at a file already written to disk (an uploaded
// evidence package staged by stageUpload) and reports whether it's an
// AD1 image, and separately whether it's ADCRYPT-encrypted -- see
// ad1.Sniff. Errors opening the file are treated as "not AD1" by the
// caller (DiscoverEvidenceFromUpload falls through to the existing ZIP
// path, which will fail with its own clear error if the file isn't a
// zip either).
func sniffStagedFile(path string) (isAD1, isEncrypted bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, false, err
	}
	defer f.Close()
	return ad1.Sniff(f)
}

// discoverAD1Upload is DiscoverEvidenceFromUpload's AD1 branch: the
// upload has already been staged and hashed (stagingPath, uploadSize,
// archiveHash) and checked for duplicates by the caller. It takes
// ownership of stagingPath (renaming it into the collection's own
// directory, via casefiles.AD1Path) and sets *stagingClaimed so the
// caller's own deferred staging cleanup doesn't also try to remove it.
//
// Unlike the ZIP path, nothing is extracted here -- see catalogAD1's doc
// comment for why cataloging an AD1 is cheap by design (Phase 7
// requirement: discovery must stay cheap even for a large image).
//
// filename (the investigator's own name for the uploaded file, e.g.
// "DiskDrigger.ad1") is stored as OriginalFilename purely for display --
// it is NEVER used to relocate the container on disk. At import time,
// ad1SegmentPathsForCollection reopens an upload-sourced AD1 by its
// deterministic staged location (casefiles.AD1Path(caseID,
// collectionID)), not by this name, so a blank, missing, or
// attacker-influenced filename here can't affect where Tracefall reads
// evidence bytes from -- see that function's doc comment.
func (s *Service) discoverAD1Upload(caseID string, stagingPath string, stagingClaimed *bool, uploadSize int64, archiveHash string, filename string) (DiscoverResult, error) {
	collectionID := uuid.NewString()
	ad1Path := s.files.AD1Path(caseID, collectionID)
	if filename == "" {
		filename = "AD1 forensic image"
	}
	collection := model.Collection{
		ID: collectionID, CaseID: caseID, CreatedAt: time.Now().UTC(),
		SourceType: model.SourceTypeAD1, ArchiveHash: archiveHash,
		OriginalFilename:  filename, // display only -- see doc comment above
		EvidenceDirectory: s.files.EvidenceDir(caseID, collectionID),
		IngestionStatus:   model.CollectionStatusPending,
	}
	// The uploaded image needs a home on disk before it can be read, but
	// the collection ROW is committed only once the catalog is complete
	// (see catalogAD1). A corrupt or unreadable image therefore leaves
	// nothing behind in the database -- not even a "failed" collection.
	if err := s.files.EnsureCollectionDir(caseID, collectionID); err != nil {
		return DiscoverResult{}, fmt.Errorf("preparing collection storage: %w", err)
	}

	succeeded := false
	defer func() {
		if !succeeded {
			_ = s.files.RemoveCollectionDir(caseID, collectionID)
		}
	}()

	if err := os.Rename(stagingPath, ad1Path); err != nil {
		return DiscoverResult{}, fmt.Errorf("finalizing uploaded AD1 image: %w", err)
	}
	*stagingClaimed = true

	res, err := s.catalogAD1(caseID, collection, []string{ad1Path})
	if err != nil {
		return DiscoverResult{}, err
	}
	res.UploadSizeBytes = uploadSize

	_ = s.files.WriteMetadata(caseID, collectionID, res.Collection)

	succeeded = true
	s.audit(caseID, model.AuditEvidenceDiscovered, model.TargetCollection, collectionID,
		fmt.Sprintf("AD1 forensic image discovered from upload: %d file(s), %d supported", res.DiscoveredCount, res.SupportedCount))
	return res, nil
}

// discoverAD1FromPath is DiscoverEvidenceFromPath's AD1 branch: path
// already sniffed as AD1 by the caller. Unlike an uploaded AD1, nothing
// is copied -- the segment file(s) stay exactly where the investigator
// put them (matching every other local-path collection's behavior;
// Tracefall never takes ownership of an investigator's own files) --
// findSiblingSegments locates any additional .ad2/.ad3/... segments next
// to path so a segmented local-path image can be opened in full, which
// an uploaded single-multipart-file AD1 cannot (see
// docs/ad1-ingestion.md's "Segmented images" section).
func (s *Service) discoverAD1FromPath(caseID, path string) (DiscoverResult, error) {
	segmentPaths, err := ad1SegmentPathsForLocalFile(path)
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("locating AD1 segment files: %w", err)
	}

	hash, err := hashAD1Segments(segmentPaths)
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("fingerprinting AD1 image: %w", err)
	}
	if err := s.checkDuplicateEvidence(caseID, hash); err != nil {
		return DiscoverResult{}, err
	}

	collectionID := uuid.NewString()
	collection := model.Collection{
		ID: collectionID, CaseID: caseID, CreatedAt: time.Now().UTC(),
		SourceType: model.SourceTypeAD1, ArchiveHash: hash,
		OriginalFilename:  path, // the investigator's own first segment, reopened at import time -- never modified, never copied
		EvidenceDirectory: s.files.EvidenceDir(caseID, collectionID),
		IngestionStatus:   model.CollectionStatusPending,
	}

	// The collection directory holds files extracted from the image at
	// import time, so it has to exist; the collection ROW is committed
	// only once the catalog is complete (see catalogAD1). A corrupt image
	// leaves neither the directory nor any database row behind.
	if err := s.files.EnsureCollectionDir(caseID, collectionID); err != nil {
		return DiscoverResult{}, fmt.Errorf("preparing collection storage: %w", err)
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = s.files.RemoveCollectionDir(caseID, collectionID)
		}
	}()

	res, err := s.catalogAD1(caseID, collection, segmentPaths)
	if err != nil {
		return DiscoverResult{}, err
	}
	succeeded = true
	s.audit(caseID, model.AuditEvidenceDiscovered, model.TargetCollection, collectionID,
		fmt.Sprintf("AD1 forensic image discovered from local path %q: %d file(s), %d supported", path, res.DiscoveredCount, res.SupportedCount))
	return res, nil
}

// ad1SegmentPathsForLocalFile returns the full ordered segment list for a
// local-path AD1 (first segment always first).
func ad1SegmentPathsForLocalFile(first string) ([]string, error) {
	return ad1.FindSiblingSegments(first)
}

// hashAD1Segments computes a deterministic SHA-256 across every segment
// file's raw bytes in order -- the AD1 analog of hashDirectory, streamed
// rather than loaded into memory (see internal/ad1's package doc comment
// on why an AD1 image is never fully buffered).
func hashAD1Segments(segmentPaths []string) (string, error) {
	h := sha256.New()
	for _, p := range segmentPaths {
		f, err := os.Open(p)
		if err != nil {
			return "", err
		}
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// catalogAD1 opens the AD1 image at segmentPaths and walks it
// (internal/ad1.Container.Walk), turning each FILE entry (directories
// aren't modeled as SourceFile rows, matching ingest.Discover's identical
// choice for ZIP/local-path collections) into a model.SourceFile row --
// classified against the same parser registry ingest.Discover uses, so
// an EvtxECmd CSV found inside an AD1 is recognized exactly as it would
// be if it had arrived in a KAPE ZIP. This is deliberately as cheap as
// internal/ad1 can make it: Walk only reads each entry's fixed-size
// header and small metadata items, never decompresses file content, so
// cataloging a large image stays fast (Phase 7 requirement 8) --
// SHA-256 is left blank here (see model.SourceFile.SHA256's doc comment)
// and only computed once a file is actually selected and imported
// (extractAD1Entry). Any MD5/SHA1 AD1 itself recorded is surfaced
// immediately, in EmbeddedHash, since that costs nothing extra to read.
func (s *Service) catalogAD1(caseID string, collection model.Collection, segmentPaths []string) (DiscoverResult, error) {
	collectionID := collection.ID
	c, err := ad1.Open(segmentPaths, s.ad1Limits)
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("%w: %v", ErrInvalidAD1, err)
	}
	defer c.Close()

	registry := ingest.Registry()
	now := time.Now().UTC()
	seenHashes := map[string]bool{}
	// make(...,0,...), not `var`: DiscoverResult.SourceFiles has no
	// `omitempty`, so an AD1 with zero entries (TestAD1_EmptyImage) would
	// otherwise serialize this as JSON `null` -- the frontend already
	// guards this specific field defensively (`disc.source_files || []`,
	// see internal/web/static/app.js), so this isn't a live crash, just
	// bringing it in line with the fix applied to the equivalent nil-slice
	// bug class found elsewhere (internal/api/service.go's Investigation
	// and ImportEvidence) during Phase 7 browser verification.
	sourceFiles := make([]model.SourceFile, 0, 16)
	var supported, unsupported, duplicate int

	walkErr := c.Walk(func(e ad1.Entry) error {
		if e.IsDir {
			return nil
		}
		var artifactType, parserName string
		supportedFile := false
		for _, p := range registry {
			if p.Detect(e.Path) {
				artifactType, parserName, supportedFile = p.ArtifactType(), p.Name(), true
				break
			}
		}
		embedded := embeddedHashString(e)

		sf := model.SourceFile{
			ID: uuid.NewString(), CaseID: caseID, CollectionID: collectionID,
			OriginalFilename: e.Name, Path: e.Path, ArtifactType: artifactType, Parser: parserName,
			Supported: supportedFile, SizeBytes: e.SizeBytes, EmbeddedHash: embedded, DiscoveredAt: now,
		}
		switch {
		case !supportedFile:
			sf.ImportStatus = model.SourceFileUnsupported
			unsupported++
		case embedded != "" && seenHashes[embedded]:
			// Best-effort intra-batch duplicate detection using AD1's own
			// embedded hash, when it recorded one -- see this file's doc
			// comment on why a true SHA-256 (what ingest.Discover uses
			// for this same check on a ZIP/local-path collection) isn't
			// affordable here. An AD1 with no embedded hashes at all
			// simply doesn't get this check; that's a narrower guarantee
			// than the ZIP path's, documented in docs/ad1-ingestion.md.
			sf.ImportStatus = model.SourceFileDuplicate
			duplicate++
			supported++
		default:
			sf.ImportStatus = model.SourceFileDiscovered
			supported++
		}
		if embedded != "" {
			seenHashes[embedded] = true
		}
		sourceFiles = append(sourceFiles, sf)
		return nil
	})
	if walkErr != nil {
		return DiscoverResult{}, fmt.Errorf("%w: %v", ErrInvalidAD1, walkErr)
	}

	if len(sourceFiles) == 0 {
		return DiscoverResult{}, fmt.Errorf("%w: the AD1 image contains no files", ErrNoEvidenceFound)
	}

	// Nothing above wrote to the database, so a corrupt, empty or
	// unreadable image returns having created no collection at all.
	collection.IngestionStatus = model.CollectionStatusPending
	collection.FileCount = len(sourceFiles)
	collection.SupportedFileCount = supported
	collection.UnsupportedFileCount = unsupported
	full, err := s.commitDiscovery(collection, sourceFiles)
	if err != nil {
		return DiscoverResult{}, err
	}

	triaged := triageAll(sourceFiles)
	return DiscoverResult{
		Collection: full, SourceFiles: triaged, Coverage: computeCoverage(triaged),
		DiscoveredCount: len(sourceFiles), SupportedCount: supported, UnsupportedCount: unsupported, DuplicateCount: duplicate,
	}, nil
}

// embeddedHashString formats an AD1 entry's own reported hash (preferring
// SHA-1 over MD5 when both are present, the stronger of the two) as
// "algo:hexdigest", or "" if AD1 recorded neither -- see
// model.SourceFile.EmbeddedHash's doc comment.
func embeddedHashString(e ad1.Entry) string {
	if e.SHA1 != "" {
		return "sha1:" + e.SHA1
	}
	if e.MD5 != "" {
		return "md5:" + e.MD5
	}
	return ""
}

// extractAD1Entry is ImportEvidence's adapter for an AD1-sourced
// collection: it materializes exactly the one requested file's bytes
// under the collection's EvidenceDirectory (creating parent directories
// as needed, the same layout ingest.ParseFile already expects for every
// other collection type), computes Tracefall's own SHA-256 while writing
// it (a natural byproduct of the copy, not an extra pass over the data),
// and records that hash via Store.SetSourceFileSHA256. It never modifies
// the original AD1 -- every read goes through internal/ad1's read-only
// Container.Extract. Called once per selected file, immediately before
// ingest.ParseFile reads that same path -- see ImportEvidence.
func (s *Service) extractAD1Entry(caseID, collectionID string, sf model.SourceFile) error {
	segmentPaths, err := s.ad1SegmentPathsForCollection(caseID, collectionID)
	if err != nil {
		return err
	}
	c, err := ad1.Open(segmentPaths, s.ad1Limits)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidAD1, err)
	}
	defer c.Close()

	var entry ad1.Entry
	found := false
	if err := c.Walk(func(e ad1.Entry) error {
		if !e.IsDir && e.Path == sf.Path {
			entry = e
			found = true
		}
		return nil
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidAD1, err)
	}
	if !found {
		return fmt.Errorf("%w: %q no longer found in AD1 image", ad1.ErrNotFound, sf.Path)
	}

	evidenceDirAbs, err := filepath.Abs(s.files.EvidenceDir(caseID, collectionID))
	if err != nil {
		return fmt.Errorf("resolving evidence directory: %w", err)
	}
	dest := filepath.Join(evidenceDirAbs, filepath.FromSlash(sf.Path))
	// Belt-and-suspenders, mirroring internal/archive's safeJoin: entry
	// names are already validated component-by-component during Walk
	// (see ad1.validateEntryName), so sf.Path can't actually contain a
	// ".." segment -- but a corrupt/hostile AD1 is exactly the situation
	// where trusting only one layer of validation is the wrong call.
	if rel, relErr := filepath.Rel(evidenceDirAbs, dest); relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: entry path %q would resolve outside the extraction directory", ad1.ErrCorrupt, sf.Path)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("creating destination directory for extracted AD1 entry: %w", err)
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating extracted file: %w", err)
	}
	defer out.Close()

	h := sha256.New()
	if _, err := c.Extract(entry, io.MultiWriter(out, h)); err != nil {
		return err
	}
	if err := s.store.SetSourceFileSHA256(sf.ID, hex.EncodeToString(h.Sum(nil))); err != nil {
		return fmt.Errorf("recording extracted file hash: %w", err)
	}
	return nil
}

// ad1SegmentPathsForCollection re-resolves an AD1 collection's segment
// files at import time.
//
// An uploaded collection's original bytes always live at the
// deterministic path casefiles.AD1Path(caseID, collectionID) (see
// discoverAD1Upload) -- checked first, and used whenever it exists,
// regardless of whatever Collection.OriginalFilename says (that field is
// upload-sourced collections' display name only, e.g. "DiskDrigger.ad1",
// never a real filesystem path -- see discoverAD1Upload's doc comment).
//
// Otherwise this is a local-path collection, whose OriginalFilename IS
// the investigator's own real first-segment path (never copied, per
// discoverAD1FromPath) -- sibling .ad2/.ad3/... segments are re-derived
// from it the same way discovery did (never recorded individually; the
// sibling set is a deterministic function of the first segment's path
// and is re-validated by ad1.Open regardless).
func (s *Service) ad1SegmentPathsForCollection(caseID, collectionID string) ([]string, error) {
	collection, err := s.store.GetCollection(collectionID)
	if err != nil || collection.CaseID != caseID {
		return nil, ErrCollectionNotFound
	}
	if uploaded := s.files.AD1Path(caseID, collectionID); fileExists(uploaded) {
		return []string{uploaded}, nil
	}
	return ad1SegmentPathsForLocalFile(collection.OriginalFilename)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
