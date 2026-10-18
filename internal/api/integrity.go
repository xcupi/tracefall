package api

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"tracefall/internal/model"
	"tracefall/internal/version"
)

// Integrity verification (Phase 11).
//
// Phase 10A RECORDED a SHA-512 over each collection's original evidence
// at ingestion. This file lets an investigator re-compute it later and
// answer the only question that matters: has the evidence changed since
// Tracefall first saw it?
//
// # Two rules govern everything here
//
// 1. It recomputes with the SAME functions Phase 10A used. Not an
//    equivalent reimplementation -- the same code. A verifier that
//    canonicalized even slightly differently would report a mismatch on
//    unchanged evidence, which is worse than not verifying at all.
//
// 2. It is READ-ONLY with respect to evidence and analysis. It never
//    rewrites the recorded digest, re-imports, re-analyzes, or touches
//    findings. The recorded digest is a historical fact captured at
//    ingestion; "verifying" by overwriting it would destroy the very
//    thing being checked.

// Verification outcomes.
const (
	// IntegrityVerified: recomputed digest equals the recorded one.
	IntegrityVerified = "verified"
	// IntegrityMismatch: the evidence is readable but hashes differently
	// than it did at ingestion. This is a finding about the EVIDENCE, not
	// an error in Tracefall.
	IntegrityMismatch = "mismatch"
	// IntegrityUnavailable: verification could not be performed -- no
	// digest was recorded (a collection ingested before Phase 10A), or
	// the original evidence is no longer reachable. Deliberately distinct
	// from "mismatch": not knowing is not the same as knowing it changed.
	IntegrityUnavailable = "unavailable"
)

// IntegrityResult is one verification's outcome.
type IntegrityResult struct {
	CollectionID string `json:"collection_id"`
	CaseID       string `json:"case_id"`
	Status       string `json:"status"`

	// RecordedSHA512 is the digest captured at ingestion and never
	// modified by verification. ComputedSHA512 is what the evidence
	// hashes to now; empty when verification could not run.
	//
	// Both are the COMPLETE 128-character digest. A truncated digest in a
	// verification result would be unusable as evidence of anything.
	RecordedSHA512 string `json:"recorded_sha512,omitempty"`
	ComputedSHA512 string `json:"computed_sha512,omitempty"`

	// Reason explains an unavailable result in plain language. It never
	// contains a server filesystem path.
	Reason string `json:"reason,omitempty"`

	// EvidenceKind names WHAT was hashed, because the answer differs by
	// source type and a reviewer must not have to guess: the received
	// upload bytes, the ordered AD1 segment bytes, or the directory
	// content digest.
	EvidenceKind string `json:"evidence_kind"`

	VerifiedAt  time.Time `json:"verified_at"`
	ToolVersion string    `json:"tool_version"`
	// DurationMS is how long the recomputation took, so a slow
	// verification is visibly slow work rather than an unexplained wait.
	DurationMS int64 `json:"duration_ms"`
}

// Evidence kinds, describing what the digest covers.
const (
	EvidenceKindUpload    = "uploaded archive bytes"
	EvidenceKindAD1       = "AD1 segment bytes, in order"
	EvidenceKindDiskImage = "disk image container bytes, in order"
	EvidenceKindDirectory = "directory content digest"
)

// ErrIntegrityNotRecorded means the collection has no recorded SHA-512.
var ErrIntegrityNotRecorded = errors.New("no integrity digest was recorded for this collection")

// VerifyCollectionIntegrity recomputes a collection's SHA-512 and
// compares it with the digest recorded at ingestion.
//
// It performs no writes to evidence, source files, events, findings or
// the collection row. The only thing it may write is an audit entry
// recording that a verification happened -- which is chain-of-custody
// information about the ANALYST's action, not about the evidence.
func (s *Service) VerifyCollectionIntegrity(caseID, collectionID string) (IntegrityResult, error) {
	collection, err := s.store.GetCollection(collectionID)
	if err != nil || collection.CaseID != caseID {
		return IntegrityResult{}, ErrCollectionNotFound
	}

	res := IntegrityResult{
		CollectionID:   collectionID,
		CaseID:         caseID,
		RecordedSHA512: collection.IntegritySHA512,
		VerifiedAt:     time.Now().UTC(),
		ToolVersion:    version.String(),
		EvidenceKind:   evidenceKindFor(collection.SourceType),
	}

	// A collection ingested before Phase 10A has nothing to verify
	// against. Reporting "unavailable" is the honest answer; computing a
	// digest now and calling it verified would attest to nothing.
	if collection.IntegritySHA512 == "" {
		res.Status = IntegrityUnavailable
		res.Reason = "This collection was ingested before Tracefall recorded integrity digests, so there is no original digest to compare against."
		s.auditVerification(caseID, collectionID, res)
		return res, nil
	}

	start := time.Now()
	computed, err := s.recomputeCollectionSHA512(caseID, collection)
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		// The evidence could not be read. That is not a mismatch -- the
		// digest is unknown, not different -- and the message must not
		// leak the server path that failed.
		res.Status = IntegrityUnavailable
		res.Reason = unavailableReason(err)
		s.auditVerification(caseID, collectionID, res)
		return res, nil
	}

	res.ComputedSHA512 = computed
	if computed == collection.IntegritySHA512 {
		res.Status = IntegrityVerified
	} else {
		res.Status = IntegrityMismatch
	}
	s.auditVerification(caseID, collectionID, res)
	return res, nil
}

// recomputeCollectionSHA512 dispatches to the SAME hashing the original
// ingestion used, chosen by source type.
func (s *Service) recomputeCollectionSHA512(caseID string, c model.Collection) (string, error) {
	switch c.SourceType {
	case model.SourceTypeAD1:
		// hashAD1Segments is Phase 10A's function, unchanged: the ordered
		// concatenation of every segment's raw bytes. Extracted or
		// decompressed content is deliberately never hashed here.
		paths, err := s.ad1SegmentPathsForCollection(caseID, c.ID)
		if err != nil {
			return "", err
		}
		_, sha512Hex, err := hashAD1Segments(paths)
		return sha512Hex, err

	case model.SourceTypeDiskImage:
		// The container file(s) as received -- E01 segments or the raw
		// file -- never the decoded disk or anything extracted from it.
		paths, err := s.diskImageSegmentPaths(caseID, c.ID)
		if err != nil {
			return "", err
		}
		_, sha512Hex, err := hashAD1Segments(paths)
		return sha512Hex, err

	case model.SourceTypeUpload:
		// The received bytes, still on disk exactly as uploaded. NOT the
		// extraction directory: hashing what came out of the archive
		// would answer a different question than the recorded digest
		// asked (see docs/evidence-integrity.md).
		return hashFileSHA512(s.files.UploadPath(caseID, c.ID))

	case model.SourceTypeLocalPath:
		// hashDirectory is Phase 10A's function, unchanged: relative path
		// + NUL + contents + NUL per file, in WalkDir lexical order. No
		// mtime, inode, permission or absolute-path input, so a pure
		// metadata change does not alter the digest.
		if c.EvidenceDirectory == "" {
			return "", errors.New("collection records no evidence directory")
		}
		_, sha512Hex, err := hashDirectory(c.EvidenceDirectory)
		return sha512Hex, err

	default:
		return "", fmt.Errorf("source type %q cannot be re-verified", c.SourceType)
	}
}

// hashFileSHA512 streams one file. Streamed rather than read whole
// because an evidence archive can be far larger than available memory --
// the same reason Phase 10A streamed it on the way in.
func hashFileSHA512(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func evidenceKindFor(sourceType string) string {
	switch sourceType {
	case model.SourceTypeAD1:
		return EvidenceKindAD1
	case model.SourceTypeDiskImage:
		return EvidenceKindDiskImage
	case model.SourceTypeUpload:
		return EvidenceKindUpload
	case model.SourceTypeLocalPath:
		return EvidenceKindDirectory
	default:
		return ""
	}
}

// unavailableReason turns a read failure into an investigator-facing
// sentence.
//
// It classifies rather than forwarding the error, because a raw
// filesystem error embeds the absolute server path it was reading --
// exactly the leak Phase 8.2 fixed for discovery errors and which this
// endpoint must not reintroduce.
func unavailableReason(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "The original evidence is no longer present on this server, so its digest cannot be recomputed. The recorded digest is unchanged."
	case errors.Is(err, os.ErrPermission):
		return "Tracefall does not have permission to read the original evidence, so its digest cannot be recomputed."
	case errors.Is(err, ErrCollectionNotFound):
		return "The original evidence for this collection could not be located."
	default:
		return "The original evidence could not be read, so its digest cannot be recomputed."
	}
}

// auditVerification records that a verification happened.
//
// Best-effort, like every other audit write (see Service.audit): a
// failure to record the action must not change the answer the
// investigator is given. The summary states the OUTCOME, so the audit
// trail shows not just that evidence was checked but what the check
// found.
func (s *Service) auditVerification(caseID, collectionID string, res IntegrityResult) {
	var summary string
	switch res.Status {
	case IntegrityVerified:
		summary = "Integrity verified: evidence SHA-512 matches the digest recorded at ingestion"
	case IntegrityMismatch:
		summary = "INTEGRITY MISMATCH: evidence SHA-512 differs from the digest recorded at ingestion"
	default:
		summary = "Integrity verification could not be completed: " + res.Reason
	}
	s.audit(caseID, model.AuditIntegrityVerified, model.TargetCollection, collectionID, summary)
}
