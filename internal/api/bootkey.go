package api

// Collection-scoped boot-key preparation (Phase 19).
//
// A SAM hive's NT hashes are encrypted under the machine boot key, which
// lives in the SYSTEM hive and NOT in the SAM. Decoding them therefore
// needs two files from the same collection, and the boot key has to be
// in hand BEFORE the SAM is parsed.
//
// WHY THIS IS NOT DONE IN THE PARSER
//
// The first implementation had the SAM parser look for a SYSTEM hive
// beside the SAM on disk. That is correct for a directory of extracted
// files and wrong for an AD1 image: AD1 entries are materialized one at
// a time immediately before each is parsed (see extractAD1Entry), so at
// the moment the SAM is parsed the SYSTEM hive has not been written yet.
// On the real evidence this was measured at a 6.2-second gap -- SAM
// extracted at 23:54:08, SYSTEM at 23:54:14 -- and every hash came back
// "encrypted, no SYSTEM hive" while the SYSTEM hive sat in the very same
// collection. The parser was racing the extraction order and losing.
//
// Preparing the key here removes the race by construction: it happens
// once, before the parse loop starts, and it looks at the collection's
// CATALOG rather than at whatever happens to be on disk at that instant.
//
// COST
//
// The whole step is skipped unless the batch actually contains a SAM
// hive, so an import with no SAM pays nothing. When it does run, the
// SYSTEM hive is opened once and the key derived once for the entire
// collection -- never once per SAM, and certainly never once per
// account.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/regf"
	"tracefall/internal/sam"
)

// maxSystemCandidates bounds how many hives are opened looking for a
// boot key. A collection can hold thousands of files; trying them all
// would turn one SAM into an unbounded amount of work.
const maxSystemCandidates = 32

// prepareBootKey derives the machine boot key for one collection, or
// explains why it could not.
//
// batch is the set of files about to be parsed. The SYSTEM hive is
// looked for across the WHOLE collection, not just the batch: an analyst
// who imported the SAM alone should still get their hashes decoded from
// a SYSTEM hive that is catalogued beside it.
func (s *Service) prepareBootKey(caseID, collectionID string, collection model.Collection, batch []model.SourceFile) parsers.ParseContext {
	if !batchContainsSAM(batch) {
		// Nothing in this import needs a boot key. Cost: one loop over
		// the batch's paths.
		return parsers.ParseContext{}
	}

	candidates, err := s.systemHiveCandidates(caseID, collectionID)
	if err != nil || len(candidates) == 0 {
		return parsers.ParseContext{
			BootKeyStatus: string(sam.BootKeyNoSystemHive),
			BootKeyReason: "No SYSTEM hive was found in this evidence collection. The NT hashes in the SAM " +
				"are encrypted under the machine boot key, which is stored in the SYSTEM hive. Collect " +
				`Windows\System32\config\SYSTEM from the same machine and import it to decode them.`,
		}
	}

	var namedSystemReason string
	tried := 0
	for _, sf := range candidates {
		if tried >= maxSystemCandidates {
			break
		}
		path, ok := s.materializeForRead(caseID, collectionID, collection, sf)
		if !ok {
			continue
		}
		h, oerr := regf.Open(path, regf.DefaultLimits())
		if oerr != nil {
			// Not a readable hive. For a file actually named SYSTEM that
			// is worth reporting: it is the file the analyst believes
			// they collected.
			if isNamedSystem(sf) && namedSystemReason == "" {
				namedSystemReason = fmt.Sprintf("The SYSTEM hive in this collection could not be read as a "+
					"registry hive (%v). It may be truncated or corrupt.", oerr)
			}
			continue
		}
		tried++
		res := sam.BootKey(h)
		h.Close()

		if res.OK() {
			// The catalog's SHA-256 is only written when the import
			// extracts a file, which for an AD1 has not happened yet at
			// this point. Hashing the bytes we just read keeps the
			// cryptographic dependency identified by hash rather than by
			// path alone -- provenance for a decoded hash has to name
			// the SECOND file exactly, not approximately.
			sha := sf.SHA256
			if sha == "" {
				sha = sha256OfFile(path)
			}
			return parsers.ParseContext{
				BootKey:           res.Key,
				BootKeySource:     sf.Path,
				BootKeySHA256:     sha,
				BootKeyStatus:     string(sam.BootKeyDerived),
				BootKeyControlSet: res.ControlSet,
			}
		}
		if isNamedSystem(sf) && namedSystemReason == "" {
			namedSystemReason = res.Reason
		}
	}

	if namedSystemReason != "" {
		// A SYSTEM hive is present and will not do. Distinct from
		// "absent", because the remedy is different.
		return parsers.ParseContext{
			BootKeyStatus: string(sam.BootKeyUnusable),
			BootKeyReason: namedSystemReason,
		}
	}
	return parsers.ParseContext{
		BootKeyStatus: string(sam.BootKeyNoSystemHive),
		BootKeyReason: "No file in this evidence collection could supply a machine boot key. The NT hashes " +
			"in the SAM are encrypted under it, and it is stored in the SYSTEM hive. Collect " +
			`Windows\System32\config\SYSTEM from the same machine and import it to decode them.`,
	}
}

// batchContainsSAM reports whether any file about to be parsed could be
// a SAM hive. Deliberately cheap and deliberately over-inclusive: a
// false positive costs one wasted hive open, a false negative costs the
// analyst their hashes.
func batchContainsSAM(batch []model.SourceFile) bool {
	for _, sf := range batch {
		if sf.ArtifactType != model.ArtifactRegistryHive {
			continue
		}
		// Any hive might be the SAM -- a renamed one included -- but the
		// common case is worth short-circuiting.
		if strings.EqualFold(filepath.Base(sf.Path), "SAM") {
			return true
		}
	}
	// A hive that is not obviously named still might be a SAM. Rather
	// than open every hive here, defer: the presence of ANY hive in the
	// batch is enough to make preparing a key worthwhile, because the
	// preparation itself is bounded and happens once.
	for _, sf := range batch {
		if sf.ArtifactType == model.ArtifactRegistryHive {
			return true
		}
	}
	return false
}

// systemHiveCandidates lists the collection's registry hives, ordered so
// the likeliest SYSTEM hive is tried first.
//
// The ORDER uses names; the DECISION never does. Every candidate has to
// prove itself by yielding a boot key, so a renamed SYSTEM hive is still
// found and a file merely called SYSTEM is not trusted.
func (s *Service) systemHiveCandidates(caseID, collectionID string) ([]model.SourceFile, error) {
	files, err := s.store.ListSourceFilesByCollection(collectionID)
	if err != nil {
		return nil, err
	}
	var named, other []model.SourceFile
	for _, sf := range files {
		if sf.DeletedAt != nil || sf.CaseID != caseID || sf.ArtifactType != model.ArtifactRegistryHive {
			continue
		}
		base := strings.ToLower(filepath.Base(sf.Path))
		switch {
		case base == "system":
			named = append(named, sf)
		case base == "sam", base == "security", base == "software", base == "default",
			base == "components", base == "ntuser.dat", base == "usrclass.dat":
			// Known to be a different hive. Skipped from the fallback
			// sweep so a large collection does not spend its budget on
			// hives that cannot possibly carry a SysKey.
		default:
			other = append(other, sf)
		}
	}
	return append(named, other...), nil
}

func isNamedSystem(sf model.SourceFile) bool {
	return strings.EqualFold(filepath.Base(sf.Path), "SYSTEM")
}

// materializeForRead returns a readable on-disk path for one catalogued
// file, extracting it from an AD1 image if it is not there yet.
//
// It never modifies the source image, and it writes only into the
// collection's own evidence directory -- the same place the import
// writes every other extracted entry. A file already present is used as
// it is.
func (s *Service) materializeForRead(caseID, collectionID string, collection model.Collection, sf model.SourceFile) (string, bool) {
	dir := collection.EvidenceDirectory
	if dir == "" {
		dir = s.files.EvidenceDir(caseID, collectionID)
	}
	path := filepath.Join(dir, filepath.FromSlash(sf.Path))
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		return path, true
	}
	if collection.SourceType != model.SourceTypeAD1 {
		// Not an AD1, and not on disk: there is nothing to materialize.
		return "", false
	}
	if err := s.extractAD1Entry(caseID, collectionID, sf); err != nil {
		return "", false
	}
	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		return "", false
	}
	return path, true
}

// sha256OfFile hashes a file, returning "" if it cannot be read. Used
// only to identify the SYSTEM hive a boot key came from; a missing hash
// is reported as absent rather than guessed at.
func sha256OfFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
