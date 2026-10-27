package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"tracefall/internal/ext4"
	"tracefall/internal/fat"
	"tracefall/internal/fsvol"
	"tracefall/internal/image"
	"tracefall/internal/ingest"
	"tracefall/internal/model"
	"tracefall/internal/ntfsvol"
	"tracefall/internal/parsers"
	"tracefall/internal/partition"
	"tracefall/internal/regf"
	"tracefall/internal/report"
)

// Disk images (roadmap item 3).
//
//	container      internal/image      raw/dd (split sets too), E01/EWF, VHD, VHDX, VMDK
//	partitions     internal/partition  MBR + extended, GPT (backup fallback)
//	file system    internal/ntfsvol    NTFS, read directly from bytes
//	  -> catalog   artifacts that existing parsers claim
//	  -> import    selected artifacts are read out of the image into the
//	               collection's evidence directory
//	  -> ingest.ParseFile, detect, correlate: unmodified
//
// This mirrors the AD1 path on purpose: discovery is cheap and writes
// nothing but a catalog, extraction happens per selected file at import,
// and the parsers cannot tell the evidence came from an image.
//
// # What is cataloged
//
// Only files a registered parser claims by path (and the $UsnJrnl:$J
// stream). Cataloging every file of a 500 GB disk would write a million
// rows nobody can act on; the per-volume statistics in the image report
// say how many files were not cataloged, so nothing is hidden. Deleted
// MFT entries are counted but not cataloged.
//
// # Path naming
//
// A file's catalog path is "volN/<path inside the volume>", N being the
// partition's number in its table. The prefix keeps volumes apart and
// stays out of the way of the parsers' path rules (they key on names such
// as "$MFT", "$Extend/$UsnJrnl" and "Windows/Prefetch").

// ErrInvalidDiskImage means the image cannot be read as a disk image.
var ErrInvalidDiskImage = errors.New("the disk image is invalid or cannot be read")

const usnStream = "$J"

// maxCompanionLogBytes bounds one transaction log copied out of an image. It is
// the ceiling the replay reader itself applies, so a log refused here is one the
// reader would have refused; a variable so a test can lower it.
var maxCompanionLogBytes int64 = regf.MaxLogFileBytes

type diskPartitionReport struct {
	Index       int    `json:"index"`
	TypeID      string `json:"type_id"`
	TypeName    string `json:"type_name"`
	Name        string `json:"name,omitempty"`
	StartLBA    uint64 `json:"start_lba"`
	SectorCount uint64 `json:"sector_count"`
	SizeBytes   int64  `json:"size_bytes"`
	FS          string `json:"fs"`
}

type diskVolumeReport struct {
	Prefix         string `json:"prefix"`
	Partition      int    `json:"partition"`
	Label          string `json:"label,omitempty"`
	Version        string `json:"ntfs_version,omitempty"`
	Serial         string `json:"serial"`
	ClusterSize    int    `json:"cluster_size"`
	MFTRecords     int64  `json:"mft_records"`
	FilesInUse     int    `json:"files_in_use"`
	Deleted        int    `json:"deleted_entries"`
	CorruptRecords int    `json:"corrupt_records"`
	Cataloged      int    `json:"cataloged"`
	NotCataloged   int    `json:"not_cataloged"`
}

// diskImageReport is written next to the collection at discovery.
type diskImageReport struct {
	Format         string                `json:"format"`
	Segments       int                   `json:"segments"`
	SizeBytes      int64                 `json:"size_bytes"`
	SectorSize     int                   `json:"sector_size"`
	Acquisition    map[string]string     `json:"acquisition,omitempty"`
	StoredMD5      string                `json:"stored_md5,omitempty"`
	StoredSHA1     string                `json:"stored_sha1,omitempty"`
	ComputedMD5    string                `json:"computed_md5"`
	ComputedSHA1   string                `json:"computed_sha1"`
	ComputedSHA256 string                `json:"computed_sha256"`
	MD5Match       *bool                 `json:"md5_match,omitempty"`
	SHA1Match      *bool                 `json:"sha1_match,omitempty"`
	Partitioning   string                `json:"partitioning"`
	DiskGUID       string                `json:"disk_guid,omitempty"`
	Partitions     []diskPartitionReport `json:"partitions"`
	Volumes        []diskVolumeReport    `json:"volumes"`
	Notes          []string              `json:"notes,omitempty"`
}

// verificationSummary is one sentence for the audit trail.
func (r diskImageReport) verificationSummary() string {
	switch {
	case r.MD5Match != nil && r.SHA1Match != nil && *r.MD5Match && *r.SHA1Match:
		return "acquisition MD5 and SHA-1 verified"
	case r.MD5Match != nil && *r.MD5Match && r.SHA1Match == nil:
		return "acquisition MD5 verified"
	case (r.MD5Match != nil && !*r.MD5Match) || (r.SHA1Match != nil && !*r.SHA1Match):
		return "acquisition hash MISMATCH: the image differs from what was acquired"
	}
	return "no acquisition hash stored in the container, so none could be verified"
}

// sniffDiskImage reports whether a regular file is a disk image Tracefall
// reads: an EWF container, or a raw disk/volume with a partition table or
// an NTFS boot sector. It looks at the contents only.
func sniffDiskImage(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() || st.Size() < 512 {
		return false
	}
	var head [8]byte
	if _, err := f.ReadAt(head[:], 0); err != nil {
		return false
	}
	if string(head[:]) == "EVF\x09\x0d\x0a\xff\x00" {
		return true
	}
	if string(head[:4]) == "PK\x03\x04" || string(head[:4]) == "PK\x05\x06" {
		return false // an archive that happens to have 55 AA in its tail
	}
	// VHD, VHDX and VMDK have no partition table at byte 0 (the disk sits behind
	// the container's own structures), so the check below cannot see them. They
	// are claimed by their signatures, even when the reader will refuse one
	// (a differencing disk), so the refusal carries its reason.
	if image.IsVirtualDisk(path) {
		return true
	}
	tb, err := partition.Read(f, st.Size(), 512)
	return err == nil && len(tb.Partitions) > 0
}

func (s *Service) discoverDiskImageFromPath(caseID, path string) (DiscoverResult, error) {
	segs, err := image.FindSegments(path)
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("%w: locating segments: %v", ErrInvalidDiskImage, err)
	}
	hash, integrity, err := hashAD1Segments(segs) // ordered concatenation of the container files
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("fingerprinting disk image: %w", err)
	}
	if err := s.checkDuplicateEvidence(caseID, hash); err != nil {
		return DiscoverResult{}, err
	}
	collectionID := uuid.NewString()
	collection := model.Collection{
		ID: collectionID, CaseID: caseID, CreatedAt: time.Now().UTC(),
		SourceType: model.SourceTypeDiskImage, ArchiveHash: hash, IntegritySHA512: integrity,
		OriginalFilename:  path, // reopened at import time; never modified, never copied
		EvidenceDirectory: s.files.EvidenceDir(caseID, collectionID),
		IngestionStatus:   model.CollectionStatusPending,
	}
	if err := s.files.EnsureCollectionDir(caseID, collectionID); err != nil {
		return DiscoverResult{}, fmt.Errorf("preparing collection storage: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = s.files.RemoveCollectionDir(caseID, collectionID)
		}
	}()
	res, rep, err := s.catalogDiskImage(caseID, collection, segs)
	if err != nil {
		return DiscoverResult{}, err
	}
	ok = true
	s.audit(caseID, model.AuditEvidenceDiscovered, model.TargetCollection, collectionID,
		fmt.Sprintf("disk image discovered from local path %q: %s, %d file(s) cataloged, %d supported; %s",
			path, strings.ToUpper(rep.Format), res.DiscoveredCount, res.SupportedCount, rep.verificationSummary()))
	return res, nil
}

func (s *Service) discoverDiskImageUpload(caseID, stagingPath string, stagingClaimed *bool, uploadSize int64, archiveHash, integrity, filename string) (DiscoverResult, error) {
	collectionID := uuid.NewString()
	if filename == "" {
		filename = "Disk image"
	}
	collection := model.Collection{
		ID: collectionID, CaseID: caseID, CreatedAt: time.Now().UTC(),
		SourceType: model.SourceTypeDiskImage, ArchiveHash: archiveHash, IntegritySHA512: integrity,
		OriginalFilename:  filename, // display only; the stored copy is found by id, never by this name
		EvidenceDirectory: s.files.EvidenceDir(caseID, collectionID),
		IngestionStatus:   model.CollectionStatusPending,
	}
	if err := s.files.EnsureCollectionDir(caseID, collectionID); err != nil {
		return DiscoverResult{}, fmt.Errorf("preparing collection storage: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = s.files.RemoveCollectionDir(caseID, collectionID)
		}
	}()
	dest := s.files.DiskImagePath(caseID, collectionID)
	if err := os.Rename(stagingPath, dest); err != nil {
		return DiscoverResult{}, fmt.Errorf("finalizing uploaded disk image: %w", err)
	}
	*stagingClaimed = true
	res, rep, err := s.catalogDiskImage(caseID, collection, []string{dest})
	if err != nil {
		return DiscoverResult{}, err
	}
	res.UploadSizeBytes = uploadSize
	ok = true
	s.audit(caseID, model.AuditEvidenceDiscovered, model.TargetCollection, collectionID,
		fmt.Sprintf("disk image discovered from upload: %s, %d file(s) cataloged, %d supported; %s",
			strings.ToUpper(rep.Format), res.DiscoveredCount, res.SupportedCount, rep.verificationSummary()))
	return res, nil
}

// diskImageSegmentPaths re-resolves a collection's container file(s).
func (s *Service) diskImageSegmentPaths(caseID, collectionID string) ([]string, error) {
	c, err := s.store.GetCollection(collectionID)
	if err != nil || c.CaseID != caseID {
		return nil, ErrCollectionNotFound
	}
	if up := s.files.DiskImagePath(caseID, collectionID); fileExists(up) {
		return []string{up}, nil
	}
	return image.FindSegments(c.OriginalFilename)
}

func volumePrefix(partitionIndex int) string { return fmt.Sprintf("vol%d", partitionIndex) }

// openDiskImageVolumes opens the image and every NTFS volume in it.
type openedVolume struct {
	part partition.Partition
	vol  fsvol.Volume
}

func openDiskImage(paths []string) (image.Image, partition.Table, []openedVolume, []string, error) {
	img, err := image.Open(paths...)
	if err != nil {
		return nil, partition.Table{}, nil, nil, fmt.Errorf("%w: %v", ErrInvalidDiskImage, err)
	}
	tb, err := partition.Read(img, img.Size(), img.Info().SectorSize)
	if err != nil {
		img.Close()
		return nil, partition.Table{}, nil, nil, fmt.Errorf("%w: %v", ErrInvalidDiskImage, err)
	}
	var vols []openedVolume
	var notes []string
	for _, w := range tb.Warnings {
		notes = append(notes, "partition table: "+w)
	}
	for _, p := range tb.Partitions {
		switch p.FS {
		case "ntfs":
			v, err := ntfsvol.Open(p.Reader(img), p.SizeBytes)
			if err != nil {
				notes = append(notes, fmt.Sprintf("partition %d: the NTFS volume could not be opened (%v)", p.Index, err))
				continue
			}
			for _, warning := range v.Info().Warnings {
				notes = append(notes, fmt.Sprintf("partition %d (NTFS): %s", p.Index, warning))
			}
			vols = append(vols, openedVolume{part: p, vol: v.AsVolume()})
		case "fat", "fat32", "exfat":
			v, err := fat.Open(p.Reader(img), p.SizeBytes)
			if err != nil {
				notes = append(notes, fmt.Sprintf("partition %d: the %s volume could not be opened (%v)", p.Index, p.FS, err))
				continue
			}
			vols = append(vols, openedVolume{part: p, vol: v})
		case "ext":
			v, err := ext4.Open(p.Reader(img), p.SizeBytes)
			if err != nil {
				notes = append(notes, fmt.Sprintf("partition %d: the ext volume could not be opened (%v)", p.Index, err))
				continue
			}
			for _, n := range v.Notes {
				notes = append(notes, fmt.Sprintf("partition %d (%s): %s", p.Index, v.Version, n))
			}
			vols = append(vols, openedVolume{part: p, vol: v})
		case "bitlocker":
			notes = append(notes, fmt.Sprintf("partition %d is BitLocker-encrypted and cannot be read without its key: its contents are NOT part of this analysis", p.Index))
		default:
			notes = append(notes, fmt.Sprintf("partition %d (%s): file system %q is not read by Tracefall, so its contents are NOT part of this analysis", p.Index, p.TypeName, p.FS))
		}
	}
	return img, tb, vols, notes, nil
}

// diskEntry is one in-use file of a volume as the catalog sees it.
type diskEntry struct {
	Rel       string // path inside the volume, forward-slash, no leading slash
	Stream    string // named stream to read; "" for the unnamed data
	Size      int64
	Sniff     []byte // first bytes, when the content was read to decide
	Supported bool   // a parser claims the file, by name or by content
}

// classifyDiskFile says how the catalog treats a file in a volume. ok is
// false only for entries that are never cataloged: directories, deleted or
// orphaned records, and $MFTMirr. Every other in-use file is cataloged,
// supported when a parser claims it and unsupported otherwise, so nothing
// is dropped without the analyst seeing it.
//
// A name is not the only way a file is identified. Amcache.hve is a REGF
// hive under an ordinary name, and a shortcut keeps its own name wherever
// it is moved, so a file the name does not decide is sniffed: its first
// bytes are offered to the same content rules folder discovery uses
// (ingest.Discover). The bytes are kept on the entry so the caller does not
// read them a second time.
func classifyDiskFile(vol fsvol.Volume, f fsvol.File, registry []parsers.ArtifactParser) (diskEntry, bool) {
	if f.IsDir || !f.InUse || f.Orphan {
		return diskEntry{}, false
	}
	rel := strings.TrimPrefix(f.Path, "/")
	// $UsnJrnl keeps its journal in the named stream $J.
	if strings.EqualFold(rel, "$Extend/$UsnJrnl") {
		for _, st := range f.Streams {
			if st.Name == usnStream && st.Size > 0 {
				return diskEntry{Rel: rel + "/" + usnStream, Stream: usnStream, Size: st.Size, Supported: true}, true
			}
		}
	}
	// $MFTMirr repeats the first records of $MFT, so cataloging it would
	// parse the same records twice and double-count them on the timeline.
	if mirrorOfMFT(rel) {
		return diskEntry{}, false
	}
	if ingest.MatchParser(rel, nil, registry) != nil {
		return diskEntry{Rel: rel, Size: f.Size, Supported: true}, true
	}
	e := diskEntry{Rel: rel, Size: f.Size}
	// Name did not decide it. Only a non-empty unnamed stream can hold a
	// hive or a log; directories and empty files cannot. Files in the
	// skipped folders are not sniffed (see sniffSkipped).
	if vol == nil || f.Size == 0 || sniffSkipped(rel) {
		return e, true
	}
	dr, err := vol.OpenStream(f.Record, "")
	if err != nil {
		return e, true
	}
	buf := make([]byte, parsers.SniffLength)
	n, _ := dr.ReadAt(buf, 0)
	if n == 0 {
		return e, true
	}
	e.Sniff = buf[:n]
	e.Supported = ingest.MatchParser(rel, e.Sniff, registry) != nil
	return e, true
}

// sniffSkipPrefixes are folders whose files are not identified by content
// when their name does not decide. They hold installed applications and
// wallpapers: most of the images found in a default Windows install are
// added, none of which is evidence, and they would bury the artifacts the
// sniff exists to find. A file there whose name is a known artifact is still
// cataloged; only the content sniff is skipped.
var sniffSkipPrefixes = []string{"Program Files/", "Program Files (x86)/", "Windows/Web/"}

// sniffSkipped reports whether rel lies in a folder whose files are not
// sniffed. Windows paths are case-insensitive, so the match is too.
func sniffSkipped(rel string) bool {
	low := strings.ToLower(rel)
	for _, p := range sniffSkipPrefixes {
		if strings.HasPrefix(low, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// mirrorOfMFT reports whether rel is the $MFTMirr copy of the first $MFT
// records.
func mirrorOfMFT(rel string) bool {
	return strings.EqualFold(rel, "$MFTMirr")
}

// catalogDiskImage opens the image, verifies it against the hashes its
// container recorded, reads its partitions, and catalogs the artifacts
// inside every NTFS volume. Nothing is written to the database until the
// catalog is complete.
func (s *Service) catalogDiskImage(caseID string, collection model.Collection, segs []string) (DiscoverResult, diskImageReport, error) {
	img, tb, vols, notes, err := openDiskImage(segs)
	if err != nil {
		return DiscoverResult{}, diskImageReport{}, err
	}
	defer img.Close()

	ver, err := image.Verify(img, nil)
	if err != nil {
		return DiscoverResult{}, diskImageReport{}, fmt.Errorf("%w: the image cannot be read to the end: %v", ErrInvalidDiskImage, err)
	}
	info := img.Info()
	rep := diskImageReport{
		Format: string(info.Format), Segments: info.Segments, SizeBytes: info.Size, SectorSize: info.SectorSize,
		Acquisition: info.Meta, StoredMD5: info.StoredMD5, StoredSHA1: info.StoredSHA1,
		ComputedMD5: ver.MD5, ComputedSHA1: ver.SHA1, ComputedSHA256: ver.SHA256, MD5Match: ver.MD5Match, SHA1Match: ver.SHA1Match,
		Partitioning: string(tb.Scheme), DiskGUID: tb.DiskGUID, Notes: notes,
	}
	if (ver.MD5Match != nil && !*ver.MD5Match) || (ver.SHA1Match != nil && !*ver.SHA1Match) {
		rep.Notes = append(rep.Notes, "the decoded image does NOT match the hash recorded when it was acquired: it was altered or damaged after acquisition")
	}
	for _, p := range tb.Partitions {
		rep.Partitions = append(rep.Partitions, diskPartitionReport{
			Index: p.Index, TypeID: p.TypeID, TypeName: p.TypeName, Name: p.Name, StartLBA: p.StartLBA,
			SectorCount: p.SectorCount, SizeBytes: p.SizeBytes, FS: p.FS,
		})
	}

	registry := ingest.Registry()
	now := time.Now().UTC()
	sourceFiles := make([]model.SourceFile, 0, 64)
	var supported, unsupported int
	// hiveByLower and logRows let the catalog label a transaction log as the
	// companion of the hive beside it once every volume has been walked.
	hiveByLower := map[string]string{}
	var logRows []int
	logLike := 0 // files named like a transaction log, as the extractor's index counts them
	for _, ov := range vols {
		prefix := volumePrefix(ov.part.Index)
		vr := diskVolumeReport{
			Prefix: prefix, Partition: ov.part.Index, Label: ov.vol.Info().Label, Version: ov.vol.Info().Version,
			Serial: fmt.Sprintf("%016X", ov.vol.Info().Serial), ClusterSize: ov.vol.Info().ClusterSize, MFTRecords: ov.vol.Info().Records,
		}
		seen := map[string]bool{}
		stats, err := ov.vol.Walk(func(f fsvol.File) error {
			if f.InUse && !f.IsDir {
				vr.FilesInUse++
			}
			e, ok := classifyDiskFile(ov.vol, f, registry)
			if !ok {
				return nil
			}
			full := prefix + "/" + e.Rel
			if seen[full] {
				return nil
			}
			seen[full] = true
			// Confirm by content, as the other catalogs do, so a text file that
			// merely carries a hive's name is not claimed. A file the classifier
			// already sniffed keeps those bytes; a name-claimed file is read
			// here; a skipped folder is not read at all.
			header := e.Sniff
			if header == nil && e.Size > 0 && !sniffSkipped(e.Rel) {
				if dr, err := ov.vol.OpenStream(f.Record, e.Stream); err == nil {
					buf := make([]byte, parsers.SniffLength)
					n, _ := dr.ReadAt(buf, 0)
					header = buf[:n]
				}
			}
			var artifactType, parserName string
			supportedFile := false
			if p := ingest.MatchParser(e.Rel, header, registry); p != nil {
				artifactType, parserName, supportedFile = p.ArtifactType(), p.Name(), true
			} else {
				artifactType = ingest.RecognizeUnparsed(e.Rel, header)
			}
			name := f.Name
			if e.Stream != "" {
				name = e.Stream
			}
			sf := model.SourceFile{
				ID: uuid.NewString(), CaseID: caseID, CollectionID: collection.ID,
				OriginalFilename: name, Path: full, ArtifactType: artifactType, Parser: parserName,
				Supported: supportedFile, SizeBytes: e.Size, DiscoveredAt: now,
			}
			if supportedFile {
				sf.ImportStatus = model.SourceFileDiscovered
				supported++
			} else {
				sf.ImportStatus = model.SourceFileUnsupported
				unsupported++
			}
			if supportedFile && artifactType == model.ArtifactRegistryHive {
				hiveByLower[strings.ToLower(full)] = full
			} else if !supportedFile && companionLogName(f.Name) {
				logRows = append(logRows, len(sourceFiles))
				if e.Stream == "" {
					logLike++
				}
			}
			sourceFiles = append(sourceFiles, sf)
			vr.Cataloged++
			return nil
		})
		if err != nil {
			return DiscoverResult{}, diskImageReport{}, fmt.Errorf("%w: reading the file system of partition %d: %v", ErrInvalidDiskImage, ov.part.Index, err)
		}
		vr.Deleted, vr.CorruptRecords = stats.Deleted, stats.CorruptCount
		vr.NotCataloged = vr.FilesInUse - vr.Cataloged
		if stats.CorruptCount > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("partition %d: %d MFT record(s) are damaged and could not be read; files described only by them are missing", ov.part.Index, stats.CorruptCount))
		}
		rep.Volumes = append(rep.Volumes, vr)
	}

	if logLike > maxCompanionIndex {
		rep.Notes = append(rep.Notes, fmt.Sprintf("the image holds %d files named like registry transaction logs, more than the %d the log index can hold: past that limit a log may go unseen, so a hive's replay may be incomplete (each hive's replay status says so)", logLike, maxCompanionIndex))
	}
	for _, i := range logRows {
		if hive, ok := companionHiveOf(sourceFiles[i].Path, hiveByLower); ok {
			sourceFiles[i].ParseCoverage = &model.ParseCoverage{CompanionOf: hive}
		}
	}

	if len(sourceFiles) == 0 {
		return DiscoverResult{}, diskImageReport{}, fmt.Errorf("%w: the image holds no file Tracefall has a parser for (%s)", ErrNoEvidenceFound, strings.Join(rep.Notes, "; "))
	}

	raw, _ := json.MarshalIndent(rep, "", " ")
	if err := os.WriteFile(s.files.DiskImageReportPath(caseID, collection.ID), raw, 0o644); err != nil {
		return DiscoverResult{}, diskImageReport{}, fmt.Errorf("recording the image report: %w", err)
	}

	collection.IngestionStatus = model.CollectionStatusPending
	collection.FileCount = len(sourceFiles)
	collection.SupportedFileCount = supported
	collection.UnsupportedFileCount = unsupported
	full, err := s.commitDiscovery(collection, sourceFiles)
	if err != nil {
		return DiscoverResult{}, diskImageReport{}, err
	}
	triaged := triageAll(sourceFiles)
	return DiscoverResult{
		Collection: full, SourceFiles: firstEvidencePage(triaged), Coverage: computeCoverage(triaged),
		SourceFilesTotal: len(triaged), SourceFilesPageSize: defaultEvidencePageSize,
		DiscoveredCount: len(sourceFiles), SupportedCount: supported, UnsupportedCount: unsupported,
	}, rep, nil
}

// loadDiskImageReport reads a collection's image report, if it has one.
func (s *Service) loadDiskImageReport(caseID, collectionID string) (diskImageReport, bool) {
	b, err := os.ReadFile(s.files.DiskImageReportPath(caseID, collectionID))
	if err != nil {
		return diskImageReport{}, false
	}
	var r diskImageReport
	if json.Unmarshal(b, &r) != nil {
		return diskImageReport{}, false
	}
	return r, true
}

// ---- extraction

type diskLocator struct {
	vol    fsvol.Volume
	record uint64
	stream string
}

// diskExtractor reads selected artifacts out of an image. It is opened
// once per import and indexes only the cataloged candidates (a few
// hundred entries, not the whole disk).
type diskExtractor struct {
	svc          *Service
	caseID       string
	collectionID string
	img          image.Image
	byPath       map[string]diskLocator
	// logs indexes every file named like a registry transaction log
	// (*.LOG1, *.LOG2, *.LOG), by lower-cased cataloged path. It is consulted
	// only for the exact name HIVE + suffix in the hive's own directory and
	// volume, so a log of another hive, directory or volume is never reached.
	logs          map[string][]companionLog
	logsTruncated bool
	// logCount is how many entries logs holds; companionIndexLimit is the cap
	// that applied (maxCompanionIndex when the index was built).
	logCount            int
	companionIndexLimit int
	// companionBytes is what the companions extracted so far add up to.
	companionBytes int64
	// companions is what became of each extracted hive's logs, by hive path.
	companions map[string][]model.HiveCompanion
	rows       map[string]model.SourceFile
}

// companionLog is one candidate transaction log found while indexing the image.
type companionLog struct {
	path string // cataloged path, volN/...
	loc  diskLocator
	size int64
}

// maxCompanionIndex bounds the index of log-like names (a variable so a test can
// lower it). A volume can hold hundreds of thousands of *.log files; past this
// the index stops growing and every hive's replay status says its logs may be
// missing from it, as does the discovery report.
var maxCompanionIndex = 200_000

func (s *Service) newDiskExtractor(caseID, collectionID string) (*diskExtractor, error) {
	segs, err := s.diskImageSegmentPaths(caseID, collectionID)
	if err != nil {
		return nil, err
	}
	img, _, vols, _, err := openDiskImage(segs)
	if err != nil {
		return nil, err
	}
	x := &diskExtractor{svc: s, caseID: caseID, collectionID: collectionID, img: img, byPath: map[string]diskLocator{},
		logs: map[string][]companionLog{}, companions: map[string][]model.HiveCompanion{}, companionIndexLimit: maxCompanionIndex}
	registry := ingest.Registry()
	for _, ov := range vols {
		prefix := volumePrefix(ov.part.Index)
		ov := ov
		if _, err := ov.vol.Walk(func(f fsvol.File) error {
			e, ok := classifyDiskFile(ov.vol, f, registry)
			if !ok {
				return nil
			}
			key := prefix + "/" + e.Rel
			if e.Supported {
				if _, dup := x.byPath[key]; !dup {
					x.byPath[key] = diskLocator{vol: ov.vol, record: f.Record, stream: e.Stream}
				}
			} else if e.Stream == "" && companionLogName(f.Name) {
				if x.logCount >= x.companionIndexLimit {
					x.logsTruncated = true
				} else {
					x.logCount++
					lk := strings.ToLower(key)
					x.logs[lk] = append(x.logs[lk], companionLog{path: key, loc: diskLocator{vol: ov.vol, record: f.Record}, size: e.Size})
				}
			}
			return nil
		}); err != nil {
			img.Close()
			return nil, fmt.Errorf("%w: %v", ErrInvalidDiskImage, err)
		}
	}
	return x, nil
}

func (x *diskExtractor) Close() error {
	if x == nil || x.img == nil {
		return nil
	}
	return x.img.Close()
}

// extract writes one cataloged file's bytes under the collection's
// evidence directory and records Tracefall's own SHA-256 of them. When the
// file is a registry hive, the transaction logs beside it are extracted too
// (extractCompanions), so every reader of the extracted hive replays them.
func (x *diskExtractor) extract(sf model.SourceFile) error {
	loc, ok := x.byPath[sf.Path]
	if !ok {
		return fmt.Errorf("%w: %q is no longer found in the disk image", ntfsvol.ErrNotFound, sf.Path)
	}
	sum, err := x.writeFile(sf.Path, loc)
	if err != nil {
		return err
	}
	if err := x.svc.store.SetSourceFileSHA256(sf.ID, sum); err != nil {
		return fmt.Errorf("recording extracted file hash: %w", err)
	}
	if sf.ArtifactType == model.ArtifactRegistryHive {
		x.extractCompanions(sf)
	}
	return nil
}

// writeFile copies one file's logical stream to its place under the
// collection's evidence directory and returns the SHA-256 of what it wrote.
func (x *diskExtractor) writeFile(relPath string, loc diskLocator) (string, error) {
	dr, err := loc.vol.OpenStream(loc.record, loc.stream)
	if err != nil {
		return "", err
	}
	root, err := filepath.Abs(x.svc.files.EvidenceDir(x.caseID, x.collectionID))
	if err != nil {
		return "", fmt.Errorf("resolving evidence directory: %w", err)
	}
	dest := filepath.Join(root, filepath.FromSlash(relPath))
	if rel, relErr := filepath.Rel(root, dest); relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: entry path %q would resolve outside the extraction directory", ntfsvol.ErrCorrupt, relPath)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", fmt.Errorf("creating destination directory: %w", err)
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("creating extracted file: %w", err)
	}
	defer out.Close()

	// The hash covers the whole LOGICAL stream, holes included, which is
	// what the file contains. Only allocated ranges are written, so a
	// sparse $UsnJrnl:$J does not become gigabytes of zeros on disk.
	h := sha256.New()
	buf := make([]byte, 1<<20)
	ranges := dr.AllocatedRanges()
	var pos int64
	zeros := make([]byte, 1<<20)
	hashZeros := func(n int64) {
		for n > 0 {
			k := int64(len(zeros))
			if n < k {
				k = n
			}
			h.Write(zeros[:k])
			n -= k
		}
	}
	for _, r := range ranges {
		if r[0] > pos {
			hashZeros(r[0] - pos)
		}
		for off := r[0]; off < r[1]; {
			n := int64(len(buf))
			if r[1]-off < n {
				n = r[1] - off
			}
			got, rerr := dr.ReadAt(buf[:n], off)
			if int64(got) < n && rerr != nil && !errors.Is(rerr, io.EOF) {
				return "", rerr
			}
			if int64(got) == 0 {
				return "", fmt.Errorf("%w: short read at offset %d of %q", ntfsvol.ErrCorrupt, off, relPath)
			}
			h.Write(buf[:got])
			if _, werr := out.WriteAt(buf[:got], off); werr != nil {
				return "", werr
			}
			off += int64(got)
		}
		pos = r[1]
	}
	if dr.Size() > pos {
		hashZeros(dr.Size() - pos)
	}
	if err := out.Truncate(dr.Size()); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// extractDiskImageEntry is the one-file convenience used where a single
// artifact is needed outside an import.
func (s *Service) extractDiskImageEntry(caseID, collectionID string, sf model.SourceFile) error {
	x, err := s.newDiskExtractor(caseID, collectionID)
	if err != nil {
		return err
	}
	defer x.Close()
	return x.extract(sf)
}

// attachImageInfo adds each disk-image collection's container, verification
// and layout record to its evidence entry. The record is the one written at
// discovery; nothing is re-read from the image here.
func (s *Service) attachImageInfo(ev []report.Evidence, collections []model.Collection) {
	for i, col := range collections {
		if i >= len(ev) || col.SourceType != model.SourceTypeDiskImage {
			continue
		}
		r, ok := s.loadDiskImageReport(col.CaseID, col.ID)
		if !ok {
			ev[i].Image = &report.ImageInfo{Verification: "The image record for this collection is missing, so its acquisition details cannot be shown."}
			continue
		}
		info := &report.ImageInfo{
			Format: strings.ToUpper(r.Format), Segments: r.Segments, Size: humanBytes(r.SizeBytes),
			StoredMD5: r.StoredMD5, StoredSHA1: r.StoredSHA1, ComputedMD5: r.ComputedMD5, ComputedSHA1: r.ComputedSHA1,
			Verification: r.verificationSummary(), Partitioning: strings.ToUpper(r.Partitioning), Notes: r.Notes,
		}
		if r.DiskGUID != "" {
			info.Partitioning += " (disk GUID " + r.DiskGUID + ")"
		}
		for _, k := range []struct{ key, label string }{
			{"case_number", "Case number"}, {"evidence_number", "Evidence number"}, {"examiner", "Examiner"},
			{"description", "Description"}, {"notes", "Acquisition notes"}, {"acquisition_date", "Acquired"},
			{"software_version", "Acquisition software"}, {"operating_system", "Acquisition OS"},
		} {
			if v := r.Acquisition[k.key]; v != "" {
				info.Acquisition = append(info.Acquisition, report.KV{Key: k.label, Value: v})
			}
		}
		for _, p := range r.Partitions {
			info.Partitions = append(info.Partitions, report.ImagePartition{
				Index: p.Index, Type: p.TypeName, Name: p.Name, FS: p.FS, Start: p.StartLBA, Size: humanBytes(p.SizeBytes),
			})
		}
		for _, v := range r.Volumes {
			info.Volumes = append(info.Volumes, report.ImageVolume{
				Prefix: v.Prefix, Label: v.Label, FilesInUse: v.FilesInUse, Deleted: v.Deleted,
				Cataloged: v.Cataloged, NotCataloged: v.NotCataloged, Corrupt: v.CorruptRecords,
			})
		}
		ev[i].Image = info
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d bytes", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB (%d bytes)", float64(n)/float64(div), "KMGTPE"[exp], n)
}
