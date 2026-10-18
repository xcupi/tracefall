package api

import (
	"context"
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

	"tracefall/internal/memory"
	"tracefall/internal/model"
	"tracefall/internal/parsers/volatility"
	"tracefall/internal/report"
)

// Memory images (roadmap item 4).
//
//	image file  -> sniff (magic or memory-style extension)
//	discovery   -> Volatility 3 identifies the OS (windows.info), in a sandbox
//	catalog     -> ONE entry, memory/volatility-analysis.json
//	import      -> the plugin set runs, output is saved as that file, and the
//	               volatility parser turns it into events
//	detect, correlate, report: unmodified
//
// The analysis is one file on purpose (see internal/parsers/volatility): the
// events join across plugins, and a join across separately imported files
// would depend on extraction order.
//
// The SHA-256 recorded on the catalog entry is of the extracted analysis
// JSON, which is Volatility's output, not the image. The image's own hash is
// the collection's ArchiveHash.

// ErrMemoryNotConfigured means no Volatility runner is set up.
var ErrMemoryNotConfigured = errors.New("memory analysis is not configured: set TRACEFALL_VOLATILITY to the path of the Volatility 3 `vol` executable (see docs/memory-analysis.md)")

const memoryAnalysisPath = "memory/" + "volatility-analysis.json"

// SetMemoryRunner enables memory analysis. Call it before the service
// starts handling requests.
func (s *Service) SetMemoryRunner(r *memory.Runner) { s.mem = r }

type memoryImageReport struct {
	Volatility   string            `json:"volatility_version"`
	Isolation    string            `json:"isolation"`
	ImageName    string            `json:"image_name"`
	ImageSize    int64             `json:"image_size"`
	Info         map[string]string `json:"info"`
	IdentifiedAt time.Time         `json:"identified_at"`
	Notes        []string          `json:"notes,omitempty"`
}

// sniffMemoryImage reports whether a regular file looks like a memory
// image Tracefall hands to Volatility. Known magics are decisive; for a raw
// dump, which has none, the file name is the only hint, so a wrong guess
// fails clearly at identification instead of being treated as evidence.
func sniffMemoryImage(path, name string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() || st.Size() == 0 {
		return false
	}
	var head [20]byte
	n, _ := f.ReadAt(head[:], 0)
	h := head[:n]
	has := func(p string) bool { return len(h) >= len(p) && string(h[:len(p)]) == p }
	switch {
	case has("PK\x03\x04"), has("PK\x05\x06"), has("EVF\x09"), has("EVF2"), has("MDMP"):
		return false // archive, EWF image, or a process minidump (not a full memory dump)
	case has("EMiL"), has("PAGEDU64"), has("PAGEDUMP"):
		return true
	case has("\x7fELF") && len(h) >= 18 && h[16] == 4: // ELF core file (winpmem)
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".vmem", ".mem", ".dmp", ".dump", ".lime", ".raw":
		return true
	}
	return false
}

func (s *Service) discoverMemoryImageFromPath(caseID, path string) (DiscoverResult, error) {
	if s.mem == nil {
		return DiscoverResult{}, ErrMemoryNotConfigured
	}
	hash, integrity, err := hashAD1Segments([]string{path})
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("fingerprinting memory image: %w", err)
	}
	if err := s.checkDuplicateEvidence(caseID, hash); err != nil {
		return DiscoverResult{}, err
	}
	collectionID := uuid.NewString()
	collection := model.Collection{
		ID: collectionID, CaseID: caseID, CreatedAt: time.Now().UTC(),
		SourceType: model.SourceTypeMemoryImage, ArchiveHash: hash, IntegritySHA512: integrity,
		OriginalFilename:  path,
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
	res, rep, err := s.catalogMemoryImage(caseID, collection, path)
	if err != nil {
		return DiscoverResult{}, err
	}
	ok = true
	s.audit(caseID, model.AuditEvidenceDiscovered, model.TargetCollection, collectionID,
		fmt.Sprintf("memory image discovered from local path %q: Volatility %s identified %s (isolation: %s)",
			path, rep.Volatility, rep.Info["NTBuildLab"], rep.Isolation))
	return res, nil
}

func (s *Service) discoverMemoryImageUpload(caseID, stagingPath string, stagingClaimed *bool, uploadSize int64, archiveHash, integrity, filename string) (DiscoverResult, error) {
	if s.mem == nil {
		return DiscoverResult{}, ErrMemoryNotConfigured
	}
	if filename == "" {
		filename = "Memory image"
	}
	collectionID := uuid.NewString()
	collection := model.Collection{
		ID: collectionID, CaseID: caseID, CreatedAt: time.Now().UTC(),
		SourceType: model.SourceTypeMemoryImage, ArchiveHash: archiveHash, IntegritySHA512: integrity,
		OriginalFilename:  filename,
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
	dest := s.files.MemoryImagePath(caseID, collectionID)
	if err := os.Rename(stagingPath, dest); err != nil {
		return DiscoverResult{}, fmt.Errorf("finalizing uploaded memory image: %w", err)
	}
	*stagingClaimed = true
	res, rep, err := s.catalogMemoryImage(caseID, collection, dest)
	if err != nil {
		return DiscoverResult{}, err
	}
	res.UploadSizeBytes = uploadSize
	ok = true
	s.audit(caseID, model.AuditEvidenceDiscovered, model.TargetCollection, collectionID,
		fmt.Sprintf("memory image discovered from upload: Volatility %s identified %s (isolation: %s)",
			rep.Volatility, rep.Info["NTBuildLab"], rep.Isolation))
	return res, nil
}

// catalogMemoryImage identifies the image and records the one catalog entry.
func (s *Service) catalogMemoryImage(caseID string, collection model.Collection, imagePath string) (DiscoverResult, memoryImageReport, error) {
	st, err := os.Stat(imagePath)
	if err != nil {
		return DiscoverResult{}, memoryImageReport{}, err
	}
	id, err := memory.Identify(context.Background(), s.mem, imagePath)
	if err != nil {
		// ErrSymbols and friends already say what is wrong; they are
		// returned as they are so the caller can classify them.
		return DiscoverResult{}, memoryImageReport{}, err
	}
	rep := memoryImageReport{
		Volatility: id.Volatility, Isolation: id.Isolation, ImageName: filepath.Base(collection.OriginalFilename),
		ImageSize: st.Size(), Info: id.Info, IdentifiedAt: time.Now().UTC(),
	}
	if id.Isolation == string(memory.IsolationNone) {
		rep.Notes = append(rep.Notes, "Volatility ran WITHOUT a sandbox: parsing this image was not contained")
	}
	if _, ok := id.Info["SystemTime"]; !ok {
		rep.Notes = append(rep.Notes, "the image carries no system time, so findings that have no time of their own cannot be placed on the timeline")
	}
	raw, _ := json.MarshalIndent(rep, "", " ")
	if err := os.WriteFile(s.files.MemoryReportPath(caseID, collection.ID), raw, 0o644); err != nil {
		return DiscoverResult{}, memoryImageReport{}, fmt.Errorf("recording the memory report: %w", err)
	}

	sf := model.SourceFile{
		ID: uuid.NewString(), CaseID: caseID, CollectionID: collection.ID,
		OriginalFilename: filepath.Base(memoryAnalysisPath), Path: memoryAnalysisPath,
		ArtifactType: model.ArtifactMemoryAnalysis, Parser: volatility.New().Name(), Supported: true,
		SizeBytes: st.Size(), DiscoveredAt: time.Now().UTC(), ImportStatus: model.SourceFileDiscovered,
	}
	collection.IngestionStatus = model.CollectionStatusPending
	collection.FileCount, collection.SupportedFileCount, collection.UnsupportedFileCount = 1, 1, 0
	full, err := s.commitDiscovery(collection, []model.SourceFile{sf})
	if err != nil {
		return DiscoverResult{}, memoryImageReport{}, err
	}
	triaged := triageAll([]model.SourceFile{sf})
	return DiscoverResult{
		Collection: full, SourceFiles: firstEvidencePage(triaged), Coverage: computeCoverage(triaged),
		SourceFilesTotal: 1, SourceFilesPageSize: defaultEvidencePageSize,
		DiscoveredCount: 1, SupportedCount: 1,
	}, rep, nil
}

func (s *Service) memoryImageSegmentPaths(caseID, collectionID string) ([]string, error) {
	c, err := s.store.GetCollection(collectionID)
	if err != nil || c.CaseID != caseID {
		return nil, ErrCollectionNotFound
	}
	if up := s.files.MemoryImagePath(caseID, collectionID); fileExists(up) {
		return []string{up}, nil
	}
	return []string{c.OriginalFilename}, nil
}

func (s *Service) loadMemoryReport(caseID, collectionID string) (memoryImageReport, bool) {
	b, err := os.ReadFile(s.files.MemoryReportPath(caseID, collectionID))
	if err != nil {
		return memoryImageReport{}, false
	}
	var r memoryImageReport
	if json.Unmarshal(b, &r) != nil {
		return memoryImageReport{}, false
	}
	return r, true
}

// extractMemoryAnalysis runs the plugin set against the collection's
// image and writes the combined analysis where the parser will read it. It
// records the SHA-256 of what it wrote.
func (s *Service) extractMemoryAnalysis(caseID, collectionID string, sf model.SourceFile) error {
	if s.mem == nil {
		return ErrMemoryNotConfigured
	}
	paths, err := s.memoryImageSegmentPaths(caseID, collectionID)
	if err != nil {
		return err
	}
	analysis, err := memory.Collect(context.Background(), s.mem, paths[0], nil)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(s.files.EvidenceDir(caseID, collectionID))
	if err != nil {
		return err
	}
	dest := filepath.Join(root, filepath.FromSlash(sf.Path))
	if rel, relErr := filepath.Rel(root, dest); relErr != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("analysis path %q would resolve outside the evidence directory", sf.Path)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(analysis)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, b, 0o644); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, strings.NewReader(string(b))); err != nil {
		return err
	}
	if err := s.store.SetSourceFileSHA256(sf.ID, hex.EncodeToString(h.Sum(nil))); err != nil {
		return fmt.Errorf("recording extracted file hash: %w", err)
	}
	return nil
}

// attachMemoryInfo adds the memory analysis details to the report's
// evidence list. The plugin outcomes come from the extracted analysis, so
// a plugin that failed is named in the report rather than silently absent.
func (s *Service) attachMemoryInfo(ev []report.Evidence, collections []model.Collection) {
	for i, col := range collections {
		if i >= len(ev) || col.SourceType != model.SourceTypeMemoryImage {
			continue
		}
		r, ok := s.loadMemoryReport(col.CaseID, col.ID)
		if !ok {
			ev[i].Memory = &report.MemoryInfo{Volatility: "unknown", Isolation: "unknown",
				Notes: []string{"The memory record for this collection is missing, so how it was analysed cannot be shown."}}
			continue
		}
		m := &report.MemoryInfo{Volatility: r.Volatility, Isolation: r.Isolation, Size: humanBytes(r.ImageSize), Notes: r.Notes}
		for _, k := range []string{"NTBuildLab", "Major/Minor", "Is64Bit", "SystemTime", "Kernel Base", "NtProductType", "NtMajorVersion", "NtMinorVersion"} {
			if v := r.Info[k]; v != "" {
				m.Info = append(m.Info, report.KV{Key: k, Value: v})
			}
		}
		if b, err := os.ReadFile(filepath.Join(s.files.EvidenceDir(col.CaseID, col.ID), filepath.FromSlash(memoryAnalysisPath))); err == nil {
			var a memory.Analysis
			if json.Unmarshal(b, &a) == nil {
				for _, p := range a.Plugins {
					out := fmt.Sprintf("ok, %d row(s)", len(p.Rows))
					if p.Status != memory.StatusOK {
						out = "FAILED: " + p.Error
					}
					m.Plugins = append(m.Plugins, report.KV{Key: p.Plugin, Value: out})
				}
			}
		} else {
			m.Notes = append(m.Notes, "The plugin set has not been run yet; import the evidence to analyse it.")
		}
		ev[i].Memory = m
	}
}
