package api

import (
	"path"
	"strings"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
	"tracefall/internal/wmirepo"
)

// repositoryBundle admits catalog rows, never filesystem directory listings.
// Source roles use original names; worker opens the explicit stored paths.
// Exact evidence-relative parent paths keep hosts, volumes and bundles apart.
func (s *Service) repositoryBundle(primary model.SourceFile, ad1 *ad1Extractor, disk *diskExtractor) ([]parsers.BundleFile, error) {
	rows, err := s.store.ListSourceFilesByCollection(primary.CollectionID)
	if err != nil {
		return nil, err
	}
	roles := map[string]bool{}
	out := []parsers.BundleFile{}
	for _, row := range rows {
		if row.CaseID != primary.CaseID || row.CollectionID != primary.CollectionID || row.DeletedAt != nil || path.Dir(row.Path) != path.Dir(primary.Path) {
			continue
		}
		role := strings.ToUpper(row.OriginalFilename)
		if !wmirepo.BundleRole(role) {
			continue
		}
		if roles[role] || role == "OBJECTS.DATA" && row.ID != primary.ID {
			return nil, wmirepo.ErrMissingBundle
		}
		roles[role] = true
		if role != "OBJECTS.DATA" && row.ArtifactType != model.ArtifactWMIRepositoryCompanion {
			return nil, wmirepo.ErrMissingBundle
		}
		if row.ID != primary.ID {
			if disk != nil {
				err = disk.extract(row)
			} else if ad1 != nil {
				err = ad1.extract(row)
			}
			if err != nil {
				return nil, err
			}
		}
		fresh, e := s.store.GetSourceFile(row.ID)
		if e != nil {
			return nil, e
		}
		out = append(out, parsers.BundleFile{Role: role, Path: fresh.Path, SourceFileID: fresh.ID, SHA256: fresh.SHA256})
	}
	if !roles["OBJECTS.DATA"] || !roles["INDEX.BTR"] || !roles["MAPPING1.MAP"] && !roles["MAPPING2.MAP"] && !roles["MAPPING3.MAP"] {
		return nil, wmirepo.ErrMissingBundle
	}
	return out, nil
}
