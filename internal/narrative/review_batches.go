package narrative

import "fmt"

// CheckReviewBatchSize enforces the combined ceiling after all batch-specific
// instructions/catalog/synthesis text have been added, and seals the receipt size.
func CheckReviewBatchSize(p *ReviewPrepared) error {
	size := len(p.System) + len(p.User)
	if size > ReviewMaxBytes {
		return ErrReviewTooLarge
	}
	p.Privacy.PayloadBytes = size
	return nil
}

// AddBatchCatalog adds fixed classification/count fields only. Source paths,
// filenames, parser errors and arbitrary coverage notes never enter this prose.
func AddBatchCatalog(p *ReviewPrepared, c ReviewCoverage, parseGapSources int) {
	p.User += fmt.Sprintf("\nK1 frozen_whole_catalog | catalog_sources_total=%d catalog_sources_imported=%d catalog_sources_failed=%d catalog_sources_unsupported=%d catalog_sources_not_imported=%d catalog_parse_coverage_not_recorded=%d catalog_sources_with_parse_gaps=%d. Source rows above are only a bounded sample, not the catalog.\n", c.SourcesTotal, c.SourcesImported, c.SourcesFailed, c.SourcesUnsupported, c.SourcesNotImported, c.ParseCoverageNotRecorded, parseGapSources)
	for _, d := range digitsRe.FindAllString(p.User, -1) {
		p.numbers[trimZeros(d)] = true
	}
	p.Privacy.PayloadBytes = len(p.System) + len(p.User)
}
