package api

import (
	"testing"

	"tracefall/internal/model"
)

func TestHostEnrichment_CollectionSiblingsAfterRecollection(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "host identity recollection")
	first := discoverZip(t, mux, c.ID, hostFixtureFiles())
	importInPathOrder(t, mux, c.ID, first, pathPecmd, pathRecmd, pathEvtx)
	before := eventFingerprints(timelineOf(t, mux, c.ID))

	// The second log is deduplicated against the first collection, but its
	// observation still explicitly establishes a host for this acquisition.
	recollectionFiles := hostFixtureFiles()
	recollectionFiles["acquisition-note.txt"] = "second synthetic acquisition"
	second := discoverZip(t, mux, c.ID, recollectionFiles)
	importInPathOrder(t, mux, c.ID, second, pathEvtx)
	importInPathOrder(t, mux, c.ID, second, pathPecmd, pathRecmd)
	after := eventFingerprints(timelineOf(t, mux, c.ID))
	if len(before) != len(after) {
		t.Fatalf("recollection inflated events: before %d after %d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("recollection identity changed:\n%s\n%s", before[i], after[i])
		}
	}
	assertAllHosts(t, timelineOf(t, mux, c.ID), model.ArtifactPrefetch, "WKSTN-042")
}

func TestHostEnrichment_PersistedSameCollectionSibling(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "collection siblings")
	disc := discoverZip(t, mux, c.ID, hostFixtureFiles())
	importInPathOrder(t, mux, c.ID, disc, pathEvtx)
	importInPathOrder(t, mux, c.ID, disc, pathPecmd, pathRecmd)
	assertAllHosts(t, timelineOf(t, mux, c.ID), model.ArtifactPrefetch, "WKSTN-042")
	assertAllHosts(t, timelineOf(t, mux, c.ID), model.ArtifactRegistryRunKey, "WKSTN-042")
}

func TestHostEnrichment_SeparateCollectionsKeepDistinctHosts(t *testing.T) {
	mux := newTestRouter(t)
	c := mustCreateCase(t, mux, "separate machine acquisitions")
	first := discoverZip(t, mux, c.ID, hostFixtureFiles())
	importInPathOrder(t, mux, c.ID, first, pathPecmd, pathRecmd, pathEvtx)
	second := discoverZip(t, mux, c.ID, map[string]string{pathEvtx2: hostEvtxCSVOtherHost, pathPecmd: hostPecmdCSV})
	importInPathOrder(t, mux, c.ID, second, pathPecmd, pathEvtx2)
	assertAllHosts(t, timelineOf(t, mux, c.ID), model.ArtifactPrefetch, "SRV-DC-01", "WKSTN-042")
	third := discoverZip(t, mux, c.ID, map[string]string{pathPecmd: hostPecmdCSV})
	importInPathOrder(t, mux, c.ID, third, pathPecmd)
	assertAllHosts(t, timelineOf(t, mux, c.ID), model.ArtifactPrefetch, "", "SRV-DC-01", "WKSTN-042")
}
