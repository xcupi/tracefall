# Source-admission recovery boundary

A source transaction commits raw evidence, events, observations, imported status,
and case-analysis invalidation together. A zero-event source still invalidates
analysis. A failure to invalidate rolls the entire source back. Retrying an
already-imported source does not invalidate a newer analysis.

Collection finalization is a separate checkpoint. `ReconcileCollectionImports`
derives active-file counts and imported-source event totals with SQL aggregates,
scoped to the requested case and collection. Failed and deleted sources do not
contribute imported files or parsed events. A legacy failed collection retains
its status. Repair and any legacy case-status invalidation share one transaction.
An unchanged rollup is a no-op, so repeated recovery preserves later analysis.

The pipeline reconciles before listing selectable IDs and before honoring a
post-admission cancellation. Ordinary import finalization also reconciles when
that invocation imported nothing. Nested memory collections reconcile before
their no-selectable-IDs shortcut. Source atomicity, historical-partial-source
retry refusal, and parser staging ownership are unchanged.

## Verified boundary

Synthetic validation uses one previously analyzed seed collection with one event
and a new collection with 37 generated SQL informational records. A **test-only Go
build overlay**, not a production flag or hook, blocks after source admission and
before collection finalization. The driver observes the marker, SIGKILLs that
compiled process, then restarts the ordinary binary against the same database,
data directory, job ID, and collection ID.

- Baseline: the resumed job succeeds with no newly imported sources, but its
  collection remains pending with zero parsed events and the case remains
  analyzed. Startup migration updates the imported-file count alone. The HTML
  report exposes the stale pending/zero-event rollup.
- Fixed: the source commit already stales analysis. Restart repairs the collection
  to ingested, one imported file, and 37 parsed events. Events/raw evidence/
  observations remain exactly 38 each across the two collections. The report
  shows the separate one-event and 37-event collections.
- Upgrade: an actually interrupted baseline process resumes with the fixed
  binary; reconciliation repairs both its legacy rollup and stale case status.
- Idempotence: after reanalysis, a **test-controlled replay** of the same job's
  import checkpoint reaches attempt three without new evidence, count drift, or
  resetting the newer analysis. This replay is not represented as a second
  observed crash.

Owner-only execution proofs, overlay sources, binary hashes, synthetic databases,
HTML reports, and driver are retained locally under
`analysis/parser-scale-validation/completion/rollup-boundary-proof-04` and
`analysis/parser-scale-validation/completion/rollup_binary_proof.py`.
No provider, network enrichment, or acquired evidence is involved.

## Verification limits

Targeted race runs cover recovery, cancellation, invalidation, source rollback,
streaming/staging guards, failed-source refusal, and store round trips. Build,
vet, and diff whitespace checks pass. A broader store race run timed out in its
100,000-event deletion scale test; that run is not a pass, and scoped store race
checks were subsequently run successfully. No full-suite pass is claimed.
Largest SQL capacity, native-file regression coverage, and other parser checkpoint
acceptance gates remain separate and open.
