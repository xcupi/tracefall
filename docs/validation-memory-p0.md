# Memory identity P0 regression — 2026-10-18

## Scope and implementation

Fixes the event-identity defect measured in
[the real-lab baseline](validation-cyberdefenders-baseline.md). This work does
not tune detection, implement Linux/Android parsing, or repair report layout.

`internal/model/dedup.go` extends identity **only for `memory_analysis`**:

- malfind: start and end addresses of the memory region;
- service: name, state, start type, service type, recorded registry binary and DLL
  (PID, timestamp and observed binary path are already in the base identity);
- socket: local address, local port, protocol and state (destination address/port,
  PID and timestamp are already in the base identity).

Source row indices, collection IDs, renderer notes and disassembly are excluded.
Identical observations continue sharing an event with separate raw-evidence
observations. Non-memory hash field sequences remain unchanged.

`internal/parsers/volatility/volatility.go` also compares **both** region bounds
in its pre-persistence duplicate filter; it no longer drops a differently sized
range just because the PID and start address agree.

## RED -> GREEN tests

Observed failures before fixing each slice:

- parser -> store: two malfind regions for one PID/snapshot persisted as one;
- parser -> store: BITS and Schedule sharing a binary/PID persisted only BITS;
- parser -> store: both connections and listeners lost the second local port;
- model: distinct service configuration/state, protocol/state and local addresses
  had identical hashes;
- parser: two ranges sharing a start but differing in end collapsed before store.

The corrected tests pass. Additional guards prove that exact duplicate service
rows still collapse, a second collection does not inflate the timeline, and
all source rows from both collections retain separate raw evidence IDs and
observations. Historical hashes are pinned for both a Windows process event
and a non-memory network event. Nil Extra maps remain safe.

Targeted commands exercised:

    go test ./internal/model ./internal/parsers/volatility -count=1
    go test ./internal/api -run '^TestMemory_' -count=1
    go test -race ./internal/model ./internal/parsers/volatility -count=1
    go test -race ./internal/api -run '^TestMemory_DedupPreserves' -count=1
    make build

A separate probe recomputed the old saved hashes of **141 actual non-memory
events** from Insider and The Crime: all remained identical.

Full `go vet ./... && go test -timeout 30m ./...` passed with **exit 0**;
`internal/api` completed in **766.328 seconds** on the clean run. `make build`
passed, as did the focused race regressions.

The initial concurrent run was **not** green: the unrelated
`TestBrowserCache_LargeCacheImportScales` imported 1,000 entries in 145.578 seconds,
exceeding its existing 90-second ceiling while real memory analysis was also
running. It still produced all 1,000 events. Without the competing dump workload,
the unchanged test passed with a 54.997-second import; the complete suite was then
rerun and passed. Both suite logs and the isolated retry log are retained. No
test threshold or browser-cache implementation was changed.

## Actual image re-ingestion, fresh cases

Reran the actual built binary's server pipeline against the original Reveal,
Ramnit and RedLine memory files, using new case IDs and a separate database/data
directory. Baseline cases/reports were not overwritten. Volatility 3 2.28.2 ran
inside bubblewrap with the previously prepared symbols.

| Dataset | Old timeline events | New timeline events | malfind regions raw/new | Nonempty service names raw/new | Distinct endpoint/state tuples raw/new |
|---|---:|---:|---:|---:|---:|
| Reveal | 637 | 853 | 12/12 | 654/654 | 59/59 |
| Ramnit | 731 | 871 | 11/11 | 651/651 | 69/69 |
| RedLine | 431 | 816 | 3/3 | 599/599 | 84/84 |

Socket tuple comparison covers PID, protocol, local address/port, remote
address/port and state; tuple totals deliberately do not count repeated rows or
separate creation times as separate endpoint/state tuples. Service-name totals
are not service-event totals: differing configuration/state may produce multiple
observations for the same name (e.g. 618 service events with 599 nonempty names
in RedLine).

**42 selected checks passed, zero failed** across the three images:

- all jobs succeeded;
- bubblewrap remained active;
- all 18 plugin row multisets still matched the independent direct-Volatility
  outputs preserved in the baseline;
- every distinct malfind range survived into the timeline;
- every nonempty service name survived;
- every distinct socket endpoint/state tuple survived;
- image integrity re-verification succeeded;
- each generated report ZIP passed the real `verify-report` command;
- SHA-256 of each original memory file remained unchanged.

HTML/PDF/ZIP reports were regenerated. Reveal PDF page 3 was visually inspected;
the plugin table and snapshot/heuristic caveats are legible. The pre-existing
inventory metric labels and Run ID layout are not fixed by this change.

Findings remain **32 / 32 / 20** and correlations **85 / 124 / 73** for
Reveal/Ramnit/RedLine respectively. More faithful evidence is not proof of better
detection; generic lineage noise and missing memory-specific reasoning remain P1.
This bounded regression does not establish full forensic correctness or coverage.

## Existing cases and recovery

This fix does **not** rewrite old cases, old stored hashes or previously issued
reports. Their generic identities may already have merged distinct objects.
Rehashing the surviving representative alone cannot reconstruct separate events.

Keep the old case/report, then create a fresh case and re-ingest the original
memory image with the fixed build; rerun analysis and issue a fresh report.
Do not assume adding a new recollection to a pre-fix case migrates its old
identities. This fresh-case workflow was the one actually validated above.

## Saved artifacts

an external results directory (not included in this repository) preserves the new cases'
outputs, combined plugin JSON, timeline, findings, correlations, HTML/PDF/ZIP,
checks, integrity results, build/source hashes and test log. Original multi-GB
memory files are not copied into the output or committed. The baseline directory
is retained unchanged for comparison.
