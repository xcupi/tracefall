# AD1 sample: DiskDrigger.ad1

**100% synthetic**, fabricated specifically to exercise Tracefall's AD1
ingestion (Phase 7) end to end, the same way
[`testdata/synthetic_case`](../synthetic_case) and
[`testdata/scenarios`](../scenarios) do for KAPE ZIP/local-path ingest.
No real hostnames, usernames, IP addresses, or evidence of any kind are
present -- the host is `WKSTN-042`, the user is `jdoe`, and IP addresses
use IANA-reserved documentation ranges (`203.0.113.0/24`,
`198.51.100.0/24`).

`DiskDrigger.ad1` is a real, structurally valid AD1v4 image (magic
bytes, segment/logical-image headers, FileEntry tree, zlib-compressed
chunks -- everything [`internal/ad1`](../../internal/ad1) parses), built
by [`internal/ad1/ad1gen`](../../internal/ad1/ad1gen) -- the same
from-scratch, pure-Go AD1 *writer* used by `internal/ad1`'s own unit
tests, so there is one source of truth for what this fixture contains,
not a hand-maintained binary that could drift from what the reader
actually expects. It was NOT produced by real FTK Imager (Tracefall has
no such tool available in this environment); "real" here means real in
format, synthetic in content -- see `docs/ad1-ingestion.md` for how the
format itself was verified against reference implementations before any
of this was written.

Declared root: `C:\Users\jdoe\Desktop\DiskDrigger`. Contents:

| Path (inside the AD1) | Artifact | Supported |
|---|---|---|
| `EvtxECmd/20260115_090000_EvtxECmd_Output.csv` | Windows Event Log (EvtxECmd) | yes |
| `PECmd/20260115_090000_PECmd_Output.csv` | Prefetch (PECmd) | yes |
| `RECmd/20260115_090000_RECmd_Batch_RunKeys_Output.csv` | Registry Run key (RECmd) | yes |
| `README.txt` | -- | no (deliberately unsupported, to exercise "visible but unselectable") |

The EvtxECmd CSV is the **same phishing → Office → PowerShell → payload
→ persistence → C2, plus a brute-force credential attack** narrative as
`testdata/synthetic_case`'s own EvtxECmd output (see that directory's
README) -- reused here so importing this AD1 and running analysis
produces real findings, correlated activity chains, and investigations
through Tracefall's completely unmodified detect/correlate/investigate
pipeline, not just an empty or trivial result. The PECmd and RECmd
entries carry an embedded MD5/SHA1 (as AD1 acquisition metadata would,
when FTK Imager is configured to compute one) so the evidence-integrity
UI has something real to show under "as reported by AD1."

Used by the browser-verification pass for Phase 7 (see the phase
report): upload → recognize as an AD1 Forensic Image → enumerate
contents → select a subset → import → analyze → verify timeline/
findings/ATT&CK/investigations → verify provenance back to the AD1
internal path → delete one imported artifact → re-analyze → verify only
that artifact's contribution disappears.
