# Forensic report

Tracefall produces a deterministic forensic report from a case's stored
data. No LLM is involved: every sentence is fixed template text or a
value read from the case, and the renderer (`internal/report`) cannot
reach the database or the parsers, so it cannot add anything the caller
did not pass in.

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /api/cases/{id}/report.html` | One self-contained HTML document. `?download=1` forces a download. |
| `GET /api/cases/{id}/report.zip` | `report.html`, `manifest.json`, `timeline.csv`, `findings.csv`, `correlations.json`, `cited-events.json`. |
| `GET /api/cases/{id}/report.pdf` | The report printed to PDF. `501` if the server has no browser to print with. |

The dashboard's **Export** menu links all three.

## What the report contains

1. Cover and metadata: case, tool version, generation time, requesting account.
2. Executive summary with severity counts and the top investigations.
3. Evidence inventory: complete SHA-256 and SHA-512, what each digest covers,
   and the latest integrity re-verification (or a statement that there is none).
4. Methodology, the analysis runs, and the distinction between **observed**
   values (read from evidence, with a source reference) and **interpretation**
   (severity, rule reasoning, ATT&CK mapping).
5. Investigations.
6. Findings: severity and confidence, why, ATT&CK, review status and notes, and
   the supporting events with the file and record each came from.
7. Correlated activity (section 6): clock offsets, web-to-host ties, host
   relationships and other stored correlations. Each carries its type, ID,
   description and ordered supporting event references. No correlation is
   silently promoted to a finding or a proof of causation.
8. Timeline summary and the events cited by findings **and correlations**. The
   full timeline is the attached `timeline.csv`.
9. Coverage and limitations: what was and was not analyzed, unsupported
   high-value artifact classes, parse failures, undated events, and fixed
   statements of what the report does not claim.
10. Appendices: attachment hashes, the detection rules that fired, the audit trail.

Evidence blocks carry event IDs, source paths and record references. HTTP
observations retain method, host, URI, status, reassembly and complete hashes;
clock observations show both clocks; recovered memory content shows its hash,
cache kind, zero-page count, sparse flag and static inspection indicators.
Command summaries are redacted with the same credential redactor used by
command-related findings. This is not a guarantee that every possible secret
is removed; the evidence attachments still contain sensitive case data.

The HTML shows at most ten supporting events per finding or correlation.
Unresolved references are **not** counted as omitted available events: they
produce an explicit evidence-incomplete warning. `correlations.json` retains
every stored correlation's complete ordered event-reference list. The companion
`cited-events.json` contains every resolved event cited by a finding or
correlation, with its full normalized fields, `Extra`, and source record
reference, including observations beyond both HTML display caps. This is
sensitive evidence and is not credential-redacted; restrict bundle access.
The CSV contains core timeline columns, not the complete event metadata.
Response-only HTTP and DNS observations explicitly preserve the missing-request
marker and the response time in the HTML. A warning
means that the interpretation cannot be fully verified from available events;
it does not manufacture replacement evidence.

Anything cut for length (events per finding, key events, audit entries,
failed-file list, investigations) states how many were omitted and where the
full data is.

## Integrity

`manifest.json` lists the SHA-256 of `report.html` and each attachment, the
evidence digests recorded at ingestion, the case, the tool version and the
generation time. The attachments are produced by the same code as the
`/export/*.csv` endpoints, so the CSV an examiner downloads separately is
byte-identical to the one in the bundle.

Check a bundle without a server or a database:

    tracefall verify-report report.zip

Exit status: `0` all files match; `1` a file differs, is missing, or is not
listed in the manifest; `2` the check could not be performed (bad arguments,
unreadable or corrupt input), which is never a pass.

The same case at the same instant renders to the same bytes. Each issuance is
recorded in the case audit trail with the SHA-256 of the report, and a report
lists the issuances before it, never itself.

## PDF

The PDF is printed from the HTML by headless Chrome or Chromium. The HTML
carries a Content-Security-Policy that forbids script and any network load,
and the browser runs with a throwaway profile, a minimal environment and a
90 second limit. Set `TRACEFALL_CHROME` to pin the binary; when it is set,
no other browser is tried.

The PDF is **not byte-reproducible** (the browser embeds its creation time),
so the HTML is the canonical artifact and the one the manifest hashes. With no
browser installed the endpoint returns `501` and says so; it never substitutes
something else. The HTML report is complete and prints to PDF from any browser.

## Privacy

A report is a document that leaves the machine. For a collection ingested
from a local path, only the final path element is shown, marked
"server path withheld", and the same redaction is applied to the audit
trail's discovery entry. The audit log itself is not changed.

## Limits of what this proves

- A manifest shows files match it. It is not a digital signature and does not
  identify who produced it.
- The account shown as having generated the report is a system account name,
  not a verified examiner identity.
- This is not a legal chain of custody record. See
  [provenance-and-custody.md](provenance-and-custody.md).
- Known instants display in UTC. Unknown-zone local readings and dates without
  a year remain as recorded, without an invented instant. The collection's
  SYSTEM hive supplies a host-zone basis when available. Capture clocks and
  snapshot clocks are not silently treated as execution times or corrected.
- The report is built from the case as stored. If evidence changed after the
  last analysis, a prominent warning says so and why.
- Timeline aggregation and its CSV attachment stream through a spool file.
  Findings, correlations, their cited events and the HTML still occupy memory;
  this is not a constant-memory report builder. CSV writers neutralize leading
  spreadsheet formula markers without altering stored evidence.
- Source-linked observations and incomplete-evidence warnings are enforced by
  regression tests. There is no formal sentence-by-sentence proof checker;
  deterministic interpretations still require examiner review.
