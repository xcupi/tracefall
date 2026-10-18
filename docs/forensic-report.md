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
| `GET /api/cases/{id}/report.zip` | `report.html`, `manifest.json`, `timeline.csv`, `findings.csv`. |
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
7. Timeline summary and the events cited by findings. The full timeline is the
   attached `timeline.csv`.
8. Coverage and limitations: what was and was not analyzed, unsupported
   high-value artifact classes, parse failures, undated events, and fixed
   statements of what the report does not claim.
9. Appendices: attachment hashes, the detection rules that fired, the audit trail.

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
- Timestamps without an explicit zone in the source were read as UTC, and the
  source system's time zone is not separately established.
- The report is built from the case as stored. If evidence changed after the
  last analysis, a prominent warning says so and why.
- Not yet addressed: the report loads the whole case into memory (see the
  streaming item in the roadmap), and the CSV attachments do not neutralize
  spreadsheet formula injection.
