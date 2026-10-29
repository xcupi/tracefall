package report

import (
	"bytes"
	"fmt"
	"html/template"
)

// Render produces the report as a single self-contained HTML document.
//
// html/template escapes every value for the context it lands in, and the
// document carries a Content-Security-Policy that forbids script and any
// network load. Both matter: the strings in a report come from evidence,
// and evidence may have been written by the attacker being investigated.
func Render(d Data) ([]byte, error) {
	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, d); err != nil {
		return nil, fmt.Errorf("report: rendering: %w", err)
	}
	return buf.Bytes(), nil
}

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"sev": func(s string) string {
		switch s {
		case "critical", "high", "medium", "low":
			return "sev-" + s
		}
		return "sev-none"
	},
}).Parse(reportHTML))

const reportHTML = `{{define "observation"}}
<article class="observation">
<p class="small"><strong>{{.Type}}</strong> &middot; {{.Artifact}} &middot; {{.Time}}</p>
<p class="small mono"><strong>Event:</strong> {{.ID}}</p>
<p class="small mono"><strong>Source:</strong> {{.Source}}{{if .Ref}} &middot; {{.Ref}}{{end}}</p>
<p class="wrap">{{.Summary}}</p>
{{if .Details}}<dl class="event-details small">{{range .Details}}<div><dt>{{.Key}}</dt><dd class="mono">{{.Value}}</dd></div>{{end}}</dl>{{end}}
</article>
{{end}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="generator" content="{{.Meta.ToolName}} {{.Meta.ToolVersion}}">
<title>{{.Meta.Title}} - {{.Meta.CaseName}}</title>
<style>
  :root { --ink:#1b1f24; --muted:#59636e; --line:#d0d7de; --bg:#fff; --soft:#f6f8fa; }
  * { box-sizing: border-box; }
  body { font: 14px/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: var(--ink); background: var(--bg); margin: 0; }
  main { max-width: 980px; margin: 0 auto; padding: 32px 28px 64px; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h2 { font-size: 19px; margin: 34px 0 10px; padding-bottom: 6px; border-bottom: 2px solid var(--ink); }
  h3 { font-size: 15px; margin: 22px 0 6px; }
  h4 { font-size: 13px; margin: 14px 0 4px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
  p { margin: 6px 0; }
  .muted { color: var(--muted); }
  .small { font-size: 12px; }
  .mono { font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; font-size: 12px; word-break: break-all; }
  table { border-collapse: collapse; width: 100%; margin: 8px 0 14px; }
  th, td { border: 1px solid var(--line); padding: 5px 8px; text-align: left; vertical-align: top; }
  td.wrap, p, li, h3 { overflow-wrap: anywhere; }
  .badge { white-space: nowrap; }
  .event-details { margin: 6px 0 0; }
  .event-details > div { display: grid; grid-template-columns: 155px minmax(0, 1fr); gap: 8px; break-inside: avoid; }
  .observation { border-left: 3px solid var(--line); padding: 6px 10px; margin: 8px 0; }
  .observation > p { break-inside: avoid; }
  .event-details dt { font-weight: 600; color: var(--muted); }
  .event-details dd { margin: 0 0 4px; overflow-wrap: anywhere; }
  .nowrap { white-space: nowrap; word-break: normal; overflow-wrap: normal; }
  th { background: var(--soft); font-weight: 600; }
  td.num, th.num { text-align: right; white-space: nowrap; }
  .cover { border-bottom: 1px solid var(--line); padding-bottom: 18px; margin-bottom: 8px; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; text-transform: uppercase; border: 1px solid var(--ink); }
  .sev-critical { background: #6e0b14; color: #fff; border-color: #6e0b14; }
  .sev-high { background: #cf222e; color: #fff; border-color: #cf222e; }
  .sev-medium { background: #fff3d0; border-color: #9a6700; color: #4a3200; }
  .sev-low { background: #e6f4ea; border-color: #1a7f37; color: #0f4a22; }
  .sev-none { background: var(--soft); color: var(--muted); border-color: var(--line); }
  .warn { border: 2px solid #9a6700; background: #fff8e1; padding: 10px 14px; margin: 14px 0; }
  .finding { border: 1px solid var(--line); padding: 4px 16px 10px; margin: 16px 0; }
  .finding h3 { margin-top: 12px; }
  ul { margin: 4px 0 8px 20px; padding: 0; }
  nav ol { margin: 6px 0 0 20px; padding: 0; }
  footer { margin-top: 40px; border-top: 1px solid var(--line); padding-top: 10px; color: var(--muted); font-size: 12px; }
  @media print {
    main { max-width: none; padding: 0; }
    h2 { page-break-after: avoid; }
    tr { page-break-inside: avoid; }
    .finding h3 { break-after: avoid; }
    h3, h4 { break-after: avoid; }
    .warn, .sev-critical, .sev-high, .sev-medium, .sev-low { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
  @page { size: A4; margin: 16mm 14mm; }
</style>
</head>
<body>
<main>

<header class="cover">
  <div class="muted small">DIGITAL FORENSIC ANALYSIS REPORT</div>
  <h1>{{.Meta.CaseName}}</h1>
  {{if .Meta.Description}}<p>{{.Meta.Description}}</p>{{end}}
  <table>
    <tr><th>Case ID</th><td class="mono">{{.Meta.CaseID}}</td><th>Case status</th><td>{{.Meta.CaseStatus}}</td></tr>
    <tr><th>Priority</th><td>{{.Meta.Priority}}</td><th>Case created</th><td class="mono">{{.Meta.CreatedAt}}</td></tr>
    <tr><th>Last analysis</th><td class="mono">{{if .Meta.AnalyzedAt}}{{.Meta.AnalyzedAt}}{{else}}never{{end}}</td><th>Report generated</th><td class="mono">{{.Meta.GeneratedAt}}</td></tr>
    <tr><th>Generated by</th><td>{{.Meta.GeneratedBy}}</td><th>Tool</th><td>{{.Meta.ToolName}} {{.Meta.ToolVersion}}</td></tr>
  </table>
  <p class="small muted">{{.Meta.TimeBasis}}</p>
</header>

<nav>
  <h4>Contents</h4>
  <ol class="small">
    <li>Executive summary</li><li>Evidence inventory</li><li>Methodology</li><li>Investigations</li>
    <li>Findings</li><li>Correlated activity</li><li>Timeline</li><li>Coverage and limitations</li><li>Appendices</li>
  </ol>
</nav>

{{if not .Analysis.Current}}
<div class="warn" role="alert">
  <strong>The analysis in this report may not reflect the current evidence.</strong>
  {{if .Analysis.Note}}<div>{{.Analysis.Note}}</div>{{end}}
  <div class="small">Re-run analysis and regenerate the report before relying on the findings below.</div>
</div>
{{end}}

<h2>1. Executive summary</h2>
<p>
  This report covers <strong>{{.Summary.Collections}}</strong> evidence collection(s) containing
  <strong>{{.Summary.SourceFiles}}</strong> cataloged file(s), of which <strong>{{.Summary.ImportedFiles}}</strong>
  were parsed into <strong>{{.Summary.Events}}</strong> normalized event(s). Deterministic detection rules produced
  <strong>{{.Summary.Findings}}</strong> finding(s), <strong>{{.Summary.Correlations}}</strong> correlation(s) and
  <strong>{{.Summary.Investigations}}</strong> grouped investigation(s), mapped to
  <strong>{{.Summary.Techniques}}</strong> MITRE ATT&amp;CK technique(s).
</p>
<table>
  <tr>{{range .Summary.Severity}}<th class="num">{{.Name}}</th>{{end}}</tr>
  <tr>{{range .Summary.Severity}}<td class="num">{{.N}}</td>{{end}}</tr>
</table>
{{if .Investigations}}
<h4>Highest-ranked investigations</h4>
<table>
  <tr><th>Investigation</th><th>Severity</th><th>Confidence</th><th class="num">Score</th><th>Period (UTC)</th></tr>
  {{range .Investigations}}
  <tr><td>{{.Title}}</td><td><span class="badge {{sev .Severity}}">{{.Severity}}</span></td><td>{{.Confidence}}</td><td class="num">{{.Score}}</td><td class="mono nowrap">{{.Start}}<br>{{.End}}</td></tr>
  {{end}}
</table>
{{else}}
<p>No investigations were produced. This is an observation about the analyzed evidence, not a statement that nothing occurred; see section 8 for what was not analyzed.</p>
{{end}}

<h2>2. Evidence inventory</h2>
<p class="small muted">Digests are those recorded when the evidence was ingested. "Integrity" is the outcome of the most recent re-verification.</p>
{{range .Evidence}}
<table>
  <tr><th colspan="2">{{.Label}} &mdash; {{.OriginalName}}</th></tr>
  <tr><th>Source type</th><td>{{.SourceType}}</td></tr>
  <tr><th>Digest scope</th><td>{{.HashKind}}</td></tr>
  <tr><th>SHA-256</th><td class="mono">{{.SHA256}}</td></tr>
  <tr><th>SHA-512</th><td class="mono">{{.SHA512}}</td></tr>
  <tr><th>Integrity</th><td>{{.Integrity}}</td></tr>
  <tr><th>Ingestion</th><td>{{.Status}}; {{.Files}} file(s) cataloged ({{.Supported}} supported, {{.Unsupported}} unsupported), {{.Imported}} imported, {{.Events}} event(s)</td></tr>
</table>
{{with .Memory}}
<h3>Memory image: how it was analysed</h3>
<table>
  <tr><th>Tool</th><td>Volatility 3 Framework {{.Volatility}}, driven by Tracefall</td></tr>
  <tr><th>Isolation</th><td>{{.Isolation}}</td></tr>
  <tr><th>Image size</th><td>{{.Size}}</td></tr>
  {{range .Info}}<tr><th>{{.Key}}</th><td class="wrap">{{.Value}}</td></tr>{{end}}
</table>
{{if .Plugins}}
<table>
  <tr><th>Plugin</th><th>Outcome</th></tr>
  {{range .Plugins}}<tr><td class="mono">{{.Key}}</td><td class="wrap">{{.Value}}</td></tr>{{end}}
</table>
{{end}}
<p class="small">Memory evidence is a snapshot. Processes and sockets that record their own creation time are placed at that time. Everything else (services, suspicious memory regions, sockets with no creation time) is dated to the system clock captured in the image and is marked <code>memory_snapshot</code> in the timeline: it shows what was present when the image was taken, not when it began. A plugin that failed is listed above and contributes no events.</p>
<p class="small">Memory findings are indicators. A hidden-process flag means a process was found by scanning memory but is absent from the active process list; it is not proof of a rootkit. A memory-injection hit means private executable memory, which legitimate JIT-compiled code also produces.</p>
{{range .Notes}}<p class="small"><strong>Note:</strong> {{.}}</p>{{end}}
{{end}}
{{with .Image}}
<h3>Disk image: container and layout</h3>
<table>
  <tr><th>Container</th><td>{{.Format}}, {{.Segments}} segment(s), {{.Size}}</td></tr>
  {{range .Acquisition}}<tr><th>{{.Key}}</th><td class="wrap">{{.Value}}</td></tr>{{end}}
  <tr><th>Hash recorded at acquisition</th><td class="mono">MD5 {{if .StoredMD5}}{{.StoredMD5}}{{else}}&mdash;{{end}}<br>SHA-1 {{if .StoredSHA1}}{{.StoredSHA1}}{{else}}&mdash;{{end}}</td></tr>
  <tr><th>Hash of the decoded image</th><td class="mono">MD5 {{.ComputedMD5}}<br>SHA-1 {{.ComputedSHA1}}</td></tr>
  <tr><th>Verification</th><td>{{.Verification}}</td></tr>
  <tr><th>Partitioning</th><td>{{.Partitioning}}</td></tr>
</table>
<table>
  <tr><th>#</th><th>Type</th><th>Name</th><th>File system</th><th>Start sector</th><th>Size</th></tr>
  {{range .Partitions}}<tr><td>{{.Index}}</td><td>{{.Type}}</td><td class="wrap">{{.Name}}</td><td>{{.FS}}</td><td>{{.Start}}</td><td>{{.Size}}</td></tr>{{end}}
</table>
{{if .Volumes}}
<table>
  <tr><th>Volume</th><th>Label</th><th>Files in use</th><th>Deleted entries</th><th>Cataloged</th><th>Not cataloged</th><th>Damaged records</th></tr>
  {{range .Volumes}}<tr><td>{{.Prefix}}</td><td class="wrap">{{.Label}}</td><td>{{.FilesInUse}}</td><td>{{.Deleted}}</td><td>{{.Cataloged}}</td><td>{{.NotCataloged}}</td><td>{{.Corrupt}}</td></tr>{{end}}
</table>
<p class="small muted">Only files that a Tracefall parser recognises are cataloged. &ldquo;Not cataloged&rdquo; files exist in the image but were not examined; deleted entries are counted but not cataloged.</p>
{{end}}
{{range .Notes}}<p class="small"><strong>Note:</strong> {{.}}</p>{{end}}
{{end}}
{{else}}
<p>No evidence has been added to this case.</p>
{{end}}

<h2>3. Methodology</h2>
<p>
  Evidence was cataloged and hashed on ingestion, parsed by format-specific parsers into a common event schema, and
  analyzed by a fixed set of deterministic detection and correlation rules. The same evidence and the same tool
  version produce the same findings. Evidence files are never modified; every event keeps a reference to the file and
  record it came from.
</p>
<p>
  Statements in this report are of two kinds. <strong>Observed</strong> statements are values read directly from
  evidence (a timestamp, a path, a command line) and carry a source reference. <strong>Interpretation</strong>
  statements (a finding's severity, a rule's reasoning, an ATT&amp;CK mapping) are produced by the rules documented
  in Appendix B and are indications for an examiner to review, not conclusions of fact.
</p>
<h4>Host time zone</h4>
{{if .TimeZones}}
<table>
  <tr><th>Collection</th><th>Zone recorded by the SYSTEM hive</th><th>Source</th></tr>
  {{range .TimeZones}}
  <tr><td>{{.Label}}</td>{{if .Recorded}}<td>{{.Basis}}</td><td class="mono">{{.Source}}</td>{{else}}<td>not recorded</td><td>{{.Reason}}</td>{{end}}</tr>
  {{end}}
</table>
{{end}}
<p>
  Windows shell items (ShellBags) record their DOS dates in the machine's local clock with no zone. Where a SYSTEM
  hive records the zone, those readings also appear as UTC, computed with one fixed offset. Daylight-saving changes
  are not applied, so a reading taken across a change can be off by one hour. The local readings are always kept as
  they were recorded. The event timestamp is never the converted value; it is the registry key's own write time, in UTC.
</p>
<h4>Analysis runs</h4>
{{if .Analysis.Runs}}
{{range .Analysis.Runs}}
<table>
<tr><th colspan="4">Analysis run <span class="mono">{{.ID}}</span></th></tr>
<tr><th>Started (UTC)</th><td class="mono">{{.Started}}</td><th>Completed (UTC)</th><td class="mono">{{.Completed}}</td></tr>
<tr><th>Status</th><td>{{.Status}}{{if .Invalidated}} (invalidated {{.Invalidated}}){{end}}</td><th>Tool version</th><td>{{.ToolVersion}}</td></tr>
<tr><th>Results</th><td colspan="3">{{.Events}} events; {{.Findings}} findings; {{.Correlations}} correlations</td></tr>
</table>
{{end}}
{{else}}
<p>No analysis run is recorded for this case.</p>
{{end}}

<h2>4. Investigations</h2>
{{range .Investigations}}
<h3>{{.Title}} <span class="badge {{sev .Severity}}">{{.Severity}}</span></h3>
<p class="small muted">Category: {{.Category}} &middot; Confidence: {{.Confidence}} &middot; Risk score: {{.Score}} &middot; Findings: {{.FindingCount}} &middot; Review status: {{.ReviewStatus}}</p>
<p class="small muted">Period: <span class="mono">{{.Start}} &ndash; {{.End}}</span>{{if .Hosts}} &middot; Hosts: {{.Hosts}}{{end}}{{if .Users}} &middot; Users: {{.Users}}{{end}}</p>
<p>{{.Summary}}</p>
{{if .Rationale}}<ul class="small">{{range .Rationale}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{else}}
<p>None.</p>
{{end}}

<h2>5. Findings</h2>
{{range .Findings}}
<div class="finding">
  <h3>{{.Number}} &mdash; {{.Title}} <span class="badge {{sev .Severity}}">{{.Severity}}</span></h3>
  <p class="small muted">Confidence: {{.Confidence}} &middot; Rule: <span class="mono">{{.RuleID}}</span> &middot; Review status: {{.ReviewStatus}} &middot; ID: <span class="mono">{{.ID}}</span></p>
  <p class="small muted">First seen <span class="mono">{{.FirstSeen}}</span> &middot; last seen <span class="mono">{{.LastSeen}}</span> (UTC)</p>
  <p>{{.Description}}</p>
  {{if .Techniques}}<p class="small"><strong>ATT&amp;CK:</strong> {{range $i, $t := .Techniques}}{{if $i}}; {{end}}{{$t.ID}} {{$t.Name}} ({{$t.Tactic}}){{end}}</p>{{end}}
  {{if .Why}}<h4>Why this severity (interpretation)</h4><ul class="small">{{range .Why}}<li>{{.}}</li>{{end}}</ul>{{end}}
  {{if .ReviewNote}}<p class="small"><strong>Analyst review note:</strong> {{.ReviewNote}}</p>{{end}}
  {{if .Notes}}<h4>Analyst notes</h4><ul class="small">{{range .Notes}}<li>{{.}}</li>{{end}}</ul>{{end}}
  <h4>Supporting evidence (observed) &mdash; {{.EventCount}} event(s)</h4>
  {{range .Events}}{{template "observation" .}}{{end}}
  {{if .EventsOmitted}}<p class="small muted">and {{.EventsOmitted}} more events not shown here; their complete normalized fields and record references are in cited-events.json.</p>{{end}}
 {{if .MissingEvents}}<p class="warn">Evidence incomplete: {{.MissingEvents}} reference(s) could not be resolved in this case. This finding cannot be fully verified from the available events.</p>{{end}}
</div>
{{else}}
<p>No findings were produced.</p>
{{end}}

<h2>6. Correlated activity</h2>
<p>These relationships are deterministic interpretations of the cited observations, not independent evidence or proof of causation. Events follow the correlation's declared order; equal or unknown timestamps do not establish a sequence.</p>
{{range .Correlations}}
<div class="finding">
<h3>{{.Number}} &mdash; {{.Title}}</h3>
<p class="small muted">Type: {{.Type}} &middot; ID: <span class="mono">{{.ID}}</span></p>
<p class="small">Period (UTC): {{if .FirstSeen}}{{.FirstSeen}}{{else}}not recorded{{end}} &ndash; {{if .LastSeen}}{{.LastSeen}}{{else}}not recorded{{end}}</p>
<p>{{.Description}}</p>
<h4>Supporting observations &mdash; {{.EventCount}} reference(s)</h4>
{{range .Events}}{{template "observation" .}}{{end}}
{{if .EventsOmitted}}<p class="small">{{.EventsOmitted}} resolved observation(s) omitted here; see cited-events.json for complete normalized fields and record references. The complete reference list is in correlations.json.</p>{{end}}
{{if .MissingEvents}}<p class="warn">Evidence incomplete: {{.MissingEvents}} reference(s) could not be resolved in this case. This relationship cannot be fully verified from the available events.</p>{{end}}
</div>
{{else}}<p>No correlations were produced. This is not proof that no related activity occurred.</p>{{end}}

<h2>7. Timeline</h2>
<p>
  <strong>{{.Timeline.Total}}</strong> event(s) in total; <strong>{{.Timeline.Dated}}</strong> carry a timestamp and
  <strong>{{.Timeline.Undated}}</strong> record none (they are not placed on the timeline and no time is invented for them).
  {{if .Timeline.Earliest}}Earliest <span class="mono">{{.Timeline.Earliest}}</span>, latest <span class="mono">{{.Timeline.Latest}}</span>.{{end}}
</p>
{{if .Timeline.ByArtifact}}
<h4>Events by artifact</h4>
<table><tr><th>Artifact</th><th class="num">Events</th></tr>
{{range .Timeline.ByArtifact}}<tr><td>{{.Name}}</td><td class="num">{{.N}}</td></tr>{{end}}</table>
{{end}}
{{if .Timeline.ByPeriod}}
<h4>Events per {{.Timeline.PeriodUnit}}</h4>
<table><tr><th>{{.Timeline.PeriodUnit}} (UTC)</th><th class="num">Events</th></tr>
{{range .Timeline.ByPeriod}}<tr><td class="mono">{{.Name}}</td><td class="num">{{.N}}</td></tr>{{end}}</table>
{{end}}
<h4>Key events: events cited by findings and correlations, in time order</h4>
{{if .Timeline.Key}}
{{range .Timeline.Key}}{{template "observation" .}}{{end}}
{{else}}
<p>No event is cited by a finding or correlation.</p>
{{end}}
{{if .Timeline.KeyOmitted}}<p class="small muted">{{.Timeline.KeyOmitted}} further key events are not shown here. Complete cited event fields are in cited-events.json; the whole case's core timeline columns are in timeline.csv.</p>{{end}}

<h2>8. Coverage and limitations</h2>
<h3>What was and was not analyzed</h3>
<p>
  {{.Coverage.Discovered}} file(s) cataloged: {{.Coverage.Supported}} supported, {{.Coverage.Unsupported}} unsupported,
  {{.Coverage.Duplicates}} duplicate(s); {{.Coverage.Imported}} imported; {{.Coverage.ParseFailed}} failed to parse.
  An unsupported file is evidence this tool could not read. It is listed so that it can be examined by other means,
  and its absence from the findings means nothing.
</p>
{{if .Coverage.ByType}}
<table>
  <tr><th>Artifact class</th><th>Family</th><th>Priority</th><th>Parsed by this tool</th><th class="num">Files</th><th class="num">Imported</th><th>Note</th></tr>
  {{range .Coverage.ByType}}
  <tr><td>{{.Type}}</td><td>{{.Family}}</td><td>{{.Priority}}</td><td>{{if .Supported}}yes{{else}}<strong>no</strong>{{end}}</td><td class="num">{{.Files}}</td><td class="num">{{.Imported}}</td><td class="small">{{.Note}}</td></tr>
  {{end}}
</table>
{{end}}
{{if .Coverage.Failed}}
<h4>Files that failed to parse</h4>
<ul class="small mono">{{range .Coverage.Failed}}<li>{{.}}</li>{{end}}</ul>
{{if .Coverage.FailedOmitted}}<p class="small muted">and {{.Coverage.FailedOmitted}} more not shown.</p>{{end}}
{{end}}

<h3>Source-level parser coverage</h3>
<p class="small">A file being imported does not mean every record was mapped. Missing diagnostics mean coverage was not recorded, not that it was complete. Undated observations are retained without inventing a time.</p>
{{if .Coverage.ParserDiagnostics}}<table><tr><th>Source</th><th>Read / mapped / unavailable coverage</th></tr>{{range .Coverage.ParserDiagnostics}}<tr><td class="mono">{{.Key}}</td><td class="wrap">{{.Value}}</td></tr>{{end}}</table>{{else}}<p>No source-level parser diagnostics were recorded.</p>{{end}}
{{if .Coverage.DiagnosticsOmitted}}<p>{{.Coverage.DiagnosticsOmitted}} source diagnostics omitted here; see the case's source-file details.</p>{{end}}
<h3>Case-specific caveats</h3>
{{if .Limitations}}<ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>None beyond those below.</p>{{end}}

<h3>General limitations</h3>
<ul>
  <li>This report is not a legal chain of custody record. It documents technical provenance between stored objects; it does not establish who handled the evidence, under what authority, or the continuity of possession.</li>
  <li>The account shown as having generated this report is a system account name. It has not been verified as an examiner identity.</li>
  <li>A recorded digest shows that two reads of the evidence agree. It is not a third-party timestamp or a signature, and it says nothing about the evidence before ingestion.</li>
  <li>A timestamp is meaningful only with its recorded clock basis. Local readings with an unknown zone and partial dates are preserved without an invented UTC instant. Recorded host time zones and capture-clock estimates are stated separately; original timestamps are not silently corrected.</li>
  <li>Findings are indications produced by fixed rules. A finding may be a false positive, and the absence of a finding is not proof of absence.</li>
  {{if .Narrative.Usable}}<li>A language model drafted the summary in Appendix E, which is labelled as a draft and is not evidence. No other part of this report was produced with one. Every other statement is either fixed text or a value taken from the case data, with one labelled exception: Appendix D quotes what an outside reputation service answered about file hashes, and says so.</li>
  {{else if .Narrative.Requested}}<li>A language model was asked for a summary (Appendix E) and returned nothing usable, so no part of this report was produced with one. Every statement is either fixed text or a value taken from the case data, with one labelled exception: Appendix D quotes what an outside reputation service answered about file hashes, and says so.</li>
  {{else}}<li>No artificial intelligence or large language model was used to produce any part of this report. Every statement is either fixed text or a value taken from the case data, with one labelled exception: Appendix D quotes what an outside reputation service answered about file hashes, and says so.</li>{{end}}
</ul>

<h2>9. Appendices</h2>
<h3>Appendix A &mdash; Attachments and hashes</h3>
<table>
  <tr><th>File</th><th>Description</th><th class="num">Rows</th><th class="num">Bytes</th><th>SHA-256</th></tr>
  {{range .Attachments}}
  <tr><td class="mono nowrap">{{.Name}}</td><td>{{.Description}}</td><td class="num">{{.Rows}}</td><td class="num">{{.Bytes}}</td><td class="mono">{{.SHA256}}</td></tr>
  {{end}}
</table>
<p class="small">The SHA-256 of this report document is recorded in manifest.json, delivered with it. To check a delivered bundle, compute the SHA-256 of each file (for example with <span class="mono">sha256sum</span>) and compare it with manifest.json.</p>

<h3>Appendix B &mdash; Detection rules that fired in this case</h3>
{{range .Rules}}
<h4>{{.Title}} <span class="mono">{{.ID}}</span> &mdash; fired {{.Fired}}&times;</h4>
<p class="small"><strong>Detects:</strong> {{.Detects}}</p>
<p class="small"><strong>Basis:</strong> {{.Basis}}</p>
<p class="small"><strong>Severity range:</strong> {{.Base}} to {{.Max}}{{if .TechList}} &middot; <strong>ATT&amp;CK:</strong> {{.TechList}}{{end}}</p>
{{else}}
<p>No rule fired.</p>
{{end}}

<h3>Appendix C &mdash; Audit trail</h3>
{{if .Audit}}
<table>
  <tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Summary</th></tr>
  {{range .Audit}}<tr><td class="mono nowrap">{{.Time}}</td><td>{{.Actor}}</td><td>{{.Action}}</td><td class="wrap">{{.Summary}}</td></tr>{{end}}
</table>
{{if .AuditOmitted}}<p class="small muted">{{.AuditOmitted}} earlier audit entries are not shown. They remain in the case export.</p>{{end}}
{{else}}
<p>No audit entries.</p>
{{end}}

<h3>Appendix D &mdash; Outside services (not evidence)</h3>
<p class="small"><strong>Egress level of this case when the report was generated:</strong> <span class="mono">{{.External.EgressLevel}}</span>. {{.External.EgressDescription}}</p>
{{with .External.VirusTotal}}
{{if or .Answered .Errors}}
<p>File hashes found in the evidence were looked up on VirusTotal. Only the hashes were sent; no file, file name, path, host, user or case detail left the server. {{.Answered}} hash(es) were answered ({{.Known}} known to VirusTotal, {{.Unknown}} not known){{if .Errors}}; {{.Errors}} could not be answered{{end}}.</p>
<p class="small"><strong>How to read this.</strong> These are the opinions of an outside service at the time shown in the table, about content identified only by its hash. They are not evidence about this case, they did not change any finding or its severity, and they can change tomorrow. &ldquo;Not known&rdquo; means VirusTotal has not been given that file; it does not mean the file is safe. A detection count is a count of engines, not proof of malicious use on this system.</p>
{{if .Rows}}
<table>
  <tr><th>Hash</th><th>VirusTotal answer</th><th>Details</th><th>Seen in events</th><th>Checked (UTC)</th></tr>
  {{range .Rows}}
  <tr><td class="mono wrap">{{.IndicatorType}}<br>{{.Indicator}}</td><td>{{.Verdict}}</td><td class="small wrap">{{if .Label}}Label: {{.Label}}<br>{{end}}{{if .FileType}}Type: {{.FileType}}<br>{{end}}{{if .ReportedName}}Name seen by VirusTotal: {{.ReportedName}}<br>{{end}}{{if .LastAnalysis}}Last analysed: {{.LastAnalysis}}<br>{{end}}{{if .Link}}<span class="mono">{{.Link}}</span>{{end}}</td><td class="mono small wrap">{{.Events}}</td><td class="mono nowrap">{{.CheckedAt}}</td></tr>
  {{end}}
</table>
{{if .Omitted}}<p class="small muted">{{.Omitted}} further answers are not shown (most-detected are listed first).</p>{{end}}
{{end}}
{{else}}
<p>No VirusTotal lookup has been made for this case.</p>
{{end}}
{{end}}

<h3>Appendix E &mdash; Summary drafted by a language model (not evidence)</h3>
{{with .Narrative}}
{{if .Requested}}
<p class="small"><strong>Requested:</strong> {{.RequestedAt}} UTC &middot; <strong>Model:</strong> <span class="mono">{{.Model}}</span> &middot;
  {{if .Local}}<strong>Ran on:</strong> a model on the machine that made this report ({{.Destination}}){{else}}<strong>Sent to:</strong> <span class="mono">{{.Destination}}</span>, another machine{{end}}.
  Names, addresses, identifiers and hashes were replaced by tokens before the facts left, and restored here; secrets were removed. The exact text sent is stored with the case; its SHA-256 is <span class="mono wrap">{{.PayloadSHA256}}</span>.{{if or .PromptTokens .CompletionTokens}} Tokens used: {{.PromptTokens}} in, {{.CompletionTokens}} out.{{end}}</p>
{{if .Stale}}<p><strong>The findings of this case changed after this draft was written.</strong> It describes an earlier state and should be requested again.</p>{{end}}
{{if .Usable}}
<p class="small"><strong>This is a draft written by a language model, not a finding and not evidence.</strong> It was asked to summarise the findings above and to cite, for every sentence, the findings or events it relies on. Each kept sentence was checked mechanically: it cites items that exist, uses only names that were given to the model, and contains no number that is not in the facts it was shown. <strong>Whether a sentence is true was not checked.</strong> Read it against the cited items. The model was shown text taken from the evidence (command lines, descriptions), and such text can try to steer a model; read the draft as you would an unverified summary.</p>
<ol>
  {{range .Sentences}}<li>{{.Text}} <span class="small mono muted">[{{.Cites}}]</span></li>{{end}}
</ol>
{{if .Rejected}}<p class="small muted">{{.Rejected}} line(s) of the model's answer were dropped by validation:{{range .Reasons}} {{.Key}} ({{.Value}});{{end}}</p>{{end}}
{{else}}
<p>The model returned nothing that passed validation{{if .Error}} ({{.Error}}){{end}}, so there is no draft. Case data was sent for this request; the text is stored with the case.</p>
{{end}}
{{else}}
<p>No language-model summary was requested for this case.</p>
{{end}}
{{end}}

<footer>Generated by {{.Meta.ToolName}} {{.Meta.ToolVersion}} on {{.Meta.GeneratedAt}}. Case {{.Meta.CaseID}}.</footer>
</main>
</body>
</html>
`
