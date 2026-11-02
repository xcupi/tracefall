# SRUM table coverage (`srum@1`)

This page lists every SRUM table Tracefall has seen, what each one holds, whether
a row is turned into an event, and what a row does and does not show. It backs
the short section in [evidence-triage.md](evidence-triage.md#system-resource-usage-monitor-srum1).

## The guarantee: SRUM carries no transfer, destination or outcome

SRUM network columns are **interval counters by application, interface or
object**. They are not flows. Nothing in Tracefall states or implies from SRUM
alone that data was uploaded, exfiltrated, sent to a place, received from a party
or that any outcome followed. A destination or an outcome must come from network
evidence (a capture, firewall, proxy or flow log, or an event-log record), never
from SRUM.

How this is held, and where it is tested:

- Every `srum_network_usage`, `srum_network_connection` and `srum_sdp_network`
  event carries `evidence_meaning` and `limitations` (what the counters are and
  that they have no destination, remote address, protocol, port, content or
  direction beyond sent/received, and do not show that data left the host).
  Tests: `TestParse_NetworkEventsStateWhatTheCountersAreAndAreNot`.
- Every SRUM event carries `time_basis` (see Time basis below).
- The report shows `evidence_meaning`, `limitations` and `time_basis` wherever it
  cites one of these events (`internal/api/report_event_details.go`;
  `TestReport_SRUMNetworkEventsCarryTheirLimitsAndNeverWordATransfer`).
- No rule, correlation, investigation, score, narrative or report sentence reads
  a SRUM counter. `internal/srumguard` fails if decision code (`detect`,
  `correlate`, `investigate`, `report`, `narrative`, `attck`, `egress`, `enrich`,
  `gate`, `authseq`, `clockskew`) names a SRUM event type, the SRUM artifact or a
  SRUM counter key; if any source file outside the parser and a short list of
  plumbing files names SRUM; if a case with huge counters produces a finding, a
  non-entity correlation or an investigation that cites them or words a transfer;
  if the narrative packet carries a counter; or if a line of `app.js` that names
  SRUM words a transfer.

### Audit of every consumer of SRUM events

| Consumer | Reads SRUM bytes? | Result |
|---|---|---|
| `internal/detect` (all rules) | No. No rule names a SRUM event type, artifact or counter key. | Nothing to fix. |
| `internal/correlate` | No counter. The *entity* correlation (`entity.go:34`, `entity := e.ProcessName`) groups events by process name across artifact types, so a SRUM row whose application resolved to the same name is listed among them. It reads only the name; its sentence says nothing about traffic. Rows of the SDP table have no process name and never enter it. | Finding recorded, not a bytes consumer; pinned by `TestNoRuleCorrelationOrInvestigationConsumesSRUMNetworkCounters`. No change made (changing detection scope is out of this slice). |
| `internal/investigate` (scoring, summaries) | No. | Nothing to fix. |
| `internal/narrative` | No. The packet reads only an allow-list of `Extra` keys (`logon_type`, `outcome`, `action`). | Pinned by `TestNarrativePacketNeverCarriesSRUMCounters`. |
| `internal/report`, `internal/api/report*.go` | Not the counters. The report shows the limits (above). Process name or path, if any, is the event summary. | Added the limits to the report details. |
| `internal/attck` | No. | Nothing to fix. |
| UI (`internal/web/static/app.js`) | Labels and category only (`srum_network_*` are grouped as `network`, `srum_sdp_network` as `other`). The event detail view lists stored fields, including `evidence_meaning` and `limitations`. | Pinned by `TestUIStringsAboutSRUMStateNoTransfer`. |
| Docs | This page and the SRUM section of `evidence-triage.md`. | Reworded. |

## Time basis

The `TimeStamp` column of every provider table is a JET `DateTime` (ESE column
type 8): an 8-byte little-endian IEEE-754 float64 of days since 1899-12-30 (an
OLE Automation date). Source: libyal esedb-kb, SRUM page,
<https://github.com/libyal/esedb-kb/blob/main/documentation/System%20Resource%20Usage%20Monitor%20%28SRUM%29.asciidoc>
("Contains an OLE Automation date ... value").

- **Zone.** None is stored. The OpenText SRUM parser page says "Timestamps are
  presented as-is without any TZ or DST settings applied"
  (<https://marketplace.opentext.com/cybersecurity/content/srum-database-parser>).
  Tracefall reads the value as UTC; that is a convention, not something checked
  against any host here.
- **What it marks.** The time the SRUM service wrote the record, at the end of an
  aggregation interval. The same OpenText page: "The 'TimeStamp' column represents
  when the record was written, which may be sometime after the activity to which
  it relates took place." Velociraptor
  (<https://docs.velociraptor.app/blog/2019/2019-12-31_digging-into-the-system-resource-usage-monitor-srum-afbadb1a375/>):
  "the Timestamp column actually refers to when the ESE record was written".
  The Chainsaw SRUM write-up
  (<https://github.com/WithSecureLabs/chainsaw/wiki/SRUM-Analysis>) describes a
  Tier1 store updated every 60 seconds and a Tier2 (the database) updated every
  hour by default.
- **Resolution.** Tracefall rounds to the millisecond. In the databases examined
  every `TimeStamp` of every provider table falls on a whole minute
  (0 rows off a minute boundary in 424,057 and 415,921 rows), with one distinct
  minute per hour (8,999 distinct minutes over a 375.0-day span for the SDP
  tables; 1,440 over 60.0 days for the application and connectivity tables).
- **Out of range.** A value that is not a number, is outside the JET range, or
  falls outside 1995..2100 is not used. The event is undated, the stored 8 bytes
  are kept in `timestamp_raw` and in the raw evidence, and the record is counted
  in `undated`. Tested for the SDP table with zero, NaN, 1950 and 2200
  (`TestParse_SDPNetworkOutOfRangeTimeStaysUndatedWithRawBytes`).
- **Not calibrated.** No calibration against the host's real clock, an event
  log, a filesystem timestamp or any other artifact has been performed, and none
  is claimed. Every event says so in `time_basis`.

Agreement with the second decoder (Python `dissect.esedb`, own float64 and epoch
arithmetic): for the three interpreted tables present, the minimum and maximum
time and the count of undated rows are equal, and 500 sampled rows per table
per database have equal times (see Verification).

## Tables seen

Three real `SRUDB.dat` copies were examined. Two have different contents; the
third is byte-identical to the first (same SHA-256), so there are two distinct
databases below ("A" and "B"). Each holds 6 provider tables. The table list and
every row count are equal between Tracefall's reader and dissect.esedb
(0 differences). Both databases were cleanly shut down and had 0 deleted records in
every provider table; the id map of database A had 0 deleted records (database B's
id map was not checked for deleted records).

Public sources for the provider names: the OpenText SRUM parser page (SDP
Volume, Physical Disk, Cpu and Network Provider GUIDs, URL above) and a SRUM
overview that lists the same names
(<https://medium.com/the-first-digit/srum-analyzing-the-user-activity-tracking-in-windows-6e2bcfb07047>:
"{DC3D3B50-...}: SDP CPU", "{EEE2F477-...}: SDP Network", "{841A7317-...}: SDP
Physical Disk", "{17F4D97B-...}: SDP Volume Provider"). Column lists for the four
SDP tables come from the 1234n6 Server 2019 write-up
(<https://blog.1234n6.com/testing-of-srum-on-windows-server-2019-continued/>,
"four new tables ... AutoIncId TimeStamp AppId UserId ...") and were checked
against the databases.

| Table | Provider | Columns (ESE type) | Rows A / B | Interpreted |
|---|---|---|---|---|
| `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` | Application Resource Usage | 19 columns: common four, cycle times and `FaceTime` (Long Long), context switches and operation counts (Long), bytes read/written (Long Long) | 241,649 / 206,750 | yes, `srum_app_usage` |
| `{DD6636C4-8929-4683-974E-22C046A43763}` | Network Connectivity Usage | common four, `InterfaceLuid` (Long Long), `L2ProfileId` (Long), `ConnectedTime` (Long), `ConnectStartTime` (Long Long, FILETIME), `L2ProfileFlags` (Long) | 2,864 / 4,290 | yes, `srum_network_connection` |
| `{EEE2F477-0659-5C47-EF03-6D6BEFD441B3}` | SDP Network Provider | common four, `BytesInBound`, `BytesOutBound`, `BytesTotal` (all Long Long) | 17,998 / 54,006 | **yes, `srum_sdp_network`** (new) |
| `{17F4D97B-F26A-5E79-3A82-90040A47D13D}` | SDP Volume Provider | common four, `Total`, `Used` (Long Long) | 80,773 / 79,938 | no |
| `{841A7317-3805-518B-C2EA-AD224CB4AF84}` | SDP Physical Disk Provider | common four, `SizeInBytes` (Long Long) | 71,774 / 61,936 | no |
| `{DC3D3B50-BB90-5066-FA4E-A5F90DD8B677}` | SDP Cpu Provider | common four, `ProcessorTime` (Long Long) | 8,999 / 9,001 | no |

The common four are `AutoIncId` (Long), `TimeStamp` (DateTime), `AppId` (Long),
`UserId` (Long). `SruDbIdMapTable` holds 166,012 (A) and 55,422 (B) live
records; `SruDbCheckpointTable` holds 0. Neither is a provider table.

Not present in any of the three databases: `{973F5D5C-1D90-4944-BE8E-24B94231A174}`
(Network Data Usage, which `srum_network_usage` reads) and
`{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}` (push notifications). The 1234n6
write-up also reports the Network Usage table absent on Server 2019. So on these
servers a standard per-application network-usage table does not exist, and the
only interpreted per-application-or-object byte counters are in the SDP network
table. An absent table is a fact about the database, not evidence that no
traffic occurred.

Share of the "not interpreted" population in database A (total 424,057 provider
rows): before this slice 179,544 (42.34 %) were in four uninterpreted tables
(the three above plus the SDP network table, 17,998); now 161,546 (38.10 %) are
in the three tables below. Database B (total 415,921): 204,881 (49.26 %) before,
150,875 (36.27 %) now.

### Interpreted: SDP Network Provider `{EEE2F477-0659-5C47-EF03-6D6BEFD441B3}` → `srum_sdp_network`

Decision: INTERPRET. (a) Layout documented by the 1234n6 write-up and by the
ANSSI DFIR-OGRE description, "SDP network telemetry with timestamp and inbound,
outbound, and total byte counters plus application and user identifiers where
recorded ... The counters do not expose endpoints, protocols, payloads, or
individual connections"
(<https://anssi-fr.github.io/dfir-ogre-documentation/built-in-plugins/network/srum_sdp_network>);
the Zimmerman SrumECmd README lists `NetworkBytes` among the tables seen on
Server 2022 and says "What they measure is in `ExeInfo` (for example `Total`, a
volume, a network adapter)"
(<https://github.com/EricZimmerman/Srum/blob/master/README.md>). (b) Every column
read exists in both databases with the documented type. (c) Decoded values equal
the second decoder (see Verification). (d) What a row does and does not show is
stated here and in each event.

What a row is: the three byte counters (`bytes_in_bound`, `bytes_out_bound`,
`bytes_total`, as stored) the SRUM service wrote for one object in an interval
ending at the row time. The object is named by `AppId` through `SruDbIdMapTable`.
In both databases every `AppId` of this table resolves to an id-map entry of
type 4 (a type no cited source documents; libyal lists only types 0 to 3), whose
stored text is shown as `sdp_object` as written and is **never** made a process
name or path. An id the map does not hold stays a number
(`sdp_object_resolved: false`).

What a row does not show:

- a flow, a destination, a remote address, a protocol, a port, content, or any
  direction beyond in/out;
- that the object is a program (public tools describe it as, for example, a
  network adapter; that is not checked here);
- the meaning of `BytesTotal`: in the databases examined it is **not** the sum of
  `BytesInBound` and `BytesOutBound` (0 of 17,998 rows equal the sum in A; in B,
  18,002 of 54,006 rows are zero in all three counters and no non-zero row equals
  the sum), no cited source explains it, so it is shown as stored and never added
  to or compared with the others (stated in `limitations`);
- that the unit is bytes of payload: the Chainsaw write-up says, for the Network
  Data Usage provider, that bytes in/out "include the size of the frames (from
  the layer 2 of the OSI model)"; whether the same holds here is not verified.

Retention differs from the other interpreted tables: the SDP tables span 375.0
days in both databases while the application and connectivity tables span
60.0. Importing the new table therefore moves a case's earliest SRUM time back
(the earliest event time in the examined case moved from a date 60 days before the
latest to one 375 days before it).

### Not interpreted (KEEP-COUNTED)

An uninterpreted table is **not evidence of nothing**. Its rows are counted, the
table is listed in the coverage census and named in the parse notes, and
nothing is read from them.

| Table | Believed to be (cited) | Why not interpreted | Rows A / B |
|---|---|---|---|
| `{17F4D97B-F26A-5E79-3A82-90040A47D13D}` | "SDP Volume Provider" (OpenText page; Medium list). Zimmerman: `TotalUsed` tables measure "for example `Total`, a volume". | The unit of `Total` and `Used` is documented by no source fetched; which volume or what is measured is not documented. In every row `Used` ≤ `Total` (80,773 of 80,773 in A; 79,938 of 79,938 in B), which fits a capacity/used pair but proves no unit. | 80,773 / 79,938 |
| `{841A7317-3805-518B-C2EA-AD224CB4AF84}` | "SDP Physical Disk Provider" (OpenText page). | `SizeInBytes` is named in bytes, but no fetched source says what is sized (capacity, free space, transfer). | 71,774 / 61,936 |
| `{DC3D3B50-BB90-5066-FA4E-A5F90DD8B677}` | "SDP Cpu Provider" (OpenText page). | No source fetched states the unit of `ProcessorTime`. (A SRUM overview that discusses time units says it "did not find resources stating the unit": <https://medium.rebeauty-writing.com/?action=show&id=6e2bcfb07047>; it does not say which column it means.) | 8,999 / 9,001 |

Other tables Tracefall counts when present but did not see in these databases:
App Timeline `{5C8CF1C7-7257-4F13-B223-970EF5939312}`, vfuprov
`{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}`, Energy Usage
`{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` (and the `LT` long-term variant), Energy
Estimation `{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}`, Tagged Energy
`{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}`, SDP Event Log, SDP Performance Counter
(names from the OpenText and Medium pages above). Any table with a `{` name that
is not interpreted is counted the same way.

### Interpreted before this slice (unchanged)

`srum_app_usage`, `srum_network_connection`, `srum_network_usage` and
`srum_push_notification`; see evidence-triage.md. Their events now also carry
`time_basis`, and the two network ones `evidence_meaning` and `limitations`.
`srum_network_usage` and `srum_push_notification` have no table in the databases
examined, so they were not re-verified against real data in this slice.

A table that is known by GUID is read only when the columns it needs are present
with the documented type; this check is new for the SDP table. A table with the
same GUID and another layout is counted, not interpreted, and a note says so
(`TestParse_SDPNetworkWithAnotherSchemaStaysCountedNotInterpreted`). The four
earlier tables keep their previous behaviour.

## Coverage census

The parse stores a census with the source (`parse_coverage`, the same mechanism
the EVTX per-ID census uses): per provider table its GUID, live rows, whether it
was interpreted (and the event type), deleted records, plus the database state
and whether it was cleanly shut down. Source details and the report show
**"N tables, M interpreted, K rows not interpreted"**, for example
`6 tables, 3 interpreted, 161546 rows not interpreted` for database A, with the
database state. If more than 64 tables exist the rest are counted in
`tables_unlisted` and the sentence says its counts are lower bounds. A source
with no census says nothing, and never reads as fully counted. Existing notes are
unchanged.

## How the sources were read

The Chainsaw SRUM write-up and the Zimmerman README were fetched in full. The
1234n6, OpenText, ANSSI DFIR-OGRE, libyal esedb-kb, Velociraptor and Medium
pages were read as search-result excerpts of those URLs (the quoted wording is
what the excerpt showed); they were not re-fetched whole. The Chainsaw page
also says the Network Data Usage table "can be used to prove data exfiltration";
Tracefall does not adopt that claim for any SRUM table.

## Verification performed

All numbers below were seen in tool output in the session that produced this page.

- **Second decoder.** Python `dissect.esedb` 3.18 (venv outside the repository)
  enumerated every table, column and type and read cell values. Tracefall's
  reader and dissect agree on the list of provider tables and on every row count:
  6 tables each, 0 differences, in both databases
  (`TestParse_RealSRUDBAgainstSecondDecoder`, set `TRACEFALL_SRUM_DB` and
  `TRACEFALL_SRUM_ORACLE`).
- **Per-table comparison** (database A / B): application usage 241,649 / 206,750
  events equal rows; connectivity 2,864 / 4,290; SDP network 17,998 / 54,006. For
  each interpreted table the sum of every numeric column, the minimum and maximum
  time and the undated count are equal, and 500 randomly sampled rows per table
  per database (seed fixed) have equal time, every numeric column, ids, resolved
  SID and (SDP) object text: 500 of 500 match, 0 mismatches, for all six
  table/database pairs.
- **End to end.** The compiled binary, with the isolated parser worker, imported
  a staged copy of database A in a disposable data directory: 262,511 events
  (base binary built from the base commit: 244,513; the 17,998 difference is
  exactly the SDP table). Findings, correlations and investigations: 0 / 0 / 0 in
  both, after analysis. Source coverage read through the files API, then again
  after a server restart, is identical and carries the census. `report.html`
  generates and shows the census. The server was stopped and the port confirmed
  closed.
- **Mutations** in a scratch copy: 27 mutations (SDP column mapping, swapped
  units, type check, object-as-process, out-of-range time, deleted rows, census
  fields; limitations text, meaning text, a "calibrated" claim, a rule consuming
  the bytes, a correlation naming SRUM, report details, narrative allow-list, a
  UI string) were all killed by a test.
- **Evidence integrity.** The three source files were hashed before and after;
  all were read from copies.

## NOT verified

- The unit, scope and meaning of `BytesInBound`/`BytesOutBound`/`BytesTotal`
  against real traffic (no capture or interface counters were available), whether
  they include link-layer overhead, and what "in" and "out" are relative to.
- Why `BytesTotal` is not the sum of the other two.
- What a type-4 id-map entry is (shown as stored text; the "network adapter"
  reading is a public tool's example, not checked).
- That the time is UTC, and any relation between the SRUM time and the host's
  real clock (no calibration was performed).
- The meaning and units of the three uninterpreted SDP tables.
- `srum_network_usage` and `srum_push_notification` against real data in this
  slice (no such table in the three databases), and the Windows builds of the
  hosts the databases came from.
- Deleted-record handling on real data: all examined databases have 0 deleted
  records, so that path is verified only on constructed databases.
- SRU log files (`.log`/`.chk`) were not read; a database copied from a running
  system can lack its newest records.
- Resolution of network profile ids to names and of NT device paths to drive
  letters (out of scope).
