// Package artifacts is the single authoritative answer to two questions
// an investigator asks about every file in an evidence collection:
//
//	What kind of artifact is this?
//	How much should I care about it?
//
// It exists because those questions were previously answerable only for
// files a parser happened to recognize. Everything else was cataloged
// with an empty artifact type and no other information -- so a KAPE
// collection or AD1 image containing seven thousand files presented as
// "8 supported, 7,065 unsupported" with no way to tell a Prefetch file
// from a font, and no way to find the six registry hives buried in it.
//
// Two things are deliberately kept separate here:
//
//   - SUPPORT is a fact about Tracefall: does a parser exist? It is
//     derived at runtime from internal/ingest's parser registry, never
//     restated by hand, so it cannot drift from what the code can
//     actually parse.
//   - PRIORITY is a fact about forensics: how much investigative value
//     does this artifact class usually carry? It is a fixed table, and
//     it is INDEPENDENT of support. Raw Prefetch is HIGH priority and
//     unsupported, and saying so is more useful than hiding it --
//     it tells an investigator what Tracefall is not looking at.
//
// The frontend renders this registry; it does not reimplement it. That
// is the point of the package existing rather than a table in app.js.
package artifacts

import (
	"path"
	"sort"
	"strings"

	"tracefall/internal/browsercache"
	"tracefall/internal/model"
	"tracefall/internal/parsers"
)

// Priority is an artifact class's forensic triage value. It describes
// the ARTIFACT, not any finding derived from it, and not whether
// Tracefall can parse it.
type Priority string

// The four levels, and what each one means. These definitions are the
// only thing a new entry in the tables below should be argued against.
//
// A priority describes the ARTIFACT CLASS. It never encodes whether
// Tracefall can parse it: an unsupported artifact keeps the priority its
// forensic value earns, which is precisely what tells an investigator
// what this build is not looking at. Assigning LOW because a parser is
// missing would hide exactly the gap the registry exists to expose.
const (
	// PriorityCritical: can contain highly significant evidence of
	// compromise, execution, persistence, credentials, or core system
	// activity. Losing it usually means losing the case.
	PriorityCritical Priority = "critical"
	// PriorityHigh: highly valuable for reconstructing user and system
	// activity and building an attack timeline.
	PriorityHigh Priority = "high"
	// PriorityMedium: commonly provides useful supporting evidence or
	// important context, but rarely carries an investigation alone.
	PriorityMedium Priority = "medium"
	// PriorityLow: auxiliary, indirect, redundant, or of limited
	// standalone value -- a file whose content is better read from the
	// artifact that describes it, or which records no investigative fact
	// of its own.
	//
	// LOW is a statement about forensic value ONLY. It is never applied
	// because an artifact is unsupported.
	PriorityLow Priority = "low"
	// PriorityUnknown is not a level in the scale above: it is the
	// absence of a classification, used only for a file that matched no
	// rule at all. It is deliberately NOT folded into LOW -- "we have no
	// idea what this is" and "we know what this is and it is of limited
	// value" are different statements, and an investigator triaging a
	// collection needs to tell them apart. It sorts last and is never
	// recommended.
	PriorityUnknown Priority = "unknown"
)

// Levels lists the four real priority levels, most significant first.
// The UI builds its filter vocabulary from this rather than hardcoding
// the set.
func Levels() []Priority {
	return []Priority{PriorityCritical, PriorityHigh, PriorityMedium, PriorityLow}
}

// Rank orders priorities most-important-first, for deterministic sorting.
func (p Priority) Rank() int {
	switch p {
	case PriorityCritical:
		return 0
	case PriorityHigh:
		return 1
	case PriorityMedium:
		return 2
	case PriorityLow:
		return 3
	default:
		return 4
	}
}

// Family groups artifacts the way an investigator thinks about them,
// which is coarser than artifact type: an EvtxECmd CSV and a raw .evtx
// are different artifact types but the same family, and an investigator
// filtering for "Event Log" wants both.
type Family string

const (
	FamilySQLServer     Family = "sql_server"
	FamilyEventLog      Family = "event_log"
	FamilyRegistry      Family = "registry"
	FamilyPrefetch      Family = "prefetch"
	FamilyScheduledTask Family = "scheduled_task"
	FamilyPowerShell    Family = "powershell"
	FamilyShell         Family = "shell"
	FamilyExecution     Family = "execution"
	FamilyFileSystem    Family = "filesystem"
	FamilyBrowser       Family = "browser"
	FamilyMemory        Family = "memory"
	FamilyLog           Family = "log"
	// FamilyNetwork covers artifacts describing connections to remote
	// hosts -- clients' saved servers, transfer history, and the like.
	// Distinct from FamilyLog because these are CONFIGURATION records
	// that name an endpoint, not observations of traffic.
	FamilyNetwork Family = "network"
	// FamilyMedia covers metadata carried inside user documents and
	// media files: EXIF and the embedded location that comes with it.
	// Distinct from FamilyFileSystem because the evidence is the file's
	// CONTENT, not the volume's record of it.
	FamilyMedia Family = "media"
	FamilyOther Family = "other"
)

// FamilyLabels renders a family for display. One place, so the UI never
// invents its own wording.
var FamilyLabels = map[Family]string{
	FamilySQLServer:     "SQL Server",
	FamilyEventLog:      "Event Log",
	FamilyRegistry:      "Registry",
	FamilyPrefetch:      "Prefetch",
	FamilyScheduledTask: "Scheduled Task",
	FamilyPowerShell:    "PowerShell",
	FamilyShell:         "Shell",
	FamilyExecution:     "Execution Artifact",
	FamilyFileSystem:    "File System",
	FamilyBrowser:       "Browser",
	FamilyMemory:        "Memory",
	FamilyLog:           "Application Log",
	FamilyNetwork:       "Network & Transfer",
	FamilyMedia:         "Media & Document Metadata",
	FamilyOther:         "Other",
}

// Capability describes one artifact class Tracefall knows about --
// whether or not it can parse it.
type Capability struct {
	// ArtifactType is the model.Artifact* constant a parser produces, or
	// "" for a class Tracefall recognizes but does not parse.
	ArtifactType string   `json:"artifact_type,omitempty"`
	Label        string   `json:"label"`
	Family       Family   `json:"family"`
	FamilyLabel  string   `json:"family_label"`
	Priority     Priority `json:"priority"`
	// Supported means a parser exists and this file can become evidence.
	Supported bool `json:"supported"`
	// Parser is the parser name@version, when one exists.
	Parser string `json:"parser,omitempty"`
	// Reason explains an unsupported classification in plain language --
	// what Tracefall cannot do, and what it CAN read instead where an
	// alternative exists. Empty for supported artifacts.
	//
	// Kept SHORT. It is rendered in a table column, and an analyst
	// scanning thirty rows needs the distinguishing fact, not the whole
	// capability list -- which lives in ParsedInstead/NotParsed and in
	// docs/evidence-triage.md.
	Reason string `json:"reason,omitempty"`

	// PriorityReason states, in one clause, WHY this artifact class
	// carries the priority it does.
	//
	// It exists because priority is the registry's most consequential
	// judgement and was previously unexplained: an analyst saw "HIGH"
	// with no way to check the reasoning, and no way to notice when it
	// was wrong. It is deliberately about forensic value only -- no
	// rationale here may mention whether a parser exists.
	PriorityReason string `json:"priority_reason,omitempty"`

	// Note qualifies a SUPPORTED classification.
	//
	// Separate from Reason on purpose: Reason answers "why can't you
	// parse this?", Note answers "you parse this, but there is something
	// I should know". A cache container is genuinely supported and
	// genuinely parsed, and is still not an event source -- an analyst
	// who does not learn that from the row will go looking for its
	// events.
	Note string `json:"note,omitempty"`

	// Recognized separates two states that are both "not supported" but
	// mean completely different things to an investigator:
	//
	//	Recognized && !Supported -- Tracefall KNOWS what this artifact is
	//	                            and has no parser for it. NTFS $MFT is
	//	                            the canonical example: identifying it
	//	                            as $MFT and saying the parser does not
	//	                            exist is far more useful than calling
	//	                            it an unknown file.
	//	!Recognized              -- genuinely unidentified. Tracefall has
	//	                            no idea what it is.
	//
	// Collapsing these would tell an analyst that a $MFT and a random
	// .dll are the same kind of gap. They are not.
	Recognized bool `json:"recognized"`

	// ParsedInstead names the artifacts in the SAME family that Tracefall
	// does parse. It exists so an unsupported classification cannot be
	// read as "this whole family is unsupported": a WebCacheV01.dat that
	// Tracefall cannot read says nothing about Chromium History, which it
	// reads fine.
	ParsedInstead []string `json:"parsed_instead,omitempty"`

	// NotParsed enumerates, specifically, what this classification covers
	// -- the counterpart to ParsedInstead. Prose in Reason explains why;
	// these two lists let the UI show the boundary as a boundary rather
	// than asking the analyst to parse a sentence.
	NotParsed []string `json:"not_parsed,omitempty"`
}

// Recommended reports whether this artifact class is worth an
// investigator's attention first: high-value AND actually parseable.
// An unsupported artifact is never recommended -- selecting it would do
// nothing -- but it is still shown, with its real priority.
func (c Capability) Recommended() bool {
	return c.Supported && (c.Priority == PriorityCritical || c.Priority == PriorityHigh)
}

// ---------- supported artifact metadata ----------
//
// Keyed by model.Artifact* constant. Support itself is NOT recorded
// here: it comes from the parser registry. This table only supplies the
// label, family and priority for an artifact type a parser produces, so
// adding a parser for a new artifact type means adding one entry here
// and nothing else. An artifact type with no entry still works -- it
// falls back to a derived label, FamilyOther and PriorityMedium -- so a
// forgotten entry degrades the display rather than breaking discovery.

type typeInfo struct {
	label    string
	family   Family
	priority Priority
	// why is the one-clause justification for priority. See
	// Capability.PriorityReason. Required for every entry: a priority
	// nobody had to justify is a priority nobody can check.
	why string
	// note qualifies a supported class. See Capability.Note.
	note string
}

var supportedTypeInfo = map[string]typeInfo{
	model.ArtifactMSSQLExtendedEvents: {label: "SQL Server Extended Events", family: FamilySQLServer, priority: PriorityHigh, why: "Retains selected XE events, statements and recorded client/session claims.", note: "Native XEL requires a separately deployed offline .NET reader and mandatory network-disabled sandbox. XML/JSONL exports are PARTIAL, not binary equivalents. Selective capture and rollover prevent completeness claims; client host/PID claims are not server host/process identity."},
	model.ArtifactMSSQLAudit:          {label: "SQL Server Audit", family: FamilySQLServer, priority: PriorityHigh, why: "Retains recorded audit actions, principals and permission outcomes.", note: "CSV exports are PARTIAL. Native binary audit is experimental NOT-VERIFIED pending a genuine fixture. Non-login succeeded means permission check, not completed execution. External proprietary reader licensing and deployment remain operator gates."},
	model.ArtifactMSSQLLog:            {label: "SQL Server ERRORLOG", family: FamilySQLServer, priority: PriorityHigh, why: "Records engine messages and explicit login outcomes; local clocks remain unconverted."},
	model.ArtifactSQLAgentLog:         {label: "SQL Server Agent text log", family: FamilySQLServer, priority: PriorityHigh, why: "Records Agent messages, not proof that every configured job ran."},
	model.ArtifactSQLInstance:         {label: "SQL Server instance configuration", family: FamilySQLServer, priority: PriorityHigh, why: "Records instance mapping and startup configuration, not observed execution."},
	model.ArtifactWindowsEventLog: {
		label: "Windows Event Log (EVTX)", family: FamilyEventLog, priority: PriorityCritical,
		why: "Records logons, process creation, service installs and PowerShell activity -- the primary account of what happened on the system.",
	},
	model.ArtifactRegistryHive: {
		label: "Windows Registry Hive", family: FamilyRegistry, priority: PriorityCritical,
		why: "Holds persistence, configuration, execution and account data, and survives the deletion of what it describes.",
	},
	model.ArtifactUserAssist: {
		label: "UserAssist", family: FamilyExecution, priority: PriorityHigh,
		why: "Per-user record of what the shell launched, with a run count and a last-activity time, attributed to one account.",
		note: "Records only launches performed THROUGH Explorer. A program started by a script, service or command line " +
			"leaves no entry, so absence is not evidence of absence -- and presence is not a process-creation record.",
	},
	model.ArtifactShellBags: {
		label: "ShellBags", family: FamilyRegistry, priority: PriorityHigh,
		why: "Reconstructs which folders a user browsed, including removable and network volumes, and survives their deletion.",
		note: "Evidence that Explorer recorded a folder, not that a file was opened or anything was executed. " +
			"The event time is the registry key's last-write time; the shell item's own date fields are local-time " +
			"readings with no timezone and are reported as metadata.",
	},
	model.ArtifactAmcache: {
		label: "Amcache", family: FamilyExecution, priority: PriorityHigh,
		why: "Records a binary's full path, SHA-1, size and publisher, and survives deletion of the binary itself.",
		note: "Windows catalogues a binary here on installation, on inventory scans and on execution alike, so " +
			"an entry is application-presence evidence with strong identifying metadata -- not a process-creation " +
			"record, and the key's write time is not an execution time.",
	},
	model.ArtifactRecentDocs: {
		label: "RecentDocs", family: FamilyRegistry, priority: PriorityHigh,
		why: "Names the documents a user opened through the shell, per file type, in most-recent-first order.",
		note: "The key's last-write time dates only the most recent entry; older entries in the same key were " +
			"added at unrecorded times.",
	},
	model.ArtifactRunMRU: {
		label: "Run dialog (RunMRU)", family: FamilyRegistry, priority: PriorityHigh,
		why:  "Records commands a user typed into the Run dialog -- deliberate, user-attributed intent.",
		note: "Evidence the command was TYPED and accepted, not that it executed successfully.",
	},
	model.ArtifactTypedPaths: {
		label: "TypedPaths", family: FamilyRegistry, priority: PriorityMedium,
		why:  "Records paths a user typed into the Explorer address bar, including UNC and removable locations.",
		note: "Evidence of what was typed. Not that the path was opened, and not that it existed.",
	},
	model.ArtifactOpenSaveMRU: {
		label: "Open/Save dialog (OpenSavePidlMRU)", family: FamilyRegistry, priority: PriorityHigh,
		why:  "Names files a user chose in Open or Save dialogs, including on volumes no longer attached.",
		note: "Evidence a file was chosen in a dialog. For a Save dialog it need not have existed beforehand.",
	},
	model.ArtifactMUICache: {
		label: "MUICache", family: FamilyRegistry, priority: PriorityMedium,
		why: "Names applications the shell has encountered, with their display names and publishers.",
		note: "The shell caches these when it merely enumerates an executable, so this is presence evidence " +
			"and not evidence that the program ran.",
	},
	model.ArtifactSAM: {
		label: "Windows SAM", family: FamilyRegistry, priority: PriorityCritical,
		why: "The machine's local account database: every local account, its RID, its account-control flags and " +
			"its stored logon and password timestamps -- and, when the SYSTEM hive is collected alongside it, " +
			"the account's stored NTLM password hash.",
		note: "Credential EVIDENCE, not activity and not an alert. Every Windows machine has these records, so " +
			"an account carrying a hash is normal and is never treated as a detection. An NTLM hash is a hash: " +
			"it is not a password, it is not reversible into one, and Tracefall does not crack passwords. " +
			"Without the SYSTEM hive the hashes stay encrypted and each account says so rather than being " +
			"reported as having none.",
	},
	model.ArtifactUnsupportedBrowserDB: {
		label: "Browser database (not parsed)", family: FamilyBrowser, priority: PriorityMedium,
		why: "Names which browser database a file is -- cookies, saved logins, favicons, autofill, media " +
			"state -- so an analyst can see it is present and decide whether to examine it with another tool.",
		note: "RECOGNIZED, NOT PARSED. Tracefall extracts no events, timestamps or values from these files. " +
			"They are listed because a browser profile holds many databases and only one of them is history; " +
			"cataloguing the rest as history reported intact evidence as broken.",
	},
	model.ArtifactRegistryTransactionLog: {
		label: "Registry transaction log", family: FamilyRegistry, priority: PriorityLow,
		why: "Holds the registry changes a hive was missing when it was copied while Windows was running, so it decides " +
			"how complete the registry evidence is.",
		note: "USED WITH ITS HIVE, NOT PARSED ON ITS OWN. When the hive beside it was not cleanly written, a log of " +
			"the Windows 8.1 and later format is replayed over the hive in memory, and only if it connects to the " +
			"hive without a gap; the older format is not replayed. The log produces no events of its own and is " +
			"never treated as a hive or reported as a broken one. Nothing is written to either file.",
	},
	model.ArtifactActivitiesCache: {
		label: "Windows Timeline (ActivitiesCache)", family: FamilyExecution, priority: PriorityHigh,
		why: "Records applications and documents a user focused, with start and end times and device context.",
		note: "An activity record is not a process-creation record; it says the Activities provider logged " +
			"application or document focus.",
	},
	model.ArtifactBrowserDownload: {
		label: "Browser download", family: FamilyBrowser, priority: PriorityHigh,
		why: "Records a file arriving on the machine from a named URL, with its local path and state.",
		note: "Downloaded is not opened and is not executed. Corroboration from Prefetch, Amcache or a " +
			"process-creation record is what establishes those.",
	},
	model.ArtifactFileZillaServer: {
		label: "FileZilla server entry", family: FamilyNetwork, priority: PriorityHigh,
		why: "Names a remote host, port, protocol and username an FTP client on this machine was configured " +
			"for -- an exfiltration or staging destination, recorded in the user's own profile and surviving " +
			"long after the transfer it was used for.",
		note: "CONFIGURATION evidence, and it records no time. A recentservers.xml entry says a connection " +
			"was ATTEMPTED from this profile; a Site Manager entry says only that a site was saved. Neither " +
			"is evidence that a connection succeeded, that anyone authenticated, or that a file moved. " +
			"Stored passwords are never extracted -- only their presence is reported.",
	},
	model.ArtifactMemoryAnalysis: {
		label: "Memory Analysis", family: FamilyMemory, priority: PriorityHigh,
		why: "Memory holds what disk and logs do not: processes unlinked from the process list, command lines, " +
			"live sockets and code injected into running processes.",
		note: "A SNAPSHOT of one instant, produced by Volatility 3. Processes and sockets that record their own " +
			"creation time sit at that time; everything else is dated to the system clock in the image and marked " +
			"memory_snapshot -- present when captured, not proof of when it began. A hidden-process flag and a " +
			"malfind hit are heuristics: JIT-compiled code legitimately produces the latter.",
	},
	model.ArtifactImageMetadata: {
		label: "Image metadata (EXIF)", family: FamilyMedia, priority: PriorityMedium,
		why: "Records the device and software that produced an image and when the exposure was taken, which " +
			"dates and attributes a file independently of the filesystem times that a copy resets.",
		note: "EXIF is ordinary file CONTENT: a camera writes it and so does any editor, exporter or forger " +
			"downstream. Make and Model name the device the metadata CLAIMS produced the image -- not proof " +
			"of which device did, and nothing at all about who owned it. Not evidence the image was opened " +
			"or viewed on this machine.",
	},
	model.ArtifactImageGPS: {
		label: "Image location (EXIF GPS)", family: FamilyMedia, priority: PriorityHigh,
		why: "Places an image at a coordinate, which can put a device -- or the file's origin -- somewhere " +
			"no other artifact on the machine mentions.",
		note: "The coordinate is what the image RECORDS, not a position Tracefall observed: metadata travels " +
			"with a copied file and can be edited or fabricated. Any country shown is DERIVED from the " +
			"coordinate by an offline boundary lookup and is not stored in the image.",
	},
	model.ArtifactRegistryRunKey: {
		label: "Registry (RECmd export)", family: FamilyRegistry, priority: PriorityHigh,
		why: "Autostart entries are a first-choice persistence mechanism and name the program that runs.",
	},
	model.ArtifactScheduledTask: {
		label: "Scheduled Task XML", family: FamilyScheduledTask, priority: PriorityHigh,
		why: "A scheduled task names a program, a trigger and an account: persistence with an execution schedule attached.",
	},
	model.ArtifactPrefetch: {
		label: "Prefetch", family: FamilyPrefetch, priority: PriorityHigh,
		why: "Proves a program ran, when, and how often, including programs since deleted.",
	},
	model.ArtifactBashHistory: {
		label: "Bash history", family: FamilyShell, priority: PriorityHigh,
		why: "Records the commands a user typed on a POSIX host, which often survive after logs are rotated or cleared.",
	},
	model.ArtifactJournal: {
		label: "Systemd journal", family: FamilyLog, priority: PriorityMedium,
		why: "The structured log of every service on a systemd host, with real timestamps. Large, so it is importable but not auto-selected.",
	},
	model.ArtifactSyslog: {
		label: "System log (syslog)", family: FamilyLog, priority: PriorityHigh,
		why: "Records the scheduled jobs cron started and the service warnings a daemon wrote -- for example a database running with an unprotected administrator account.",
	},
	model.ArtifactNetworkCapture: {
		label: "Network capture (pcap)", family: FamilyNetwork, priority: PriorityHigh,
		why: "Records who talked to whom and when, every name looked up, every HTTP object that crossed the wire with its hash, Remote Desktop connections, and the clocks of the machines involved.",
	},
	model.ArtifactWebAccessLog: {
		label: "Web server access log", family: FamilyLog, priority: PriorityHigh,
		why: "Records every request a web server answered, with the source address, URL, status and client -- the trail of web attacks and web-shell use.",
	},
	model.ArtifactCryptnetURLCache: {
		label: "CryptoAPI URL cache (CryptnetUrlCache)", family: FamilyExecution, priority: PriorityHigh,
		why:  "Records URLs Windows retrieved and cached, with the time, size and ETag, and the cached object itself. certutil -urlcache -f leaves its download here.",
		note: "An entry shows that a URL was retrieved and when. It does not name the program that asked: almost every entry in an ordinary system is Windows validating certificates (revocation lists, OCSP, trust lists). The Content folder is read only to report what the cached object is and its hash.",
	},
	model.ArtifactDefenderCmdLog: {
		label: "Defender command-line log (MpCmdRun.log)", family: FamilyExecution, priority: PriorityHigh,
		why:  "Records each run of MpCmdRun.exe with its command line. MpCmdRun.exe -DownloadFile can fetch a file with a signed Microsoft binary.",
		note: "Times are the machine's local time with no zone, so a run has no instant unless the collection's SYSTEM hive records the zone (then a UTC reading is derived with one fixed offset). Only English day and month names are read. MPLog and MPDetection are read by their own parser (Defender antimalware support log).",
	},
	model.ArtifactDefenderHistory: {
		label: "Defender detection history", family: FamilyLog, priority: PriorityHigh,
		why:  "Retained stateful Defender detection observations with byte-derived identity and original FILETIMEs.",
		note: "Strict modern Magic.Version:1.2 subset only; unsupported or incomplete records fail atomically. One observation is not a sequence of executions. Sensitive literal resources and nested values remain in private raw evidence, not default event projections. Unknown status/action bits imply no execution or remediation success.",
	},
	model.ArtifactDefenderMPLog: {
		label: "Defender antimalware support log (MPLog / MPDetection)", family: FamilyLog, priority: PriorityHigh,
		why:  "The engine's own log of detections and blocked process creations, often retained when the Operational event log has rolled over. A 'Process creation blocked' line states that real-time protection stopped a process, which no other log records.",
		note: "Selective reader: only 'Process creation blocked' lines and DETECTIONEVENT lines are read; every other line (the great majority) is skipped by design and counted. Line prefix times carry no zone and are kept as written, so these events are undated. A blocked creation is not a process start. DetectionHistory binary files have their own strict parser; other Defender text logs are not read.",
	},
	model.ArtifactSRUM: {
		label: "System Resource Usage Monitor (SRUM)", family: FamilyExecution, priority: PriorityHigh,
		why:  "Windows records, about once an hour, what each application and service used: CPU cycles, foreground time, disk I/O and bytes sent and received per network interface. It shows that a program ran and how much data it moved, including programs that left no other trace.",
		note: "A row shows an application was active and what it used in the interval ending at the row's time; it does not show what it did, and the interval is not the moment of any single action. Applications and users are named by the database's own id map; an id with no map entry is shown as an id. Only the application resource, network usage, network connectivity and push notification tables are interpreted; the other tables are counted and named. A database copied from a running system can lack the newest records, which are still in the SRU log files.",
	},
	model.ArtifactWebCache: {
		label: "IE / Edge Legacy web cache (WebCache)", family: FamilyBrowser, priority: PriorityMedium,
		why:  "Internet Explorer and Edge Legacy keep browsing history and a cache index in one ESE database: the URLs visited, when they were last accessed, how often, and the resources cached.",
		note: "A history record is one URL with its last access time and an access count, not one record per visit. A cache record shows that a copy was held, not that the user chose to load it. Cookie containers are deliberately not read. The History and cache containers are interpreted; every other container (DOM storage, background transfer, ...) is counted and named in the parse notes.",
	},
	model.ArtifactIISLog: {
		label: "IIS web log (W3C)", family: FamilyLog, priority: PriorityHigh,
		why:  "Records every request IIS answered, with the source address, URL, query, user and status -- the trail of web exploitation and web-shell use on a Windows server.",
		note: "Only the site logs (u_ex*.log) are read. FTP site logs and HTTP.sys error logs under the same folders are not. Times are UTC. A line shows the status IIS returned, not what the request did on the server.",
	},
	model.ArtifactContainerLog: {
		label: "Container log (Docker json-file)", family: FamilyLog, priority: PriorityHigh,
		why:  "Records what the application inside a container wrote to stdout and stderr, with the engine's own UTC time. Without this, activity in a container is invisible to the host logs.",
		note: "Only the json-file log driver is read. Only what the container printed is here; a process that wrote nowhere the engine captured leaves nothing. Windows-container paths are built from the documented format and not verified.",
	},
	model.ArtifactContainerConfig: {
		label: "Container configuration (Docker)", family: FamilyLog, priority: PriorityHigh,
		why:  "Records the image, command, mounts, published ports and the privileges a container was started with: what could reach the host, and what secrets sit in its environment (names only).",
		note: "A snapshot of configuration, not of what ran. Environment values are never shown.",
	},
	model.ArtifactGrafanaLog: {
		label: "Grafana log", family: FamilyLog, priority: PriorityHigh,
		why:  "Records the requests Grafana chose to log, with status and client address: login failures, probing and API use against the dashboard.",
		note: "The default log is thin: a failed login is an anonymous 401 and does not name the account tried, and many successful actions are not logged at all.",
	},
	model.ArtifactGrafanaDB: {
		label: "Grafana database", family: FamilyLog, priority: PriorityHigh,
		why:  "Holds the users, service-account tokens, data sources (with stored credentials, never shown) and recent login attempts: the durable record when the log is thin.",
		note: "Shows what Grafana stored, not who caused it. Login attempts cover only existing accounts and are pruned. Secrets are never read.",
	},
	model.ArtifactPackageLog: {
		label: "Package log (dpkg)", family: FamilyLog, priority: PriorityMedium,
		why: "Records which packages were installed, upgraded or removed, which dates a tool or service arriving on a host.",
	},
	model.ArtifactAuthLog: {
		label: "Authentication log (auth.log)", family: FamilyLog, priority: PriorityHigh,
		why: "Records su and sudo privilege changes, the commands sudo authorised, SSH logons with their source addresses, and account and group changes.",
	},
	model.ArtifactWtmp: {
		label: "Login records (wtmp)", family: FamilyLog, priority: PriorityHigh,
		why: "Records when accounts logged in and out and the terminal or remote host used, with epoch timestamps.",
	},
	model.ArtifactPowerShellHistory: {
		label: "PowerShell console history", family: FamilyPowerShell, priority: PriorityHigh,
		why: "Records the commands an operator actually typed, often verbatim and often after the event log was cleared.",
	},
	model.ArtifactBrowserHistory: {
		label: "Browser history (Chromium / Firefox)", family: FamilyBrowser, priority: PriorityMedium,
		why: "Establishes what a user navigated to and when -- strong supporting evidence for delivery and download activity.",
	},
	// MEDIUM, and that is load-bearing rather than a shrug. Recommended()
	// selects supported artifacts of critical or high priority, so a
	// medium-priority cache entry is importable but never swept up
	// automatically. A single browser cache holds tens of thousands of
	// entry files; "Select recommended" pulling all of them in would make
	// the selection unusable, which is exactly what the evidence-
	// selection requirement warns against.
	// Label deliberately short. WHICH cache format an entry came from is
	// on every event and every raw record as cache_format_name; repeating
	// the four supported formats on every catalog row would crowd out
	// the thing the row exists to say.
	model.ArtifactBrowserCache: {
		label:  "Browser cache entry",
		family: FamilyBrowser, priority: PriorityMedium,
		why: "Shows resources the browser received and stored; corroborates activity but does not by itself establish user intent.",
	},
	// A cache CONTAINER: an index or map. Genuinely parsed -- entry
	// counts, cache size, a creation time -- so genuinely supported, and
	// carrying a Note because it is not an event source.
	model.ArtifactBrowserCacheIndex: {
		label:  "Browser cache container/index",
		family: FamilyBrowser, priority: PriorityMedium,
		why:  "Describes a cache as a whole -- entry count, size, creation time -- which dates and sizes the browsing evidence beside it.",
		note: "Container/index: parsed for the cache's own metadata (entry count, size, creation time). Not an event source -- the cached resources are in the associated entry files.",
	},
	// HIGH: a shortcut often preserves the only surviving description of
	// a file that has been deleted. The priority reflects that value and
	// does not change when a particular shortcut happens to omit an
	// optional structure -- a .lnk with no LinkInfo still carries a
	// target path and three timestamps.
	model.ArtifactLNK: {
		label: "Windows LNK shortcut", family: FamilyFileSystem, priority: PriorityHigh,
		why: "Preserves a referenced target's path, volume and timestamps, often after the target itself is gone.",
		note: "Shortcut metadata can preserve the referenced target path, volume information and target timestamps " +
			"even when the target is no longer present. LNK metadata alone does not prove execution.",
	},
	// MEDIUM, unchanged from when this was unsupported. Gaining a parser
	// does not change what an artifact is worth: the $R file is still
	// content whose identity lives in the paired $I record, and the $I
	// record is still the half that carries the forensic facts. What
	// changed is that the content can now be measured and hashed.
	// HIGH. A Jump List ties an application to the files a user reached
	// through it, with a per-entry access count and, for automatic
	// lists, the application's own last-access time -- application and
	// target attribution over a long history, which is squarely "highly
	// valuable for reconstructing user activity".
	model.ArtifactJumpListAutomatic: {
		label: "Windows Jump List (Automatic Destinations)", family: FamilyExecution, priority: PriorityHigh,
		why: "Ties an application to the files a user reached through it, with an access count and the application's own last-access time per item.",
		note: "Embedded shortcuts are decoded by the same parser that reads standalone .lnk files. A Jump List entry " +
			"shows that an application holds a reference to a target -- it is not proof the target was executed.",
	},
	model.ArtifactJumpListCustom: {
		label: "Windows Jump List (Custom Destinations)", family: FamilyExecution, priority: PriorityHigh,
		why: "An application's own task and pinned entries, tying it to the targets it offers or has been given.",
		note: "A different container from an Automatic Destinations list: concatenated shortcuts with no DestList, " +
			"so it records no access times, access counts or most-recently-used order.",
	},
	model.ArtifactRecycleBinContent: {
		// Kept distinct from "Recycle Bin" and named for what it is: the
		// $R half is SUPPORTING evidence for an $I record, produces no
		// events of its own, and must never read as a second kind of
		// deletion artifact.
		label: "Recycle Bin content ($R)", family: FamilyFileSystem, priority: PriorityMedium,
		why: "The deleted file's content. What it was and when it was deleted is in the paired $I record, not here.",
		note: "The recovered content of a deleted file. Its original path, name and deletion time are read from " +
			"the paired $I record; its size and SHA-256 are measured from this file. Produces no timeline events -- " +
			"the deletion itself is timestamped by the $I record.",
	},
	model.ArtifactRecycleBin: {
		// "Recycle Bin", not "Windows Recycle Bin $I metadata". This is the
		// label an analyst picks out of the Timeline's Artifact filter,
		// and it has to be the name they are looking for. The $I detail
		// belongs on the event -- where record_version, the paired $R
		// status and the original path already are -- not in a filter
		// option that then fails to match what anyone would search for.
		label: "Recycle Bin", family: FamilyFileSystem, priority: PriorityHigh,
		why: "Names a deleted file's original full path, its size and the moment of deletion -- deletion evidence with attribution.",
		note: "Recycle Bin metadata records the deleted file's original path, size and deletion time. " +
			"The $R file contains the deleted content when it is still available.",
	},
	model.ArtifactMFT: {
		label: "NTFS $MFT", family: FamilyFileSystem, priority: PriorityHigh,
		why: "A record for every file on the volume, with four timestamps each, including files that were deleted.",
	},
	model.ArtifactUsnJournal: {
		label: "NTFS $UsnJrnl change journal", family: FamilyFileSystem, priority: PriorityHigh,
		why: "A historical log of filesystem change, recovering creation and deletion the current $MFT no longer shows.",
	},
	// $LogFile is MEDIUM, not HIGH, and deliberately so. It is parsed
	// and validated, but it yields transaction metadata rather than
	// timeline events (see internal/parsers/logfile), so recommending it
	// as urgently as the $MFT or the journal would overstate what an
	// analyst gets from importing it.
	model.ArtifactLogFile: {
		label: "NTFS $LogFile transaction log", family: FamilyFileSystem, priority: PriorityMedium,
		why: "Transaction metadata that contextualises filesystem activity; it yields no timeline events of its own.",
	},
}

// ---------- recognition-only classes ----------
//
// Keyed by the model.Artifact* recognition constants that DISCOVERY
// assigns from a file's own bytes when no parser claimed it (see
// ingest.recognizeUnparsed). No parser produces these, and nothing here
// is ever Supported -- recognizing a file is not the same as being able
// to parse it.
//
// They exist because a browser cache is a small filesystem of its own.
// Rankings, payload blocks, journals, locks and raw bodies are not
// broken evidence and not parse failures: they are files whose useful
// metadata lives in the entry record that addresses them, or which carry
// no forensic metadata at all. One message for all of them would say
// nothing; these say which is which, in one line each.
//
// Priority follows what the file could yield, not what family it is in:
// auxiliary and bookkeeping files are LOW, an unknown file in a cache
// directory is LOW, and a recognized structure in an unsupported variant
// is MEDIUM because it may still hold recoverable data.
var recognizedTypeInfo = map[string]unsupportedRule{
	model.ArtifactBrowserCacheRankings: {
		label:     "Chromium blockfile auxiliary file",
		family:    FamilyBrowser,
		priority:  PriorityLow,
		why:       "Records use times but no cache key, so nothing in it can be attributed to a URL.",
		reason:    "Chromium blockfile auxiliary file (data_0). Ranking/index data is not independently parsed.",
		notParsed: []string{"Chromium blockfile rankings (data_0): use times, but no cache key"},
	},
	model.ArtifactBrowserCachePayload: {
		label:     "Chromium blockfile payload file",
		family:    FamilyBrowser,
		priority:  PriorityLow,
		why:       "Holds stream content only; the metadata describing it is in the entry record that addresses it.",
		reason:    "Chromium blockfile auxiliary payload file (data_2/data_3). Cache metadata is stored in the associated data_1 entry records.",
		notParsed: []string{"Chromium blockfile payload blocks (data_2 / data_3)"},
	},
	model.ArtifactBrowserCacheBody: {
		label:     "Chromium cached response body",
		family:    FamilyBrowser,
		priority:  PriorityLow,
		why:       "A response body with no key, time or headers -- the entry record that names it carries all of those.",
		reason:    "Cached response body (f_######). Its metadata is stored in the associated data_1 entry record.",
		notParsed: []string{"Cached response bodies (Tracefall reads cache metadata only)"},
	},
	model.ArtifactBrowserCacheAuxiliary: {
		label:    "Browser cache auxiliary file",
		family:   FamilyBrowser,
		priority: PriorityLow,
		why:      "Cache bookkeeping whose useful metadata lives in the entry records that address it.",
		reason:   "Browser-cache auxiliary file. Its metadata is stored in the associated cache entry records.",
		notParsed: []string{
			"Cache structures whose metadata lives in the entry records that address them",
		},
	},
	model.ArtifactBrowserCacheState: {
		label:    "Browser cache journal/state",
		family:   FamilyBrowser,
		priority: PriorityLow,
		why:      "A cache's own housekeeping. It records no cached resource and no user activity.",
		reason:   "Browser-cache journal/state file. No independently parsed cache-entry metadata.",
		notParsed: []string{
			"Cache journals, lock files and temporary indexes",
		},
	},
	model.ArtifactBrowserCacheVariant: {
		label:    "Browser cache unsupported format",
		family:   FamilyBrowser,
		priority: PriorityMedium,
		why:      "A cache structure Tracefall reads in a version it does not: it may still hold recoverable URLs and timestamps.",
		reason:   "Recognized browser-cache format, but this version or variant is not supported.",
		notParsed: []string{
			"Browser-cache structures in a version or state this build does not decode",
		},
	},
	model.ArtifactBrowserCacheUnknown: {
		label:    "Browser cache unknown",
		family:   FamilyBrowser,
		priority: PriorityLow,
		why:      "Unidentified, but inside a browser cache -- worth an analyst's glance even though nothing is known about it.",
		reason:   "File is located in a browser-cache directory, but its format could not be identified.",
		notParsed: []string{
			"Files in a browser cache whose format structural detection could not identify",
		},
	},
}

// ---------- recognized-but-unparsed artifact classes ----------
//
// These are the artifacts a DFIR analyst expects to find in a triage
// collection and would want to know about even though Tracefall has no
// parser for them. Each carries an honest reason.
//
// Matching is by path/filename only: these files are never opened during
// discovery, because discovery walks every file in a collection and must
// stay cheap. Content sniffing is reserved for the parsers that actually
// claim a file (see parsers.ContentDetector).

// browserParsedInstead is the browser evidence Tracefall DOES parse,
// attached to every unsupported browser classification so the gap is
// never mistaken for the whole family. Kept as one variable because
// these three rules must never drift apart from each other.
//
// This list describes internal/parsers/browserhistory and is not a
// promise of future support; nothing here adds a parser.
var browserParsedInstead = []string{
	"Chromium History (Chrome, Edge, Brave, Opera, Vivaldi)",
	"Firefox History (places.sqlite)",
	"Chromium Simple Cache entries (cache metadata)",
	"Chromium blockfile cache data_1 entries (cache metadata)",
	"Chromium blockfile cache index (container metadata)",
	"Firefox cache2 entries (cache metadata)",
	"Firefox cache1 _CACHE_00x_ entries (cache metadata)",
	"Firefox cache1 _CACHE_MAP_ (container metadata)",
}

type unsupportedRule struct {
	label    string
	family   Family
	priority Priority
	// why is the one-clause justification for priority, exactly as for a
	// supported class -- and written to the same standard, because an
	// unsupported artifact's priority is the more consequential of the
	// two: it is what tells an investigator what is being missed.
	why    string
	reason string
	// parsedInstead / notParsed populate the Capability fields of the
	// same name. See Capability for why the boundary is expressed as two
	// lists and not only as prose.
	parsedInstead []string
	notParsed     []string
	// match reports whether a lower-cased forward-slash relative path is
	// this artifact class.
	match func(lowerPath, lowerBase string) bool
}

// hasExt matches any of the given extensions. Variadic because several
// artifact classes are one class written with more than one suffix -- a
// crash dump is a crash dump whether it is .dmp, .mdmp or .hdmp.
func hasExt(exts ...string) func(string, string) bool {
	return func(_, base string) bool {
		for _, e := range exts {
			if strings.HasSuffix(base, e) {
				return true
			}
		}
		return false
	}
}

func baseIs(names ...string) func(string, string) bool {
	set := map[string]bool{}
	for _, n := range names {
		set[strings.ToLower(n)] = true
	}
	return func(_, base string) bool { return set[base] }
}

// matchBlockfileExternalBody matches a Chromium blockfile external body
// file: f_ followed by exactly six hexadecimal digits, and nothing else.
// The strict shape matters -- "f_report.txt" is not one.
func matchBlockfileExternalBody(p, base string) bool {
	if !browsercache.InCacheDirectory("/" + p) {
		return false
	}
	if len(base) != 8 || !strings.HasPrefix(base, "f_") {
		return false
	}
	for _, c := range base[2:] {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// matchCacheHashIndex matches the cache indexes that store key hashes
// rather than keys. Confined to a cache directory so an unrelated file
// called "index" elsewhere in a collection is never claimed.
func matchCacheHashIndex(p, base string) bool {
	if !browsercache.InCacheDirectory("/" + p) {
		return false
	}
	switch base {
	case "index", "the-real-index", "index-dir":
		return true
	}
	return false
}

// matchCacheStateFile matches a cache's own bookkeeping files by their
// exact names, and only inside a cache directory. Exact names because
// these formats define them; confined to a cache directory because
// "journal" and "LOCK" are far too common to claim anywhere else.
func matchCacheStateFile(p, base string) bool {
	if !browsercache.InCacheDirectory("/" + p) {
		return false
	}
	switch base {
	case "lock", ".lock", "parent.lock", "journal", "index.log", "index.tmp",
		"temp-index", "index-dir", "context.tmp", "cache_dir_lock":
		return true
	}
	return false
}

// matchInCacheDirectory is the locator for the generic cache fallback.
func matchInCacheDirectory(p, _ string) bool {
	return browsercache.InCacheDirectory("/" + p)
}

// matchProcessDump matches a process memory dump by name. LSASS is
// called out because a dump of it is credential material, but any
// "<process>.dmp" under a dump-collection path is the same class of
// artifact.
func matchProcessDump(p, base string) bool {
	if strings.HasPrefix(base, "lsass") && strings.HasSuffix(base, ".dmp") {
		return true
	}
	return strings.HasSuffix(base, ".dmp") &&
		(strings.Contains(p, "/procdump/") || strings.Contains(p, "/dumps/") || strings.Contains(p, "/crashdumps/"))
}

// matchPowerShellTranscript matches PowerShell's session transcripts,
// which are named for their start time by the transcription policy.
func matchPowerShellTranscript(_, base string) bool {
	return strings.HasPrefix(base, "powershell_transcript") && strings.HasSuffix(base, ".txt")
}

// matchSetupAPILog matches the device-install logs that record when a
// removable device was first attached.
func matchSetupAPILog(_, base string) bool {
	return strings.HasPrefix(base, "setupapi.") && strings.HasSuffix(base, ".log")
}

// matchDefenderLog matches Microsoft Defender's detection and protection
// logs. Confined to a Defender path so an unrelated MPLog is not claimed.
func matchDefenderLog(p, base string) bool {
	if strings.Contains(p, "windows defender") || strings.Contains(p, "/defender/") {
		return strings.HasSuffix(base, ".log")
	}
	return strings.HasPrefix(base, "mplog-") && strings.HasSuffix(base, ".log")
}

// matchWebServerLog matches IIS/W3C extended log files, which are named
// u_exYYMMDD.log (or u_inYYMMDD / u_ncYYMMDD) or live under LogFiles.
func matchWebServerLog(p, base string) bool {
	if !strings.HasSuffix(base, ".log") {
		return false
	}
	for _, prefix := range []string{"u_ex", "u_in", "u_nc", "u_ev"} {
		if strings.HasPrefix(base, prefix) {
			return true
		}
	}
	return strings.Contains(p, "/inetpub/logs/") || strings.Contains(p, "/logfiles/w3svc")
}

// matchThumbcache matches the per-size thumbnail cache databases.
func matchThumbcache(_, base string) bool {
	return (strings.HasPrefix(base, "thumbcache_") || strings.HasPrefix(base, "iconcache_")) &&
		strings.HasSuffix(base, ".db")
}

// matchRDPCache matches the outbound RDP client's bitmap cache.
func matchRDPCache(p, base string) bool {
	if strings.HasPrefix(base, "bcache") && strings.HasSuffix(base, ".bmc") {
		return true
	}
	return strings.Contains(p, "/terminal server client/cache/") && strings.HasSuffix(base, ".bin")
}

// matchHostsFile matches the static name-resolution files, which have no
// extension and must therefore be anchored to their directory.
func matchHostsFile(p, base string) bool {
	if !strings.Contains(p, "/etc/") {
		return false
	}
	switch base {
	case "hosts", "lmhosts", "lmhosts.sam", "networks", "protocol", "services":
		return true
	}
	return false
}

func pathContains(fragments ...string) func(string, string) bool {
	return func(p, _ string) bool {
		for _, f := range fragments {
			if strings.Contains(p, f) {
				return true
			}
		}
		return false
	}
}

// unsupportedRules is ordered: the first match wins, so specific rules
// precede general ones.
var unsupportedRules = []unsupportedRule{
	// ---- credential and persistence stores ----
	//
	// CRITICAL by the level's own definition: an artifact that can carry
	// credentials or a persistence mechanism. That none of these has a
	// parser is exactly why their priority matters -- a HIGH or CRITICAL
	// row Tracefall cannot read is the most useful thing this screen can
	// tell an investigator.
	{
		label: "Process memory dump (LSASS or similar)", family: FamilyMemory, priority: PriorityCritical,
		why:    "A process memory dump of LSASS carries credential material directly; of any process, its decrypted runtime state.",
		reason: "Tracefall performs no memory analysis. The dump is cataloged and hashed, not read.",
		match:  matchProcessDump,
	},
	{
		label: "WMI repository", family: FamilyExecution, priority: PriorityCritical,
		why:    "Holds WMI event subscriptions, a fileless persistence mechanism that survives reboot and leaves little else behind.",
		reason: "Tracefall has no WMI repository parser. OBJECTS.DATA and its indexes are not decoded.",
		match:  baseIs("objects.data", "index.btr", "mapping1.map", "mapping2.map", "mapping3.map"),
	},

	// ---- execution and user-activity artifacts ----
	{
		label: "SRUM database", family: FamilyExecution, priority: PriorityHigh,
		why:    "Per-application network and resource usage over 30-60 days: what ran, and how much data it moved.",
		reason: "A file named SRUDB.dat is read as the System Resource Usage Monitor database only when it starts with the ESE database header; this one does not, so it is not read.",
		match:  baseIs("srudb.dat"),
	},
	{
		// $MFT, $UsnJrnl and $LogFile are all PARSED now, so none of them
		// appears here. What remains are the NTFS metafiles Tracefall
		// genuinely does not read -- claiming them because the other
		// three work would be a fabricated capability.
		label: "NTFS volume metadata (other metafiles)", family: FamilyFileSystem, priority: PriorityMedium,
		why:    "Volume-level structures that contextualise filesystem evidence without recording activity of their own.",
		reason: "Tracefall reads the NTFS $MFT, $UsnJrnl change journal and $LogFile. The remaining NTFS metafiles -- $Secure (security descriptors), $Bitmap (cluster allocation), $Quota, $ObjId and $Reparse -- are separate structures with their own formats and are not parsed.",
		parsedInstead: []string{
			"NTFS $MFT (master file table) -- file metadata and MACB timestamps",
			"NTFS $UsnJrnl:$J change journal -- historical file change records",
			"NTFS $LogFile -- validated transaction metadata (no timeline events; see the notes)",
		},
		notParsed: []string{
			"$Secure (security descriptor store)",
			"$Bitmap (cluster allocation map)",
			"$Quota, $ObjId, $Reparse indexes",
			"$Boot, $BadClus, $Volume",
		},
		match: baseIs("$secure", "$bitmap", "$quota", "$objid", "$reparse", "$boot", "$badclus", "$volume"),
	},
	{
		label: "PowerShell transcript", family: FamilyPowerShell, priority: PriorityHigh,
		why:    "A verbatim record of a PowerShell session including command output, often surviving when the event log does not.",
		reason: "Tracefall has no transcript parser; console history (ConsoleHost_history.txt) IS parsed.",
		match:  matchPowerShellTranscript,
	},
	{
		label: "USB / device install log (SetupAPI)", family: FamilyLog, priority: PriorityHigh,
		why:    "First-connection times for removable devices, which is the primary evidence of data movement to external media.",
		reason: "Tracefall has no SetupAPI log parser.",
		match:  matchSetupAPILog,
	},
	{
		label: "Antimalware detection log", family: FamilyLog, priority: PriorityHigh,
		why:    "Detection and remediation history names malicious files and the time they were seen, often the earliest signal available.",
		reason: "Tracefall reads MpCmdRun.log and the detection and blocked-process lines of MPLog / MPDetection. This Defender text log is another kind (or is not named like those) and is not read.",
		match:  matchDefenderLog,
	},
	{
		label: "Web server log (IIS / W3C)", family: FamilyLog, priority: PriorityHigh,
		why:    "Records requests against a hosted service: the primary evidence for web exploitation and webshell activity.",
		reason: "Tracefall reads IIS site logs (u_ex*.log). This file is another kind of log kept under the same folders (an FTP site log or an HTTP.sys error log) or not an IIS site log, and is not read.",
		match:  matchWebServerLog,
	},
	{
		label: "Windows Search index (Windows.edb)", family: FamilyExecution, priority: PriorityMedium,
		why:    "Indexes file names, paths and content, including for files since deleted -- useful corroboration, rarely primary.",
		reason: "Windows.edb is an ESE database. Tracefall reads ESE databases but has no interpretation of the Windows Search tables yet.",
		match:  baseIs("windows.edb"),
	},
	{
		label: "Thumbnail cache", family: FamilyExecution, priority: PriorityMedium,
		why:    "Retains thumbnails of images and documents after the originals are deleted, evidencing that a file once existed.",
		reason: "Tracefall has no thumbcache parser.",
		match:  matchThumbcache,
	},
	{
		label: "RDP bitmap cache", family: FamilyExecution, priority: PriorityMedium,
		why:    "Fragments of what was displayed during an outbound RDP session; reconstructable but partial and labour-intensive.",
		reason: "Tracefall has no RDP bitmap cache parser.",
		match:  matchRDPCache,
	},
	{
		label: "Event trace log (.etl)", family: FamilyLog, priority: PriorityMedium,
		why:    "Kernel and provider tracing that can carry process and network detail, though rarely retained long enough to rely on.",
		reason: "Tracefall has no ETL parser.",
		match:  hasExt(".etl"),
	},
	{
		label: "Hosts / network configuration file", family: FamilyLog, priority: PriorityMedium,
		why:    "A modified hosts file redirects name resolution -- small, high-signal, and frequently altered by malware.",
		reason: "Tracefall does not parse static network configuration files.",
		match:  matchHostsFile,
	},
	{
		label: "Host firewall log", family: FamilyLog, priority: PriorityMedium,
		why:    "Allowed and dropped connections at the host, corroborating network activity seen elsewhere.",
		reason: "Tracefall has no firewall log parser.",
		match:  baseIs("pfirewall.log", "pfirewall.log.old"),
	},
	{
		label: "Crash dump", family: FamilyMemory, priority: PriorityMedium,
		why:    "A snapshot of one process or the kernel at failure: can hold injected code, but is bounded and often unrelated.",
		reason: "Tracefall performs no memory analysis.",
		match:  hasExt(".dmp", ".mdmp", ".hdmp"),
	},

	// ---- browser artifacts ----
	//
	// Browser support is PARTIAL, and the old single rule ("Browser data
	// (unsupported format)") described the gap so vaguely that a file
	// landing in it read as "Tracefall does not do browsers". It does:
	// Chromium History and Firefox places.sqlite are parsed (see
	// internal/parsers/browserhistory).
	//
	// Split into one rule per artifact so each unsupported browser file
	// is named for what it actually is, and each carries the list of
	// browser artifacts that ARE parsed. An analyst looking at a
	// WebCacheV01.dat row can then see, on that row, that their Chrome
	// history is still covered.
	{
		label: "IE / Edge Legacy web cache (WebCacheV01.dat)", family: FamilyBrowser, priority: PriorityMedium,
		why:           "Holds Internet Explorer and Edge Legacy browsing history -- the same class of evidence as any other browser history.",
		reason:        "A WebCacheV01.dat is read when it is an ESE database; this file is not (or is the old index.dat format), so IE history is not extracted.",
		parsedInstead: browserParsedInstead,
		notParsed:     []string{"Internet Explorer index.dat (legacy history format)"},
		match:         baseIs("webcachev01.dat", "index.dat"),
	},
	{
		label: "Browser cookie store", family: FamilyBrowser, priority: PriorityMedium,
		why:           "Evidences authenticated sessions and site contact; supports user activity without establishing it.",
		reason:        "Tracefall has no cookie-store parser. Cookies are not extracted from any browser.",
		parsedInstead: browserParsedInstead,
		notParsed:     []string{"Browser cookie stores"},
		match:         baseIs("cookies.sqlite", "cookies"),
	},
	{
		// The path-only cache rules.
		//
		// These are the LAST resort for a cache file: discovery already
		// recognized what it could from the bytes (see
		// recognizedTypeInfo), so a file reaching here either was not
		// read at discovery time -- a catalog written by an older build
		// -- or carries no signature at all. Each still says which kind
		// of cache file it is rather than sharing one message.
		//
		// Note the priorities: none of these is MEDIUM by default.
		// Auxiliary and bookkeeping files hold no independently useful
		// metadata by design, and saying so at LOW keeps them out of an
		// analyst's way without hiding them.
		label:  "Browser cache auxiliary file",
		family: FamilyBrowser, priority: PriorityLow,
		why:           "Cache bookkeeping whose useful metadata lives in the entry records that address it.",
		reason:        "Cached response body (f_######). Its metadata is stored in the associated data_1 entry record.",
		parsedInstead: browserParsedInstead,
		notParsed:     []string{"Cached response bodies (Tracefall reads cache metadata only)"},
		match:         matchBlockfileExternalBody,
	},
	{
		label:  "Browser cache hash index",
		family: FamilyBrowser, priority: PriorityLow,
		why:           "Stores key hashes rather than keys, so it names no URL; the entry files it points at carry the evidence.",
		reason:        "Cache index of key hashes, not keys, so it names no URL. The entry files it points at are parsed.",
		parsedInstead: browserParsedInstead,
		notParsed: []string{
			"Chromium Simple Cache index / index-dir/the-real-index (key hashes and last-used times)",
			"Firefox cache2 index (SHA-1 key hashes)",
		},
		match: matchCacheHashIndex,
	},
	{
		label:  "Browser cache journal/state",
		family: FamilyBrowser, priority: PriorityLow,
		why:           "A cache's own housekeeping. It records no cached resource and no user activity.",
		reason:        "Browser-cache journal/state file. No independently parsed cache-entry metadata.",
		parsedInstead: browserParsedInstead,
		notParsed:     []string{"Cache journals, lock files and temporary indexes"},
		match:         matchCacheStateFile,
	},
	{
		// The generic fallback, and ONLY the generic fallback: a file in
		// a cache directory whose format nothing could identify. LOW,
		// not medium -- an unidentified file is not a promise of value.
		label:  "Browser cache unknown",
		family: FamilyBrowser, priority: PriorityLow,
		why:           "Unidentified, but inside a browser cache -- worth a glance even though nothing is established about it.",
		reason:        "File is located in a browser-cache directory, but its format could not be identified.",
		parsedInstead: browserParsedInstead,
		notParsed:     []string{"Files in a browser cache whose format structural detection could not identify"},
		match:         matchInCacheDirectory,
	},
	{
		// Split from the single "memory image" rule: a full capture and
		// a page file are not the same evidence. hiberfil/memory.dmp are
		// a complete snapshot of running state; pagefile/swapfile are
		// fragments of it -- valuable, but partial and unstructured.
		label: "Memory image (full capture)", family: FamilyMemory, priority: PriorityCritical,
		why:    "A complete snapshot of running state: injected code, decrypted payloads, network state and credential material.",
		reason: "Tracefall performs no memory analysis.",
		match:  baseIs("hiberfil.sys", "memory.dmp", "memory.raw", "winpmem.raw"),
	},
	{
		label: "Page / swap file", family: FamilyMemory, priority: PriorityHigh,
		why:    "Fragments of process memory paged to disk: often recoverable strings and payloads, but partial and unstructured.",
		reason: "Tracefall performs no memory analysis.",
		match:  baseIs("pagefile.sys", "swapfile.sys"),
	},
	{
		label: "Windows Error Report", family: FamilyLog, priority: PriorityLow,
		why:    "Crash telemetry naming a process and its modules: corroborates execution already evidenced elsewhere.",
		reason: "Crash telemetry. Tracefall has no WER parser.",
		match:  hasExt(".wer"),
	},
	{
		// CRITICAL, matching EVTX. A pre-Vista .evt holds the same
		// evidence in an older container: on a system that writes them,
		// it IS the event log. This was MEDIUM, which tracked the
		// missing parser rather than the artifact -- the one thing a
		// priority must never do.
		label: "Event Log (legacy .evt)", family: FamilyEventLog, priority: PriorityCritical,
		why:    "The same account of logons, service installs and process activity that EVTX carries, in the pre-Vista container.",
		reason: "Tracefall parses the modern EVTX format only, not the pre-Vista .evt format.",
		match:  hasExt(".evt"),
	},
	{
		label: "Log file", family: FamilyLog, priority: PriorityLow,
		why:    "Application-specific text whose value depends entirely on the application; records no general investigative fact.",
		reason: "Plain-text logs are not parsed; their format is application-specific.",
		match:  hasExt(".log"),
	},
	{
		label: "CSV (unrecognized tool output)", family: FamilyOther, priority: PriorityMedium,
		why:    "Tool output that may hold processed forensic data, but of unknown provenance and structure.",
		reason: "This CSV does not match the naming convention of any EZ Tools output Tracefall parses (EvtxECmd, PECmd, RECmd).",
		match:  hasExt(".csv"),
	},
	{
		label: "XML (not a Scheduled Task)", family: FamilyOther, priority: PriorityLow,
		why:    "Configuration or data serialization; carries no activity record of its own.",
		reason: "Only Task Scheduler XML collected under a Tasks directory is parsed.",
		match:  hasExt(".xml"),
	},
	{
		label: "Documentation / notes", family: FamilyOther, priority: PriorityLow,
		why:    "Human-written text about the collection, not evidence the system produced.",
		reason: "Not forensic evidence.",
		match: func(_, base string) bool {
			return hasExt(".md")("", base) || hasExt(".txt")("", base) || hasExt(".rtf")("", base)
		},
	},
}

// unknownCapability is what a file matching no rule gets: honest about
// being unrecognized rather than guessing.
var unknownCapability = Capability{
	Label:       "Unrecognized",
	Family:      FamilyOther,
	FamilyLabel: FamilyLabels[FamilyOther],
	// UNKNOWN, deliberately, and never LOW. Calling an unidentified file
	// "limited forensic value" asserts something nobody established --
	// the file might be the most important thing in the collection. The
	// honest answer is that its class was not determined, which is what
	// this priority says and what sorts it last without dismissing it.
	Priority:       PriorityUnknown,
	PriorityReason: "Not classified: this file matched no artifact rule, so no forensic value has been assessed either way.",
	Supported:      false,
	Recognized:     false,
	Reason:         "Tracefall does not recognize this file as a known forensic artifact.",
}

// Registry answers capability questions for one build of Tracefall.
type Registry struct {
	// byType maps an artifact type produced by a real parser to its
	// capability. Built from the parser registry, so it is exactly the
	// set of things this binary can parse.
	byType map[string]Capability
	all    []Capability
}

// NewRegistry derives the capability registry from the live parser
// registry. Pass ingest.Registry().
func NewRegistry(registered []parsers.ArtifactParser) *Registry {
	r := &Registry{byType: map[string]Capability{}}

	// Two passes. The first registers each parser's own FILE artifact
	// type; the second adds the types its EVENTS carry (see
	// parsers.EventArtifactTypeSource). File types are registered first
	// so a parser that both reads a file type and emits it as an event
	// type keeps the file-level registration, which names the parser
	// that actually claims the file.
	for _, p := range registered {
		at := p.ArtifactType()
		if _, seen := r.byType[at]; seen {
			// Two parsers producing the same artifact type (e.g. the
			// EvtxECmd CSV parser and the native .evtx parser both
			// produce windows_event_log) is normal and intended -- the
			// capability describes the TYPE, so the first registration
			// wins and the type is listed once.
			continue
		}
		info, ok := supportedTypeInfo[at]
		if !ok {
			// A parser whose artifact type has no metadata entry still
			// works; it just displays generically. Better than omitting
			// a supported artifact from the registry entirely.
			info = typeInfo{label: humanize(at), family: FamilyOther, priority: PriorityMedium}
		}
		r.byType[at] = Capability{
			ArtifactType:   at,
			Label:          info.label,
			Family:         info.family,
			FamilyLabel:    FamilyLabels[info.family],
			Priority:       info.priority,
			Supported:      true,
			Recognized:     true,
			Parser:         p.Name(),
			PriorityReason: info.why,
			Note:           info.note,
		}
	}

	for _, p := range registered {
		src, ok := p.(parsers.EventArtifactTypeSource)
		if !ok {
			continue
		}
		for _, at := range src.EventArtifactTypes() {
			if _, seen := r.byType[at]; seen {
				continue
			}
			info, ok := supportedTypeInfo[at]
			if !ok {
				info = typeInfo{label: humanize(at), family: FamilyOther, priority: PriorityMedium}
			}
			r.byType[at] = Capability{
				ArtifactType:   at,
				Label:          info.label,
				Family:         info.family,
				FamilyLabel:    FamilyLabels[info.family],
				Priority:       info.priority,
				Supported:      true,
				Recognized:     true,
				Parser:         p.Name(),
				PriorityReason: info.why,
				Note:           info.note,
			}
		}
	}

	for _, c := range r.byType {
		r.all = append(r.all, c)
	}
	// Deterministic order: priority first, then label.
	sort.Slice(r.all, func(i, j int) bool {
		if a, b := r.all[i].Priority.Rank(), r.all[j].Priority.Rank(); a != b {
			return a < b
		}
		return r.all[i].Label < r.all[j].Label
	})
	return r
}

// Supported returns every artifact class this build can actually parse.
func (r *Registry) Supported() []Capability {
	out := make([]Capability, len(r.all))
	copy(out, r.all)
	return out
}

// Unsupported returns the recognized-but-unparsed artifact classes, in
// priority order. Useful on its own as documentation of the gaps.
func (r *Registry) Unsupported() []Capability {
	out := make([]Capability, 0, len(unsupportedRules))
	for _, rule := range unsupportedRules {
		out = append(out, Capability{
			Label:          rule.label,
			Family:         rule.family,
			FamilyLabel:    FamilyLabels[rule.family],
			Priority:       rule.priority,
			PriorityReason: rule.why,
			Supported:      false,
			Recognized:     true,
			Reason:         rule.reason,
			ParsedInstead:  rule.parsedInstead,
			NotParsed:      rule.notParsed,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority.Rank() < out[j].Priority.Rank() })
	return out
}

// Classify answers "what is this file, and how much should I care?" for
// one discovered file.
//
// artifactType is what discovery already determined (non-empty exactly
// when a parser claimed the file). When it is set, the answer comes from
// the parser registry -- the authoritative source. When it is empty, the
// path is matched against the recognized-but-unparsed rules so the file
// still gets a type, a priority and a reason instead of being an
// anonymous row in a list of seven thousand.
func (r *Registry) Classify(relPath, artifactType string) Capability {
	if artifactType != "" {
		if c, ok := r.byType[artifactType]; ok {
			return c
		}
		// A recognition assigned by discovery from the file's own bytes.
		// Recognized, never Supported -- see recognizedTypeInfo.
		if rule, ok := recognizedTypeInfo[artifactType]; ok {
			return Capability{
				Label:          rule.label,
				Family:         rule.family,
				FamilyLabel:    FamilyLabels[rule.family],
				Priority:       rule.priority,
				PriorityReason: rule.why,
				Supported:      false,
				Recognized:     artifactType != model.ArtifactBrowserCacheUnknown,
				Reason:         rule.reason,
				ParsedInstead:  browserParsedInstead,
				NotParsed:      rule.notParsed,
			}
		}
		// An artifact type from an older collection whose parser no
		// longer exists in this build. Report it honestly rather than
		// claiming support that is gone.
		return Capability{
			ArtifactType: artifactType,
			Label:        humanize(artifactType),
			Family:       FamilyOther,
			FamilyLabel:  FamilyLabels[FamilyOther],
			Priority:     PriorityMedium,
			Supported:    false,
			Recognized:   true,
			Reason:       "This evidence was cataloged by a version of Tracefall that had a parser for it; this build does not.",
		}
	}

	lower := strings.ToLower(strings.ReplaceAll(relPath, `\`, "/"))
	base := path.Base(lower)
	for _, rule := range unsupportedRules {
		if rule.match(lower, base) {
			return Capability{
				Label:          rule.label,
				Family:         rule.family,
				FamilyLabel:    FamilyLabels[rule.family],
				Priority:       rule.priority,
				PriorityReason: rule.why,
				Supported:      false,
				Recognized:     true,
				Reason:         rule.reason,
				ParsedInstead:  rule.parsedInstead,
				NotParsed:      rule.notParsed,
			}
		}
	}
	return unknownCapability
}

// humanize turns an artifact type constant into a readable label as a
// last resort ("windows_event_log" -> "Windows Event Log").
func humanize(s string) string {
	if s == "" {
		return "Unrecognized"
	}
	parts := strings.Split(s, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}
