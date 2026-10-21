# Memory images

Tracefall analyses a Windows memory image by driving Volatility 3 in a
sandbox and turning its output into the same events, findings and report as
every other source. It does not reimplement memory forensics.

## Enable it

Volatility 3 is not bundled. Install it (for example `pip install volatility3`
in a virtualenv) and point Tracefall at the `vol` executable:

    TRACEFALL_VOLATILITY=/path/to/venv/bin/vol tracefall

Optional: TRACEFALL_VOLATILITY_SYMBOLS (directories of symbol tables, path
list), TRACEFALL_VOLATILITY_CACHE, TRACEFALL_VOLATILITY_TIMEOUT (default 2h),
TRACEFALL_VOLATILITY_ALLOW_UNSANDBOXED=1.

Without the variable, a memory image is refused (HTTP 501) with a message that
says this. Nothing else changes.

Volatility needs a symbol table matching the image's Windows build. It
downloads these itself when it has network access; the sandbox has none, so
install them beforehand into a directory listed in TRACEFALL_VOLATILITY_SYMBOLS.
An image Volatility cannot match is rejected (HTTP 422) at discovery and
nothing is stored. Volatility prints the same message for "not a Windows
memory image" and "symbols not installed", so Tracefall reports both.

## Flow

    upload or local path -> sniff (magic bytes, or .vmem .mem .dmp .lime .raw)
    discovery -> windows.info (identifies the OS) -> one catalog entry
    import    -> plugin set runs -> memory/volatility-analysis.json -> parser -> events

Plugins: pslist, psscan, cmdline, netscan, malfind, svcscan (names are
resolved against the installed Volatility; malfind moved between releases).
A plugin that fails is recorded with its error and the rest continue; the
snapshot event and the report list what failed.

## Containment

Every run uses bubblewrap: new user, network, PID and IPC namespaces, empty
environment, read-only system, Volatility, symbols and image, and one writable
directory (Volatility's cache). A hung run is killed after the timeout, with
its child processes; output over 256 MiB is cut off. If bubblewrap cannot
create namespaces here, Tracefall refuses to start the runner unless
TRACEFALL_VOLATILITY_ALLOW_UNSANDBOXED=1, and then the report says the run
was not contained. There is NO memory limit (Volatility maps the whole image).

## What the events mean

- Processes: ProcessCreate at the process's own create time. Found by pslist
  and psscan = 0.9 confidence. Found only by psscan and never exited:
  `hidden_process=true`, 0.6 confidence (unlinked from the process list; not
  proof of a rootkit). Command lines are joined by PID to the process that was
  alive; an unreadable command line is recorded as `cmdline_unavailable`, never
  as a command line. PIDs are reused, so rows are keyed by PID and create time.
- Network: connection (has a remote end) or listener (does not). Dated to the
  socket's creation time; with none, to the snapshot, and marked.
- malfind: `memory_injection_suspect`, confidence 0.5. Private executable
  memory, which JIT-compiled code also produces. Dated to the snapshot.
- Services: `service_in_memory`, dated to the snapshot. A state, not an
  installation event.
- Consoles (`cmdscan`, `consoles`): `console_command_in_memory`, one per
  command a console still held, in order, with `console_title` and
  `console_application` when known. A command found by both plugins is one
  event (`found_by`). The console keeps no time per command, so the event is
  dated to the snapshot (`timestamp_basis=memory_snapshot`). Also
  `console_screen_in_memory`: the text of a screen buffer (commands and their
  output), truncated at 4000 characters. Volatility 3 reads these from
  `conhost.exe` only. When the process list has none, the snapshot event says
  so in `console_note`: the absence of commands then means nothing. When the
  plugins ran and found none, the note says a closed or cleared console proves
  nothing either. Commands feed the rule `system-change-command`
  (confidence low: a command in a console was typed there, not shown to have
  run).
- File objects (`filescan`): `file_object_in_memory`, for runnable, document,
  archive and data files outside the operating system's and installed
  software's own locations. The file was open or cached at capture; it may
  not exist on disk and no content hash is known. Everything not listed is
  counted in the snapshot event's `file_objects` (routine locations, other
  types, unreadable names). Names are matched against files delivered over
  HTTP in a capture by the correlation `web_to_host`.
- Recovered files (`windows.dumpfiles`, after `filescan`): up to 60 runnable
  files (executables, libraries, scripts) outside the operating system's
  locations, users' and temporary locations first, browser caches last. Each is
  dumped by its file-object address into a private directory inside the
  sandbox's cache directory, inspected without being run (`internal/payload`),
  and deleted: only hashes and the inspection are kept.
  `file_content_from_memory` has `sha256`/`md5`/`sha1`, `file_signature`, the
  parts of a Windows program (machine, sections, imports, injection APIs,
  exports, claimed build time), indicators, and readable strings.
  - **What comes back is what was in memory.** A page that was not resident
    returns as zeros. `zero_pages` says how many; at a tenth or more the event
    is `sparse=true`, and indicators about something being absent (few imports,
    no signature, malformed PE) are withheld and listed in
    `indicators_withheld`, because the part may simply not have been resident.
  - An image-section dump is laid out as mapped, so its hash is not the hash of
    the file on disk. A data-section dump is the cached file data, and equals the
    file only when every page was cached.
  - The snapshot event's `file_recovery` counts what was recovered, what was not
    in memory, what was too large (32 MiB, sized but not read) and what failed.
    A file not in memory says nothing about whether it existed.
  - When a delivered object (see `web_to_host`) has the same SHA-256 as
    recovered bytes, the correlation says the content is the same.
- Snapshot: one event at the image's system time with Volatility version,
  isolation and plugin outcomes.

Anything dated to the snapshot carries `timestamp_basis=memory_snapshot`. It
shows what was present when the image was taken, not when it began. If the
image has no system time, those events are not created rather than dated
wrongly.

## Event identity and older cases

Snapshot time plus PID is not sufficient to identify objects inside a process.
Memory deduplication additionally uses region start/end addresses, service name
and recorded configuration/state, or socket source address/local port/protocol/state
(the destination is already part of the base event identity). Source row numbers,
plugin rendering notes and collection IDs are not object identity; true duplicate
observations still share an event and retain separate raw-evidence observations.
The extra fields affect only `memory_analysis` events, not existing log/disk hashes.

**Earlier memory imports must be reprocessed in a fresh case.** This fix does not
silently rewrite old case events, observations or issued reports. Old generic
hashes may already have merged different objects; changing a stored hash alone
cannot reconstruct their separate event rows. Keep the old case/report as a
baseline, create a new case and ingest the original memory image with this build,
then regenerate the analysis and report. Do not merge an old pre-fix memory case
with a new recollection and assume its identities have been upgraded.

## What is verified, and what is not

Verified on real authorised CyberDefenders Windows memory dumps (Reveal,
Ramnit, RedLine): all six plugin outputs for each image matched direct
Volatility 3 2.28.2 JSON output while Tracefall used bubblewrap. Key process,
command-line and network indicators matched public walkthrough references.
All jobs produced HTML/PDF/ZIP reports and passed image integrity rechecks.

**Not accepted for complete forensic analysis:** the baseline exposed memory
identity collisions; these are now fixed and revalidated in fresh Reveal,
Ramnit and RedLine cases (all 42 selected P0 regression checks pass). See
[the P0 regression](validation-memory-p0.md) for the new counts and the required
fresh-case recovery workflow. Generic lineage noise and missing memory-specific
analysis remain open; preserving objects is not a pass for investigative
completeness. See [the original baseline](validation-cyberdefenders-baseline.md)
for the pre-fix failures and other coverage limits. Unit fixtures are constructed;
the multi-GB lab images remain external and are not in this repository.

Console and file-object parsing follows the plugin column names read from
Volatility 3 2.28.2's source and was run on a real Windows 10 image; that image's
console was empty, so command rows come from constructed fixtures. An older
Windows (consoles hosted by csrss.exe) yields nothing from these plugins.

Not covered: Linux/macOS memory, pagefile/hiberfil, driver/handle/registry
plugins, process dumping, YARA scanning.
