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

Not covered: Linux/macOS memory, pagefile/hiberfil, driver/handle/registry
plugins, process dumping, YARA scanning.
