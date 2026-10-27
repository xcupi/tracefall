# Evidence-bound activity/service joins and host identity

## Analysis policy

- Activity requires an identified Office → interpreter lineage. It reuses the
  process-chain case/host/collection, PID/PPID or GUID, observed-start and exit
  checks, but excludes hypothetical name-only links. Consecutive narrative
  links remain bounded by the existing two-hour activity window.
- Network observations need a recorded process creation, matching PID or GUID,
  compatible recorded names/paths, the same case and nonempty acquisition and
  host, strict timestamp order, and no contradictory observed start or exit.
  A missing exit does **not** establish a continuous lifetime: descriptions
  explicitly retain unobserved PID reuse/lifetime uncertainty.
- Nearby same-user logons are not process-session attribution. Optional logon
  context requires a matching recorded session and account in the acquisition.
- Registry/task/service configuration names an executable target, not its
  running instance. In particular Sysmon registry `PID` is the **writer** while
  normalized `ProcessName` is the configured target. These are never equated.
  A unique, ordered full-path reference may appear only as labelled contextual
  configuration. Service chains do not claim SCM launched the observed process.
  Investigations retain this caveat in their summaries and do not award
  contextual chains the evidenced-chain or independent-correlation score and
  confidence bonuses. The stored `Contextual ` title marker carries this basis;
  historical pre-fix chains must be re-analyzed.
- Bare executable names, uncertain command-line/path extraction, undated or
  snapshot-only instants, tied timestamps, ambiguous candidates, contradictory
  identities and unknown acquisitions cause abstention from the affected join.
  Other raw timeline observations and independent findings remain available.

## Host names and addresses

Distinct FQDNs remain distinct even when their first DNS label agrees. All
comparison keys retain the existing case-insensitive normalization. Short-name
aliases need one compatible FQDN and evidence of compatibility (co-observation
in one known acquisition, or the machine's recorded DNS domain for address
identity). A later conflicting FQDN invalidates an ambiguous short alias,
independently of input order. Contradictory recorded domain/role/OS metadata is
not overwritten to manufacture an identity. Unknown host names are never
inherited from another event or case; investigation unknowns remain acquisition
scoped. Investigation aliases do not acquire case-wide inheritance.

Address identity retains its stated evidence basis and rank. Shared addresses
never merge machine identities; competing strongest claims resolve to neither.
This is **not** historical temporal IP-ownership reconstruction. Static, memory,
last-DHCP, client-claimed and DNS facts retain their existing limitations; a
stronger fact is not proof of ownership at every historical instant. Clock
logon/capture pairing now requires a positively resolved destination and the
same registry identity, not a fallback when address resolution fails.

Filtered correlation loads include DNS facts and distinct host/acquisition name
projections from all event references. Projections carry no invented timestamp
or event type, cannot become chain steps, and are deduplicated by name/scope
rather than expanding every untyped event to a full retained event.

## Credential and SQL-to-Windows chains

Credential builders use the same case-wide validated comparison keys, including
unreferenced names and machine metadata from filtered sources. Unknown or
contradictory identity cannot support a host-bound authentication chain.
Repeated acquisitions of the same established host remain eligible: collection
equality is not imposed on failure/success sequences. Recorded source-address,
account-domain and subject-session contradictions still reject a sequence;
missing context remains uncertainty, not proof of a match.

SQL connection and OS-request/process builders also validate identity before
narrowing their input set. Same-machine short/FQDN co-observation can establish
an alias; a diagnostic server label alone cannot establish one. All existing
same-collection, exact connection-ID, independent diagnostic, bounded process
lifetime, SQL syntax/outcome and parent-identity requirements remain intact.
These changes do not add SQL readers or extract new fields.

## Existing cases and boundaries

No parser, persisted event, dedup hash, schema or original evidence is changed.
Re-analyze an existing case to replace stored correlations/investigations under
this policy; no reimport is required for correctly stored observations. If a
historical import itself stored incorrect inherited hosts or lost observations,
analysis cannot reconstruct them: a fresh-case reimport with the appropriate
upstream fix is a separate operation, not performed by this change.

This work does not add SQL readers, GUID extraction to parsers, reconstruct
missing process starts/exits, establish service execution from configuration,
or perform a real-case examination. Synthetic regressions and disposable built
binary validation are software evidence, not conclusions about acquired cases.
