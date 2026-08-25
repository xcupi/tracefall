# SYNTHETIC TEST DATA — NOT REAL FORENSIC EVIDENCE

Everything under this directory is **fabricated** for testing Tracefall's
pipeline. No file here was collected from a real machine, no host named
`WKSTN-042` exists, and no user, IP address, file hash, or timestamp
represents a real person, system, or incident.

It resembles the output of a KAPE collection run with the `!EZParser`
module (EvtxECmd / PECmd / RECmd CSV, plus raw Task Scheduler XML) and
encodes a synthetic attack-like sequence for exercising the full
ingest → normalize → detect → correlate → ATT&CK-map pipeline:

1. `jdoe` logs on interactively (`EvtxECmd`, Security 4624).
2. `jdoe` opens a phishing attachment, which launches Microsoft Word
   (`EvtxECmd`, Security 4688; `PECmd`).
3. Word spawns PowerShell with an obfuscated, encoded command
   (`EvtxECmd`, Security 4688 + PowerShell 4104).
4. PowerShell downloads and executes a payload, `update.exe`, from
   `%TEMP%` (`EvtxECmd`, Security 4688; `PECmd`).
5. The payload establishes persistence via both a registry Run key
   (`RECmd`) and a scheduled task (`Tasks/*.xml`).
6. The payload beacons out to an external IP (`EvtxECmd`, Sysmon Network
   Connect).

A second, unrelated thread simulates a brute-force credential attack
against a local service account (four failed logons followed by a
success) to exercise the `brute-force-then-success` detection rule.

See [`../../docs/adding-parsers.md`](../../docs/adding-parsers.md#regenerating-or-extending-the-synthetic-test-dataset)
for how to extend this dataset.
