# Tracefall synthetic scenarios (Phase 4)

**All data under `testdata/` is 100% synthetic**, fabricated specifically
to exercise Tracefall's parsers, detection rules, and correlation engine.
No real hostnames, usernames, IP addresses, or evidence of any kind are
present anywhere in this directory tree. Hosts are named `WKSTN-SIM-*`,
users are fictional (`jdoe`, `svc-sql`, `svc-backup`, `admin`), and IP
addresses use IANA-reserved documentation ranges (`203.0.113.0/24`,
`10.0.0.0/8`).

This directory holds Phase 4's expanded scenario set, scenarios B through
G. Scenario A (Phishing -> Office -> PowerShell -> payload -> persistence
-> C2) is **not duplicated here** -- it's the existing fixture at
[`testdata/synthetic_case/`](../synthetic_case/), left untouched so the
tests that already depend on its exact contents
(`internal/ingest/ingest_test.go`, `internal/api/upload_test.go`,
`internal/api/api_test.go`, `internal/api/duplicate_evidence_test.go`)
keep passing unmodified.

Each scenario below is deliberately self-contained (only the artifact
types it actually needs), minimal (just enough rows to exercise the
relevant rule, not a realistic-volume triage), and exercised end-to-end
by `internal/api/phase4_scenarios_test.go` (discover -> import -> analyze
-> assert on findings/correlations).

| Scenario | Directory | Exercises |
|---|---|---|
| A | [`testdata/synthetic_case/`](../synthetic_case/) | Phishing -> Office -> PowerShell -> payload -> persistence -> C2 (Phase 1, unchanged) |
| B | `b_brute_force/` | Repeated failed logons (4625 x4) followed by a success (4624) -- brute-force chain |
| C | `c_scheduled_task_persistence/` | A scheduled task registered to run PowerShell from AppData at highest available privilege |
| D | `d_registry_run_key_persistence/` | A Run key pointing at an AppData-staged executable |
| E | `e_suspicious_service/` | A service installed (System 7045) with its binary in a user-writable path |
| F | `f_powershell_download/` | Standalone PowerShell (no Office involved) with an encoded download command, followed by a network connection |
| G | `g_benign_admin_activity/` | **Required negative case**: a plausible day of ordinary IT administration (RDP logon, privileged logon, mapped drive with alternate creds, standard-path software install, a legitimate scheduled task/Run key/service, an unremarkable PowerShell script run) -- must not produce any high-severity, high-confidence finding |

See `docs/detection-engine.md` for which rule each scenario is meant to
exercise, and why.
