package store

// schema is applied on every startup with CREATE TABLE IF NOT EXISTS,
// which is sufficient for a database created fresh under this schema
// version. A database created under an earlier schema version (before
// collections/dedup existed) is upgraded in place by migrate.go, which
// runs right after this -- see that file for the migration itself and
// docs/data-model.md for the schema's evolution.
//
// Lists (Finding.SupportingEvents/Techniques, Correlation.EventIDs) are
// stored as JSON text columns rather than join tables: Tracefall never
// needs to query "which findings reference event X" at the SQL level, it
// loads a case's findings/correlations wholesale and filters in Go. If
// that changes, normalizing these into join tables is a mechanical
// migration, noted as a Phase 2 item in docs/data-model.md.
const schema = `
CREATE TABLE IF NOT EXISTS cases (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL,
	created_at  TEXT NOT NULL,
	updated_at  TEXT NOT NULL,
	-- Phase 6 additions -- see internal/model.Case's doc comment for why
	-- case_status is a SEPARATE concept from status above (analysis
	-- lifecycle vs. analyst investigative workflow), never conflated.
	-- analyzed_at is '' until AnalyzeCase first succeeds. On a database
	-- predating these columns, migrate.go's addColumnIfMissing adds them
	-- (CREATE TABLE IF NOT EXISTS is a no-op against an existing table).
	case_status TEXT NOT NULL DEFAULT 'open',
	priority    TEXT NOT NULL DEFAULT 'medium',
	analyzed_at TEXT NOT NULL DEFAULT ''
);
-- idx_cases_name_unique (case names are unique, trimmed and
-- case-insensitively) is created in migrate.go, not here: a database
-- from before this constraint existed might already contain two cases
-- with the same name, which migrate.go must detect and report -- not
-- silently fix -- before it's safe to create the index. See that file's
-- enforceCaseNameUniqueness and docs/data-model.md's "Case name
-- uniqueness" section.

-- One row per independent evidence-gathering event ingested into a case
-- (one KAPE ZIP upload, one local-path ingest). A case's timeline,
-- findings, and correlations always span every collection -- see
-- docs/data-model.md.
CREATE TABLE IF NOT EXISTS collections (
	id                     TEXT PRIMARY KEY,
	case_id                TEXT NOT NULL REFERENCES cases(id),
	created_at             TEXT NOT NULL,
	source_type            TEXT NOT NULL,
	original_filename      TEXT NOT NULL DEFAULT '',
	archive_hash           TEXT NOT NULL DEFAULT '',
	-- Phase 10A: SHA-512 of the original evidence object, for integrity
	-- rather than deduplication. Kept separate from archive_hash, which
	-- duplicate detection depends on -- see model.Collection's doc
	-- comment and docs/evidence-integrity.md. On a database predating
	-- this column, migrate.go's addColumnIfMissing adds it.
	integrity_sha512       TEXT NOT NULL DEFAULT '',
	evidence_directory     TEXT NOT NULL DEFAULT '',
	ingestion_status       TEXT NOT NULL,
	file_count             INTEGER NOT NULL DEFAULT 0,
	supported_file_count   INTEGER NOT NULL DEFAULT 0,
	unsupported_file_count INTEGER NOT NULL DEFAULT 0,
	imported_file_count    INTEGER NOT NULL DEFAULT 0,
	parsed_event_count     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_collections_case ON collections(case_id);
-- Enforces "no two collections in the same case may share an
-- archive/source hash" at the database level -- the authoritative
-- defense against two concurrent requests both passing a SELECT-based
-- duplicate check before either has inserted (see
-- internal/api.Service.commitDiscovery). Partial (WHERE
-- archive_hash != '') so: (a) legacy collections predating hash
-- computation, which all share archive_hash = '', never collide with
-- each other; (b) archive hashes are never required to be globally
-- unique across cases -- the same evidence may legitimately exist in
-- more than one investigation, only not twice in the *same* one.
CREATE UNIQUE INDEX IF NOT EXISTS idx_collections_case_archive_hash
	ON collections(case_id, archive_hash) WHERE archive_hash != '';

-- One row per individual evidence file discovered inside a collection --
-- the unit an investigator selects, imports, inspects, and deletes
-- independently (see internal/model.SourceFile's doc comment for the
-- discovered -> imported life cycle, and docs/data-model.md's "Evidence
-- file model" section). A row exists the moment a file is *discovered*,
-- before it's ever parsed -- import_status distinguishes a merely
-- cataloged file from one that's actually become evidence.
CREATE TABLE IF NOT EXISTS source_files (
	id                TEXT PRIMARY KEY,
	case_id           TEXT NOT NULL REFERENCES cases(id),
	collection_id     TEXT NOT NULL REFERENCES collections(id),
	original_filename TEXT NOT NULL DEFAULT '',
	path              TEXT NOT NULL,
	artifact_type     TEXT NOT NULL DEFAULT '',
	parser            TEXT NOT NULL DEFAULT '',
	supported         INTEGER NOT NULL DEFAULT 0,
	size_bytes        INTEGER NOT NULL DEFAULT 0,
	sha256            TEXT NOT NULL DEFAULT '',
	-- Phase 7 addition: a hash the source CONTAINER itself reported (AD1
	-- acquisition-time MD5/SHA1), format "algo:hexdigest" -- see
	-- internal/model.SourceFile.EmbeddedHash's doc comment. On a database
	-- predating this column, migrate.go's addColumnIfMissing adds it.
	embedded_hash     TEXT NOT NULL DEFAULT '',
	import_status     TEXT NOT NULL DEFAULT 'discovered',
	event_count       INTEGER NOT NULL DEFAULT 0,
	discovered_at     TEXT NOT NULL,
	imported_at       TEXT NOT NULL DEFAULT '',
	deleted_at        TEXT NOT NULL DEFAULT '',
 parse_coverage_json TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_source_files_case ON source_files(case_id);
-- idx_source_files_collection and idx_source_files_collection_sha256_active
-- (file-level duplicate protection -- see migrate.go for why it's scoped
-- to one collection, not the whole case) are created in migrate.go, not
-- here: on a database from before "collection_id" (or the newer
-- source_files columns) existed, this schema's CREATE TABLE IF NOT
-- EXISTS is a no-op (the table already exists without those columns), so
-- an index referencing them here would fail before migrate.go's ALTER
-- TABLE gets a chance to add them. See there.

CREATE TABLE IF NOT EXISTS raw_evidence (
	id               TEXT PRIMARY KEY,
	case_id          TEXT NOT NULL REFERENCES cases(id),
	source_file_id   TEXT NOT NULL REFERENCES source_files(id),
	source_reference TEXT NOT NULL DEFAULT '',
	raw              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_raw_evidence_case ON raw_evidence(case_id);

-- One row per deduplicated real-world event. A single Event row can have
-- many event_observations (below) if the same underlying event was
-- independently collected more than once.
CREATE TABLE IF NOT EXISTS events (
	id                  TEXT PRIMARY KEY,
	case_id             TEXT NOT NULL REFERENCES cases(id),
	collection_id       TEXT NOT NULL REFERENCES collections(id),
	timestamp           TEXT NOT NULL,
	host                TEXT NOT NULL DEFAULT '',
	user                TEXT NOT NULL DEFAULT '',
	event_type          TEXT NOT NULL,
	provider            TEXT NOT NULL DEFAULT '',
	event_id            INTEGER NOT NULL DEFAULT 0,
	process_name        TEXT NOT NULL DEFAULT '',
	process_path        TEXT NOT NULL DEFAULT '',
	parent_process      TEXT NOT NULL DEFAULT '',
	parent_process_path TEXT NOT NULL DEFAULT '',
	pid                 INTEGER NOT NULL DEFAULT 0,
	ppid                INTEGER NOT NULL DEFAULT 0,
	command_line        TEXT NOT NULL DEFAULT '',
	file_path           TEXT NOT NULL DEFAULT '',
	registry_path       TEXT NOT NULL DEFAULT '',
	network_source      TEXT NOT NULL DEFAULT '',
	network_dest        TEXT NOT NULL DEFAULT '',
	network_dest_port   INTEGER NOT NULL DEFAULT 0,
	artifact_type       TEXT NOT NULL,
	source_file_id      TEXT NOT NULL REFERENCES source_files(id),
	source_reference    TEXT NOT NULL DEFAULT '',
	parser              TEXT NOT NULL,
	confidence          REAL NOT NULL DEFAULT 1.0,
	raw_evidence_id     TEXT NOT NULL DEFAULT '',
	dedup_hash          TEXT NOT NULL DEFAULT '',
	extra_json          TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
CREATE INDEX IF NOT EXISTS idx_events_case_type ON events(case_id, event_type);
-- Phase 14 REPLACES idx_events_case_ts (case_id, timestamp) with the
-- same index plus the primary key. The old one is dropped in migrate.go,
-- so this is a swap and not an addition: the events table carries the
-- same number of indexes it did before, and import speed is unchanged
-- (measured: 200,000 events insert in 5.8s either way).
--
-- The id column is what the server-side timeline needs. Its ordering is
-- deterministic -- timestamp, then id -- so paging can never show one
-- event twice and skip another. Without id in the index SQLite satisfied
-- the WHERE from (case_id, timestamp) and then SORTED every matching row
-- to break the ties, which for an unfiltered case means sorting the
-- whole evidence set to return ten rows, on every page navigation. With
-- it the order comes straight off the index and the scan stops when the
-- page is full: page 5,000 of a 200,000-event case went from 155ms to
-- 22ms. The old index is a strict prefix of this one, so every query
-- that used it is served at least as well.
--
-- No index exists for artifact_type, event_type, host, user or
-- process_name beyond the pre-existing event_type one. Those columns are
-- filtered and are used to build the timeline's dropdowns, and indexing
-- them was measured rather than assumed: four such indexes cost +73% on
-- import (5.3s -> 9.1s per 200,000 events, paid on every import) to save
-- roughly 700ms once per timeline open. EventFacets gets the same result
-- from a single pass instead -- see store/eventquery.go.
CREATE INDEX IF NOT EXISTS idx_events_case_ts_id ON events(case_id, timestamp, id);
-- idx_events_case_dedup is created in migrate.go -- see the comment by
-- idx_source_files_collection above; the same ordering problem applies
-- to the dedup_hash column.

-- One row per (event, collection) it was actually observed in --
-- preserves full cross-collection provenance through deduplication. See
-- internal/model.EventObservation.
CREATE TABLE IF NOT EXISTS event_observations (
	id                TEXT PRIMARY KEY,
	event_id          TEXT NOT NULL REFERENCES events(id),
	case_id           TEXT NOT NULL REFERENCES cases(id),
	collection_id     TEXT NOT NULL REFERENCES collections(id),
	source_file_id    TEXT NOT NULL REFERENCES source_files(id),
	raw_evidence_id   TEXT NOT NULL DEFAULT '',
	source_reference  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_observations_event ON event_observations(event_id);
CREATE INDEX IF NOT EXISTS idx_observations_case ON event_observations(case_id);
CREATE INDEX IF NOT EXISTS idx_observations_collection ON event_observations(collection_id);

CREATE TABLE IF NOT EXISTS findings (
	id                    TEXT PRIMARY KEY,
	case_id               TEXT NOT NULL REFERENCES cases(id),
	rule_id               TEXT NOT NULL,
	title                 TEXT NOT NULL,
	severity              TEXT NOT NULL,
	confidence            TEXT NOT NULL,
	description           TEXT NOT NULL,
	supporting_events_json TEXT NOT NULL DEFAULT '[]',
	techniques_json       TEXT NOT NULL DEFAULT '[]',
	first_seen            TEXT NOT NULL,
	last_seen             TEXT NOT NULL,
	created_at            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);

-- analysis_runs records one execution of the detection/correlation
-- engines (Phase 11). Findings carry analysis_run_id so a finding can be
-- attributed to the run that produced it; findings written before this
-- table existed have an empty analysis_run_id and are reported as
-- legacy rather than being retrofitted to an invented run.
--
-- Superseded runs are KEPT. The findings they produced are gone (an
-- analysis replaces them atomically), but the record that the run
-- happened, when, and on which build is chain-of-custody information
-- and outlives its output.
CREATE TABLE IF NOT EXISTS analysis_runs (
	id                TEXT PRIMARY KEY,
	case_id           TEXT NOT NULL REFERENCES cases(id),
	started_at        TEXT NOT NULL,
	-- Empty string, not NULL, for "not finished" -- the same convention
	-- source_files.imported_at/deleted_at already use in this schema.
	completed_at      TEXT NOT NULL DEFAULT '',
	status            TEXT NOT NULL,
	tool_version      TEXT NOT NULL DEFAULT '',
	event_count       INTEGER NOT NULL DEFAULT 0,
	finding_count     INTEGER NOT NULL DEFAULT 0,
	correlation_count INTEGER NOT NULL DEFAULT 0,
	error             TEXT NOT NULL DEFAULT '',
	-- A completed run whose evidence was later deleted is INVALIDATED,
	-- not removed: the row, its counts and the findings it produced are
	-- all retained for audit, and none of them is ever presented as
	-- current again. Empty means the run still describes the evidence.
	invalidated_at      TEXT NOT NULL DEFAULT '',
	invalidation_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_case ON analysis_runs(case_id, started_at);

CREATE TABLE IF NOT EXISTS correlations (
	id            TEXT PRIMARY KEY,
	case_id       TEXT NOT NULL REFERENCES cases(id),
	type          TEXT NOT NULL,
	title         TEXT NOT NULL,
	description   TEXT NOT NULL,
	event_ids_json TEXT NOT NULL DEFAULT '[]',
	first_seen    TEXT NOT NULL,
	last_seen     TEXT NOT NULL,
	-- The run that produced this correlation, mirroring findings.
	analysis_run_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_correlations_case ON correlations(case_id);

-- ==================== Phase 6: analyst workflow ====================
-- Everything below is analyst-entered workflow state, never forensic
-- evidence and never produced by detect/correlate/investigate -- see
-- internal/model/workflow.go's package doc comment. All four tables are
-- independent of findings/correlations specifically so that
-- ReplaceAnalysis (which deletes and rebuilds those two tables on every
-- re-analysis) never touches any of this.

-- Free-text analyst annotations attachable to any target entity. Never
-- cascade-deleted when their target disappears (see model.Note's doc
-- comment) -- only a full case deletion removes them, alongside
-- everything else belonging to that case.
CREATE TABLE IF NOT EXISTS notes (
	id          TEXT PRIMARY KEY,
	case_id     TEXT NOT NULL REFERENCES cases(id),
	target_type TEXT NOT NULL,
	target_id   TEXT NOT NULL,
	note        TEXT NOT NULL,
	created_at  TEXT NOT NULL,
	updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_case ON notes(case_id);
CREATE INDEX IF NOT EXISTS idx_notes_target ON notes(target_type, target_id);

-- Lightweight labels, user-created or chosen from model.CommonTags.
CREATE TABLE IF NOT EXISTS tags (
	id          TEXT PRIMARY KEY,
	case_id     TEXT NOT NULL REFERENCES cases(id),
	target_type TEXT NOT NULL,
	target_id   TEXT NOT NULL,
	tag         TEXT NOT NULL,
	created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tags_case ON tags(case_id);
CREATE INDEX IF NOT EXISTS idx_tags_target ON tags(target_type, target_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tags_unique ON tags(target_type, target_id, tag);

-- Analyst review status for one Finding or Investigation (target_type
-- 'finding'|'investigation'). One row per target -- upserted, not
-- appended -- since a target has exactly one CURRENT status; note is a
-- short free-text explanation of the status change, not a full note
-- thread (use the notes table above for that). Never joined against
-- findings/correlations by foreign key, since target_id must remain
-- resolvable even after ReplaceAnalysis deletes the finding it once
-- pointed at (see model.AnalystStatus's doc comment).
CREATE TABLE IF NOT EXISTS analyst_status (
	case_id     TEXT NOT NULL REFERENCES cases(id),
	target_type TEXT NOT NULL,
	target_id   TEXT NOT NULL,
	status      TEXT NOT NULL,
	note        TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL,
	PRIMARY KEY (target_type, target_id)
);
CREATE INDEX IF NOT EXISTS idx_analyst_status_case ON analyst_status(case_id);

-- Append-only audit trail of analyst/system actions -- never raw
-- evidence content, never secrets (see model.AuditEvent's doc comment).
-- security_log records authentication and account-administration events
-- (Phase 12).
--
-- SEPARATE from audit_log, for two reasons:
--
--  1. audit_log.case_id is NOT NULL REFERENCES cases(id). A login, a
--     logout or a failed authentication belongs to no case, so it cannot
--     be stored there at all -- the foreign key rejects it.
--  2. The two answer different questions. audit_log is the forensic
--     record of what happened TO A CASE and travels with that case's
--     export; security_log is the operational record of who accessed the
--     SYSTEM. Mixing them would put account administration into every
--     case export.
--
-- case_id is present but unconstrained, so an event that does concern a
-- case (a denied request against one) can still say which.
-- app_settings holds APPLICATION-WIDE display preferences (Phase 14).
--
-- Deliberately a tiny key/value table rather than a typed one: the only
-- thing stored here so far is a display timezone, and inventing a schema
-- for a single row would be more structure than the problem has.
--
-- Nothing forensic lives here. These are PRESENTATION choices, and no
-- value in this table is allowed to influence stored timestamps,
-- hashes, evidence, ordering, or any analysis result. A case export
-- does not carry it, and changing it never invalidates an analysis --
-- which is exactly why it is not stored on a case or an evidence row.
CREATE TABLE IF NOT EXISTS app_settings (
	key        TEXT PRIMARY KEY,
	value      TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_log (
	id          TEXT PRIMARY KEY,
	timestamp   TEXT NOT NULL,
	action      TEXT NOT NULL,
	actor       TEXT NOT NULL DEFAULT 'unauthenticated',
	case_id     TEXT NOT NULL DEFAULT '',
	target_type TEXT NOT NULL DEFAULT '',
	target_id   TEXT NOT NULL DEFAULT '',
	summary     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_security_log_time ON security_log(timestamp);

-- users and sessions (Phase 12).
--
-- Local accounts only; Tracefall has no external identity provider.
-- password_hash holds an encoded PBKDF2 hash (see internal/auth) and
-- never a plaintext or reversible value.
CREATE TABLE IF NOT EXISTS users (
	id            TEXT PRIMARY KEY,
	-- username_lower carries the UNIQUE constraint so "Admin" and "admin"
	-- cannot both exist. Storing both forms keeps the display spelling the
	-- operator chose while making the uniqueness rule unambiguous -- the
	-- same approach cases already use for their names.
	username      TEXT NOT NULL,
	username_lower TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	role          TEXT NOT NULL,
	created_at    TEXT NOT NULL,
	disabled      INTEGER NOT NULL DEFAULT 0,
	last_login    TEXT NOT NULL DEFAULT '',
	-- must_change_password gates an account behind a mandatory password
	-- change. Set for the first-run bootstrap account, whose password was
	-- generated by the server and printed to a terminal -- a credential
	-- that has been displayed in plaintext must not remain usable
	-- indefinitely.
	--
	-- Persisted rather than held in memory so the requirement survives a
	-- restart: a bootstrap account whose password change could be escaped
	-- by restarting the process would not be a requirement at all.
	must_change_password INTEGER NOT NULL DEFAULT 0
);

-- sessions holds the HASH of each session token, never the token.
-- A stolen database therefore yields no usable cookies.
--
-- ON DELETE is not declared: DeleteUser removes a user's sessions
-- explicitly, in order, for the same reason DeleteCase does -- an
-- explicit ordered delete is auditable, a cascade is implicit.
CREATE TABLE IF NOT EXISTS sessions (
	id         TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL REFERENCES users(id),
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
	id          TEXT PRIMARY KEY,
	case_id     TEXT NOT NULL REFERENCES cases(id),
	timestamp   TEXT NOT NULL,
	action      TEXT NOT NULL,
	actor       TEXT NOT NULL DEFAULT 'local-user',
	target_type TEXT NOT NULL DEFAULT '',
	target_id   TEXT NOT NULL DEFAULT '',
	summary     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_log_case ON audit_log(case_id, timestamp);

-- Roadmap item 2: server-side pipeline jobs and resumable uploads.
-- OPERATIONAL state, not evidence: nothing here feeds detection or any
-- finding. Both are scoped to a case and are removed with it.
--
-- A job's (stage, collection_id) is its resume point: after a restart a
-- running job is put back to 'queued' and continues from there rather
-- than starting over.
CREATE TABLE IF NOT EXISTS pipeline_jobs (
	id               TEXT PRIMARY KEY,
	case_id          TEXT NOT NULL REFERENCES cases(id),
	kind             TEXT NOT NULL,
	status           TEXT NOT NULL,
	stage            TEXT NOT NULL DEFAULT 'queued',
	collection_id    TEXT NOT NULL DEFAULT '',
	params           TEXT NOT NULL DEFAULT '{}',
	progress         TEXT NOT NULL DEFAULT '',
	result           TEXT NOT NULL DEFAULT '',
	error            TEXT NOT NULL DEFAULT '',
	attempts         INTEGER NOT NULL DEFAULT 0,
	cancel_requested INTEGER NOT NULL DEFAULT 0,
	created_by       TEXT NOT NULL DEFAULT '',
	created_at       TEXT NOT NULL,
	started_at       TEXT NOT NULL DEFAULT '',
	finished_at      TEXT NOT NULL DEFAULT '',
	updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pipeline_jobs_case ON pipeline_jobs(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_pipeline_jobs_queue ON pipeline_jobs(status, created_at);

-- Answers from outside services about indicators read from evidence. Not
-- evidence: nothing here changes an event or a finding. One row per
-- (case, provider, indicator); a later answer replaces an earlier one.
CREATE TABLE IF NOT EXISTS enrichments (
	id               TEXT PRIMARY KEY,
	case_id          TEXT NOT NULL REFERENCES cases(id),
	provider         TEXT NOT NULL,
	indicator_type   TEXT NOT NULL,
	indicator        TEXT NOT NULL,
	status           TEXT NOT NULL,
	result_json      TEXT NOT NULL DEFAULT '{}',
	error            TEXT NOT NULL DEFAULT '',
	fetched_at       TEXT NOT NULL,
	source_event_ids TEXT NOT NULL DEFAULT '[]',
	UNIQUE (case_id, provider, indicator)
);
CREATE INDEX IF NOT EXISTS idx_enrichments_fetched ON enrichments(provider, fetched_at);

-- One row per request made to an outside service, kept for the service's
-- request allowance. It belongs to no case on purpose: the allowance is the
-- key's, so deleting a case must not give requests back. Rows hold the
-- provider and the time only; nothing about what was asked.
CREATE TABLE IF NOT EXISTS provider_requests (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	provider TEXT NOT NULL,
	at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provider_requests ON provider_requests(provider, at);

CREATE TABLE IF NOT EXISTS upload_sessions (
	id            TEXT PRIMARY KEY,
	case_id       TEXT NOT NULL REFERENCES cases(id),
	filename      TEXT NOT NULL,
	size          INTEGER NOT NULL,
	received      INTEGER NOT NULL DEFAULT 0,
	status        TEXT NOT NULL,
	client_sha256 TEXT NOT NULL DEFAULT '',
	created_by    TEXT NOT NULL DEFAULT '',
	created_at    TEXT NOT NULL,
	updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_case ON upload_sessions(case_id);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_status ON upload_sessions(status, updated_at);
`
