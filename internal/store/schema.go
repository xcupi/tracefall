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
-- internal/api.Service.createCollectionOrDuplicateError). Partial (WHERE
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
	import_status     TEXT NOT NULL DEFAULT 'discovered',
	event_count       INTEGER NOT NULL DEFAULT 0,
	discovered_at     TEXT NOT NULL,
	imported_at       TEXT NOT NULL DEFAULT '',
	deleted_at        TEXT NOT NULL DEFAULT ''
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
CREATE INDEX IF NOT EXISTS idx_events_case_ts ON events(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_case_type ON events(case_id, event_type);
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

CREATE TABLE IF NOT EXISTS correlations (
	id            TEXT PRIMARY KEY,
	case_id       TEXT NOT NULL REFERENCES cases(id),
	type          TEXT NOT NULL,
	title         TEXT NOT NULL,
	description   TEXT NOT NULL,
	event_ids_json TEXT NOT NULL DEFAULT '[]',
	first_seen    TEXT NOT NULL,
	last_seen     TEXT NOT NULL
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
`
