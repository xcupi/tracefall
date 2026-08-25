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
	updated_at  TEXT NOT NULL
);

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

CREATE TABLE IF NOT EXISTS source_files (
	id            TEXT PRIMARY KEY,
	case_id       TEXT NOT NULL REFERENCES cases(id),
	collection_id TEXT NOT NULL REFERENCES collections(id),
	path          TEXT NOT NULL,
	artifact_type TEXT NOT NULL,
	parser        TEXT NOT NULL,
	row_count     INTEGER NOT NULL,
	sha256        TEXT NOT NULL,
	ingested_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_source_files_case ON source_files(case_id);
-- idx_source_files_collection is created in migrate.go, not here: on a
-- database from before "collection_id" existed, this schema's
-- CREATE TABLE IF NOT EXISTS is a no-op (the table already exists
-- without that column), so an index on it here would fail before
-- migrate.go's ALTER TABLE gets a chance to add the column. See there.

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
`
