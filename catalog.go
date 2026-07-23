package forensic

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
)

const repositorySchema = `
CREATE TABLE IF NOT EXISTS repository_info (
  singleton INTEGER PRIMARY KEY CHECK (singleton=1), format_version INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, lookup_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
  description TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
  scope TEXT NOT NULL, operation TEXT NOT NULL, key TEXT NOT NULL,
  fingerprint TEXT NOT NULL, result_json TEXT NOT NULL,
  PRIMARY KEY(scope,operation,key)
);
CREATE TABLE IF NOT EXISTS maintenance_leases (
  case_id TEXT PRIMARY KEY REFERENCES cases(id), holder TEXT NOT NULL,
  acquired_at TEXT NOT NULL, expires_at TEXT NOT NULL
);`

const caseSchema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_info (
  singleton INTEGER PRIMARY KEY CHECK (singleton=1), id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL, description TEXT NOT NULL, format_version INTEGER NOT NULL,
  schema_version INTEGER NOT NULL, created_at TEXT NOT NULL, revision INTEGER NOT NULL,
  audit_head TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS revisions (
  revision INTEGER PRIMARY KEY, recorded_at TEXT NOT NULL, operation TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  sequence INTEGER PRIMARY KEY, revision INTEGER NOT NULL UNIQUE, previous_hash TEXT NOT NULL,
  event_json TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(kind,name)
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), label TEXT NOT NULL,
  started_at TEXT NOT NULL, closed_at TEXT
);
CREATE TABLE IF NOT EXISTS activities (
  id TEXT PRIMARY KEY, session_id TEXT REFERENCES sessions(id), agent_id TEXT NOT NULL REFERENCES agents(id),
  type TEXT NOT NULL, label TEXT NOT NULL, tool_json TEXT, config_json TEXT NOT NULL,
  config_digest TEXT NOT NULL, capture_mode TEXT NOT NULL, state TEXT NOT NULL,
  inputs_sealed INTEGER NOT NULL DEFAULT 0, sealed_revision INTEGER,
	parent_activity_id TEXT REFERENCES activities(id), execution_json TEXT,
	reported_started_at TEXT, reported_finished_at TEXT, time_source TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL, finished_at TEXT, outcome_json TEXT, idempotency_key TEXT
);
CREATE INDEX IF NOT EXISTS activities_session ON activities(session_id);
CREATE TABLE IF NOT EXISTS activity_agents (
	activity_id TEXT NOT NULL REFERENCES activities(id), agent_id TEXT NOT NULL REFERENCES agents(id),
	role TEXT NOT NULL, PRIMARY KEY(activity_id,agent_id,role)
);
CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, schema_uri TEXT NOT NULL DEFAULT '',
  schema_version INTEGER NOT NULL DEFAULT 1,
  generating_activity_id TEXT NOT NULL REFERENCES activities(id), created_revision INTEGER NOT NULL,
  created_at TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'committed', media_type TEXT NOT NULL DEFAULT '',
  display_name TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS entities_kind ON entities(kind,id);
CREATE INDEX IF NOT EXISTS entities_activity ON entities(generating_activity_id);
CREATE TABLE IF NOT EXISTS activity_inputs (
  activity_id TEXT NOT NULL REFERENCES activities(id), entity_id TEXT NOT NULL REFERENCES entities(id),
  role TEXT NOT NULL, PRIMARY KEY(activity_id,entity_id,role)
);
CREATE TABLE IF NOT EXISTS activity_outputs (
  activity_id TEXT NOT NULL REFERENCES activities(id), entity_id TEXT NOT NULL UNIQUE REFERENCES entities(id),
  role TEXT NOT NULL, PRIMARY KEY(activity_id,entity_id)
);
CREATE TABLE IF NOT EXISTS blobs (
  digest TEXT PRIMARY KEY, size INTEGER NOT NULL CHECK(size>=0), created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS objects (
  id TEXT PRIMARY KEY REFERENCES entities(id), blob_digest TEXT NOT NULL REFERENCES blobs(digest),
  size INTEGER NOT NULL CHECK(size>=0), role TEXT NOT NULL, path_display TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS objects_blob ON objects(blob_digest);
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY REFERENCES entities(id), label TEXT NOT NULL, acquisition_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_objects (
  evidence_id TEXT NOT NULL REFERENCES evidence(id), object_id TEXT NOT NULL REFERENCES objects(id),
  role TEXT NOT NULL, PRIMARY KEY(evidence_id,object_id)
);
CREATE TABLE IF NOT EXISTS source_trees (
  id TEXT PRIMARY KEY REFERENCES entities(id), evidence_id TEXT NOT NULL REFERENCES evidence(id),
  label TEXT NOT NULL, tree_digest TEXT NOT NULL, manifest_object_id TEXT NOT NULL REFERENCES objects(id),
  file_count INTEGER NOT NULL, total_bytes INTEGER NOT NULL, entry_count INTEGER NOT NULL,
  policy_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tree_entries (
  tree_id TEXT NOT NULL REFERENCES source_trees(id), ordinal INTEGER NOT NULL,
	path TEXT NOT NULL, raw_path BLOB NOT NULL DEFAULT X'', path_encoding TEXT NOT NULL DEFAULT '',
	path_separator TEXT NOT NULL DEFAULT '', entry_kind TEXT NOT NULL, file_mode INTEGER NOT NULL,
  size INTEGER NOT NULL, blob_digest TEXT, object_id TEXT REFERENCES objects(id), link_target TEXT NOT NULL,
  PRIMARY KEY(tree_id,ordinal), UNIQUE(tree_id,path),
  FOREIGN KEY(blob_digest) REFERENCES blobs(digest)
);
CREATE INDEX IF NOT EXISTS tree_entries_object ON tree_entries(object_id);
CREATE INDEX IF NOT EXISTS tree_entries_path ON tree_entries(tree_id,path);
CREATE TABLE IF NOT EXISTS source_locators (
  entity_id TEXT NOT NULL REFERENCES entities(id), locator_type TEXT NOT NULL,
  locator_json TEXT NOT NULL, PRIMARY KEY(entity_id,locator_type,locator_json)
);
CREATE TABLE IF NOT EXISTS artifacts (
	id TEXT PRIMARY KEY REFERENCES entities(id), artifact_type TEXT NOT NULL,
	source_object_id TEXT NOT NULL REFERENCES objects(id), producer_key TEXT NOT NULL DEFAULT '',
	producer_fingerprint TEXT NOT NULL DEFAULT '', generating_activity_id TEXT NOT NULL REFERENCES activities(id)
);
CREATE INDEX IF NOT EXISTS artifacts_type ON artifacts(artifact_type,id);
CREATE UNIQUE INDEX IF NOT EXISTS artifacts_producer_key ON artifacts(generating_activity_id,producer_key) WHERE producer_key<>'';
CREATE TABLE IF NOT EXISTS artifact_values (
  artifact_id TEXT NOT NULL REFERENCES artifacts(id), ordinal INTEGER NOT NULL,
  property TEXT NOT NULL, schema_uri TEXT NOT NULL DEFAULT '', value_type TEXT NOT NULL, raw TEXT NOT NULL,
  normalized_json TEXT, unit TEXT NOT NULL, encoding TEXT NOT NULL DEFAULT '', language TEXT NOT NULL,
  confidence REAL, interpretation TEXT NOT NULL DEFAULT '', locator_type TEXT, locator_json TEXT,
  PRIMARY KEY(artifact_id,ordinal)
);
CREATE INDEX IF NOT EXISTS artifact_values_property ON artifact_values(property,raw);
CREATE TABLE IF NOT EXISTS temporal_values (
  artifact_id TEXT NOT NULL REFERENCES artifacts(id), value_ordinal INTEGER NOT NULL,
  temporal_json TEXT NOT NULL, utc_start TEXT, utc_end TEXT, semantic_role TEXT NOT NULL,
  PRIMARY KEY(artifact_id,value_ordinal),
  FOREIGN KEY(artifact_id,value_ordinal) REFERENCES artifact_values(artifact_id,ordinal)
);
CREATE INDEX IF NOT EXISTS temporal_values_range ON temporal_values(semantic_role,utc_start,utc_end,artifact_id);
CREATE VIRTUAL TABLE IF NOT EXISTS artifact_fts USING fts5(artifact_id UNINDEXED, property UNINDEXED, text);
CREATE TABLE IF NOT EXISTS assertions (
	id TEXT PRIMARY KEY REFERENCES entities(id), assertion_type TEXT NOT NULL, body TEXT NOT NULL,
	confidence REAL, supersedes_id TEXT REFERENCES assertions(id), producer_key TEXT NOT NULL DEFAULT '',
	producer_fingerprint TEXT NOT NULL DEFAULT '', generating_activity_id TEXT NOT NULL REFERENCES activities(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS assertions_producer_key ON assertions(generating_activity_id,producer_key) WHERE producer_key<>'';
CREATE TABLE IF NOT EXISTS assertion_targets (
  assertion_id TEXT NOT NULL REFERENCES assertions(id), target_id TEXT NOT NULL REFERENCES entities(id),
  target_kind TEXT NOT NULL, PRIMARY KEY(assertion_id,target_id)
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, current_revision_id TEXT NOT NULL UNIQUE,
  current_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_revisions (
  id TEXT PRIMARY KEY REFERENCES entities(id), finding_id TEXT NOT NULL REFERENCES findings(id),
  version INTEGER NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL, confidence REAL,
	severity TEXT NOT NULL, review_state TEXT NOT NULL DEFAULT '', assignees_json TEXT NOT NULL DEFAULT '[]',
	vulnerability_json TEXT, predecessor_id TEXT REFERENCES finding_revisions(id),
  UNIQUE(finding_id,version)
);
CREATE TABLE IF NOT EXISTS finding_members (
  revision_id TEXT NOT NULL REFERENCES finding_revisions(id), entity_id TEXT NOT NULL REFERENCES entities(id),
  role TEXT NOT NULL, PRIMARY KEY(revision_id,entity_id,role)
);
CREATE TABLE IF NOT EXISTS selections (
  id TEXT PRIMARY KEY REFERENCES entities(id), name TEXT NOT NULL, observed_revision INTEGER NOT NULL,
  query_json TEXT NOT NULL, query_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS selection_members (
  selection_id TEXT NOT NULL REFERENCES selections(id), ordinal INTEGER NOT NULL,
  entity_id TEXT NOT NULL REFERENCES entities(id), kind TEXT NOT NULL,
  PRIMARY KEY(selection_id,ordinal), UNIQUE(selection_id,entity_id)
);
CREATE TABLE IF NOT EXISTS projections (
  id TEXT PRIMARY KEY REFERENCES entities(id), selection_id TEXT NOT NULL REFERENCES selections(id),
  spec_json TEXT NOT NULL, spec_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projection_members (
  projection_id TEXT NOT NULL REFERENCES projections(id), ordinal INTEGER NOT NULL,
  entity_id TEXT NOT NULL REFERENCES entities(id), kind TEXT NOT NULL, reason TEXT NOT NULL,
  PRIMARY KEY(projection_id,ordinal), UNIQUE(projection_id,entity_id)
);
CREATE TABLE IF NOT EXISTS projection_exclusions (
	projection_id TEXT NOT NULL REFERENCES projections(id), ordinal INTEGER NOT NULL,
	entity_id TEXT NOT NULL REFERENCES entities(id), kind TEXT NOT NULL, reason TEXT NOT NULL,
	PRIMARY KEY(projection_id,ordinal), UNIQUE(projection_id,entity_id)
);
CREATE TABLE IF NOT EXISTS materializations (
  id TEXT PRIMARY KEY, projection_id TEXT NOT NULL REFERENCES projections(id),
  destination TEXT NOT NULL, manifest_object_id TEXT NOT NULL REFERENCES objects(id),
  created_revision INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliverables (
	id TEXT PRIMARY KEY REFERENCES entities(id), selection_id TEXT REFERENCES selections(id),
	path_hint TEXT NOT NULL, package_sha256 TEXT NOT NULL, format TEXT NOT NULL DEFAULT '',
	closure TEXT NOT NULL DEFAULT '', manifest_object_id TEXT REFERENCES objects(id), spec_json TEXT NOT NULL DEFAULT '{}',
	version TEXT NOT NULL DEFAULT '', predecessor_id TEXT REFERENCES deliverables(id), recipient TEXT NOT NULL DEFAULT '',
	purpose TEXT NOT NULL DEFAULT '', redaction_policy TEXT NOT NULL DEFAULT '', verification_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS deliverable_members (
	deliverable_id TEXT NOT NULL REFERENCES deliverables(id), ordinal INTEGER NOT NULL,
	entity_id TEXT NOT NULL REFERENCES entities(id), kind TEXT NOT NULL, disposition TEXT NOT NULL,
	reason TEXT NOT NULL, emitted_path TEXT NOT NULL, blob_digest TEXT,
	PRIMARY KEY(deliverable_id,ordinal), UNIQUE(deliverable_id,entity_id),
	FOREIGN KEY(blob_digest) REFERENCES blobs(digest)
);
CREATE TABLE IF NOT EXISTS custody_events (
	activity_id TEXT PRIMARY KEY REFERENCES activities(id), item_entity_id TEXT NOT NULL REFERENCES entities(id),
	from_agent_id TEXT REFERENCES agents(id), to_agent_id TEXT REFERENCES agents(id),
	from_location TEXT NOT NULL, to_location TEXT NOT NULL, purpose TEXT NOT NULL,
	reference_number TEXT NOT NULL, occurred_at TEXT NOT NULL, recorded_at TEXT NOT NULL,
	acknowledgement_json TEXT NOT NULL, signature BLOB, created_revision INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS custody_events_item ON custody_events(item_entity_id,occurred_at,activity_id);
CREATE TABLE IF NOT EXISTS idempotency_keys (
  scope TEXT NOT NULL, operation TEXT NOT NULL, key TEXT NOT NULL,
  fingerprint TEXT NOT NULL, result_json TEXT NOT NULL,
  PRIMARY KEY(scope,operation,key)
);
CREATE TABLE IF NOT EXISTS maintenance_leases (
  name TEXT PRIMARY KEY, holder TEXT NOT NULL, acquired_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS parser_cache (
  cache_key TEXT PRIMARY KEY, parser_id TEXT NOT NULL, parser_version TEXT NOT NULL,
  parser_build_digest TEXT NOT NULL, config_digest TEXT NOT NULL,
  input_object_id TEXT NOT NULL REFERENCES objects(id), source_activity_id TEXT NOT NULL REFERENCES activities(id),
  created_revision INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS parser_cache_outputs (
  cache_key TEXT NOT NULL REFERENCES parser_cache(cache_key), ordinal INTEGER NOT NULL,
  entity_id TEXT NOT NULL REFERENCES entities(id), PRIMARY KEY(cache_key,ordinal),
  UNIQUE(cache_key,entity_id)
);`

func sqliteDSN(path string, busy time.Duration) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("_txlock", "immediate")
	q.Add("_pragma", "journal_mode=WAL")
	q.Add("_pragma", "synchronous=FULL")
	q.Add("_pragma", "foreign_keys=ON")
	q.Add("_pragma", "trusted_schema=OFF")
	q.Add("_pragma", fmt.Sprintf("busy_timeout=%d", busy.Milliseconds()))
	return abs + "?" + q.Encode(), nil
}

func openSQLite(ctx context.Context, path string, busy time.Duration) (*sql.DB, error) {
	if busy <= 0 {
		busy = 5 * time.Second
	}
	dsn, err := sqliteDSN(path, busy)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, mapSQLError(err)
	}
	return db, nil
}

func openSQLiteReadOnly(ctx context.Context, path string, busy time.Duration) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if busy <= 0 {
		busy = 5 * time.Second
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "trusted_schema(0)")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busy.Milliseconds()))
	dsn := "file:" + filepath.ToSlash(abs) + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open read-only sqlite: %w", err)
	}
	db.SetMaxOpenConns(4)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, mapSQLError(err)
	}
	return db, nil
}

type sqliteBackuper interface {
	NewBackup(string) (*sqlite.Backup, error)
}

func onlineBackup(ctx context.Context, db *sql.DB, destination string) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return mapSQLError(err)
	}
	defer conn.Close()
	return conn.Raw(func(driverConn any) error {
		b, ok := driverConn.(sqliteBackuper)
		if !ok {
			return fmt.Errorf("%w: SQLite driver has no online backup support", ErrUnsupported)
		}
		backup, err := b.NewBackup(destination)
		if err != nil {
			return err
		}
		finished := false
		defer func() {
			if !finished {
				_ = backup.Finish()
			}
		}()
		for more := true; more; {
			if err = ctx.Err(); err != nil {
				return err
			}
			more, err = backup.Step(256)
			if err != nil {
				return mapSQLError(err)
			}
		}
		err = backup.Finish()
		finished = true
		return mapSQLError(err)
	})
}

func execSchema(ctx context.Context, db *sql.DB, schema string) error {
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return mapSQLError(err)
	}
	return nil
}

func validateCaseCatalog(ctx context.Context, db *sql.DB, want CaseID) error {
	var id CaseID
	var format, version int
	err := db.QueryRowContext(ctx, "SELECT id,format_version,schema_version FROM case_info WHERE singleton=1").Scan(&id, &format, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: missing case metadata", ErrIntegrity)
	}
	if err != nil {
		return mapSQLError(err)
	}
	if id != want {
		return fmt.Errorf("%w: marker and catalog case IDs differ", ErrIntegrity)
	}
	if format != CaseFormat {
		return fmt.Errorf("%w: case format %d", ErrUnsupportedStorage, format)
	}
	if version > SchemaVersion {
		return fmt.Errorf("%w: schema version %d is newer than supported version %d", ErrUnsupportedStorage, version, SchemaVersion)
	}
	if version < SchemaVersion {
		return fmt.Errorf("%w: no migration from schema version %d", ErrUnsupportedStorage, version)
	}
	return validateRequiredCaseSchema(ctx, db)
}

func validateRequiredCaseSchema(ctx context.Context, db *sql.DB) error {
	required := map[string][]string{
		"schema_migrations":     {"version", "applied_at"},
		"case_info":             {"id", "format_version", "schema_version", "revision", "audit_head"},
		"revisions":             {"revision"},
		"audit_events":          {"sequence", "revision", "event_json", "event_hash"},
		"agents":                {"id", "kind", "name"},
		"sessions":              {"id", "agent_id"},
		"activities":            {"id", "parent_activity_id", "execution_json", "reported_started_at", "reported_finished_at", "time_source"},
		"activity_agents":       {"activity_id", "agent_id", "role"},
		"entities":              {"id", "kind", "generating_activity_id", "created_revision"},
		"activity_inputs":       {"activity_id", "entity_id", "role"},
		"activity_outputs":      {"activity_id", "entity_id", "role"},
		"blobs":                 {"digest", "size"},
		"objects":               {"id", "blob_digest", "size"},
		"evidence":              {"id", "acquisition_json"},
		"evidence_objects":      {"evidence_id", "object_id", "role"},
		"source_trees":          {"id", "evidence_id", "manifest_object_id", "tree_digest"},
		"tree_entries":          {"tree_id", "path", "raw_path", "path_encoding", "path_separator", "entry_kind", "object_id"},
		"source_locators":       {"entity_id", "locator_type", "locator_json"},
		"artifacts":             {"id", "source_object_id", "producer_fingerprint"},
		"artifact_values":       {"artifact_id", "schema_uri", "encoding", "interpretation", "locator_json"},
		"temporal_values":       {"artifact_id", "value_ordinal", "temporal_json"},
		"artifact_fts":          {"artifact_id", "property", "text"},
		"assertions":            {"id", "assertion_type", "supersedes_id"},
		"assertion_targets":     {"assertion_id", "target_id", "target_kind"},
		"findings":              {"id", "current_revision_id"},
		"finding_revisions":     {"id", "finding_id", "review_state", "assignees_json", "vulnerability_json"},
		"finding_members":       {"revision_id", "entity_id", "role"},
		"selections":            {"id", "observed_revision", "query_json"},
		"selection_members":     {"selection_id", "entity_id", "kind"},
		"projections":           {"id", "selection_id", "spec_json"},
		"projection_members":    {"projection_id", "entity_id", "kind"},
		"projection_exclusions": {"projection_id", "entity_id", "reason"},
		"materializations":      {"id", "projection_id", "manifest_object_id"},
		"deliverables":          {"id", "format", "closure", "manifest_object_id", "verification_json"},
		"deliverable_members":   {"deliverable_id", "entity_id", "disposition"},
		"custody_events":        {"activity_id", "item_entity_id", "occurred_at"},
		"idempotency_keys":      {"scope", "operation", "key", "fingerprint"},
		"maintenance_leases":    {"name", "holder", "expires_at"},
		"parser_cache":          {"cache_key", "input_object_id", "source_activity_id"},
		"parser_cache_outputs":  {"cache_key", "ordinal", "entity_id"},
	}
	for table, columns := range required {
		rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
		if err != nil {
			return mapSQLError(err)
		}
		found := map[string]bool{}
		for rows.Next() {
			var ordinal, notNull, primaryKey int
			var name, columnType string
			var defaultValue any
			if err = rows.Scan(&ordinal, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				rows.Close()
				return err
			}
			found[name] = true
		}
		if err = rows.Close(); err != nil {
			return err
		}
		for _, column := range columns {
			if !found[column] {
				return fmt.Errorf("%w: schema version %d lacks %s.%s", ErrIntegrity, SchemaVersion, table, column)
			}
		}
	}
	return nil
}

func mapSQLError(err error) error {
	if err == nil {
		return nil
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "database is locked"), strings.Contains(s, "database is busy"), strings.Contains(s, "sqlite_busy"):
		return fmt.Errorf("%w: %v", ErrBusy, err)
	case strings.Contains(s, "unique constraint"), strings.Contains(s, "constraint failed"):
		return fmt.Errorf("%w: %v", ErrConflict, err)
	case strings.Contains(s, "foreign key constraint"):
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	default:
		return err
	}
}

type mutationEvent struct {
	Domain        string    `json:"domain"`
	Sequence      int64     `json:"sequence"`
	Revision      int64     `json:"revision"`
	PreviousHash  string    `json:"previous_hash"`
	Actor         AgentID   `json:"actor,omitempty"`
	Session       SessionID `json:"session,omitempty"`
	Operation     string    `json:"operation"`
	Affected      []string  `json:"affected,omitempty"`
	RequestDigest string    `json:"request_digest,omitempty"`
	RecordedAt    string    `json:"recorded_at"`
}

var errIdempotentReplay = errors.New("forensic: internal idempotent replay")

func (c *Case) mutate(ctx context.Context, actor AgentID, session SessionID, operation, requestDigest string, affected []string, apply func(*sql.Tx, int64) error) (int64, error) {
	if err := c.checkOpen(); err != nil {
		return 0, err
	}
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		tx, err := c.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			last = mapSQLError(err)
			if !errors.Is(last, ErrBusy) {
				return 0, last
			}
			continue
		}
		var rev int64
		var head string
		if err = tx.QueryRowContext(ctx, "SELECT revision,audit_head FROM case_info WHERE singleton=1").Scan(&rev, &head); err != nil {
			tx.Rollback()
			return 0, mapSQLError(err)
		}
		next := rev + 1
		if err = apply(tx, next); err != nil {
			tx.Rollback()
			if errors.Is(err, errIdempotentReplay) {
				return rev, nil
			}
			return 0, mapSQLError(err)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		event := mutationEvent{Domain: "forensic-audit-v1", Sequence: next, Revision: next, PreviousHash: head, Actor: actor, Session: session, Operation: operation, Affected: affected, RequestDigest: requestDigest, RecordedAt: now}
		body, err := canonicalJSON(event)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
		h := sha256.New()
		h.Write([]byte(event.Domain))
		h.Write([]byte(fmt.Sprint(next)))
		h.Write([]byte(head))
		h.Write(body)
		eventHash := hex.EncodeToString(h.Sum(nil))
		if _, err = tx.ExecContext(ctx, "INSERT INTO revisions(revision,recorded_at,operation) VALUES(?,?,?)", next, now, operation); err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO audit_events(sequence,revision,previous_hash,event_json,event_hash) VALUES(?,?,?,?,?)", next, next, head, string(body), eventHash)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, "UPDATE case_info SET revision=?,audit_head=? WHERE singleton=1", next, eventHash)
		}
		if err == nil {
			err = c.injectFault("before-catalog-commit")
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err == nil {
			if injected := c.injectFault("after-catalog-commit"); injected != nil {
				return 0, injected
			}
			return next, nil
		}
		last = mapSQLError(err)
		if !errors.Is(last, ErrBusy) {
			return 0, last
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 10 * time.Millisecond):
		}
	}
	return 0, last
}

func lookupIdempotency(ctx context.Context, tx *sql.Tx, scope, operation, key, fingerprint string, out any) (bool, error) {
	if key == "" {
		return false, nil
	}
	var fp, result string
	err := tx.QueryRowContext(ctx, "SELECT fingerprint,result_json FROM idempotency_keys WHERE scope=? AND operation=? AND key=?", scope, operation, key).Scan(&fp, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fp != fingerprint {
		return false, fmt.Errorf("%w: idempotency key reused with a different request", ErrConflict)
	}
	if out != nil && json.Unmarshal([]byte(result), out) != nil {
		return false, fmt.Errorf("%w: invalid idempotency record", ErrIntegrity)
	}
	return true, nil
}

func storeIdempotency(ctx context.Context, tx *sql.Tx, scope, operation, key, fingerprint string, result any) error {
	if key == "" {
		return nil
	}
	b, err := canonicalJSON(result)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(scope,operation,key,fingerprint,result_json) VALUES(?,?,?,?,?)", scope, operation, key, fingerprint, string(b))
	return err
}
