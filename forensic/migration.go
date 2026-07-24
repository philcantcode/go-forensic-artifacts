package forensic

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MigrateCase explicitly upgrades a supported older case catalog. It blocks
// new opens through a repository maintenance lease, takes and verifies a live
// SQLite backup, and records the schema change in the case audit chain.
func (r *Repository) MigrateCase(ctx context.Context, selector CaseSelector, spec MigrationSpec) (result MigrationResult, err error) {
	if err = r.checkOpen(); err != nil {
		return result, err
	}
	id, err := r.resolveCaseForMaintenance(ctx, selector)
	if err != nil {
		return result, err
	}
	result.Case = id
	holder, err := newID("lease_")
	if err != nil {
		return result, err
	}
	if spec.LeaseDuration <= 0 {
		spec.LeaseDuration = 5 * time.Minute
	}
	if spec.LeaseDuration < time.Minute || spec.LeaseDuration > 24*time.Hour {
		return result, fmt.Errorf("%w: lease duration must be between one minute and 24 hours", ErrInvalid)
	}
	if err = r.acquireMaintenanceLease(ctx, id, holder, spec.LeaseDuration); err != nil {
		return result, err
	}
	defer func() {
		releaseErr := r.releaseMaintenanceLease(context.WithoutCancel(ctx), id, holder)
		if err == nil && releaseErr != nil {
			err = releaseErr
		}
	}()

	root := filepath.Join(r.root, "cases", string(id))
	db, err := openSQLite(ctx, filepath.Join(root, "catalog.sqlite3"), r.busy)
	if err != nil {
		return result, err
	}
	defer db.Close()
	var catalogID CaseID
	var format, version int
	if err = db.QueryRowContext(ctx, "SELECT id,format_version,schema_version FROM case_info WHERE singleton=1").Scan(&catalogID, &format, &version); err != nil {
		return result, mapSQLError(err)
	}
	if catalogID != id || format != CaseFormat {
		return result, fmt.Errorf("%w: invalid case catalog identity or format", ErrIntegrity)
	}
	result.FromVersion, result.ToVersion = version, version
	if version == SchemaVersion {
		var revision int64
		if err = db.QueryRowContext(ctx, "SELECT revision FROM case_info WHERE singleton=1").Scan(&revision); err != nil {
			return result, mapSQLError(err)
		}
		result.Revision = revision
		return result, nil
	}
	if version > SchemaVersion || version < 1 {
		return result, fmt.Errorf("%w: no migration from schema version %d", ErrUnsupportedStorage, version)
	}

	backupPath := strings.TrimSpace(spec.BackupPath)
	if backupPath == "" {
		backupPath = filepath.Join(root, "checkpoints", fmt.Sprintf("pre-migration-v%d-%s.sqlite3", version, strings.TrimPrefix(holder, "lease_")))
	} else if backupPath, err = filepath.Abs(backupPath); err != nil {
		return result, err
	}
	if inside, _ := pathWithin(root, backupPath); inside && filepath.Dir(backupPath) != filepath.Join(root, "checkpoints") {
		return result, fmt.Errorf("%w: migration backup inside the case must be in checkpoints", ErrInvalid)
	}
	if err = os.MkdirAll(filepath.Dir(backupPath), 0700); err != nil {
		return result, err
	}
	if _, statErr := os.Lstat(backupPath); statErr == nil {
		return result, fmt.Errorf("%w: migration backup already exists", ErrConflict)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return result, statErr
	}
	if err = onlineBackup(ctx, db, backupPath); err != nil {
		return result, err
	}
	result.BackupPath = backupPath
	if err = verifySQLiteBackup(ctx, backupPath, r.busy, id, version); err != nil {
		return result, err
	}

	for version < SchemaVersion {
		switch version {
		case 1:
			result.Revision, err = migrateCaseV1ToV2(ctx, db, id)
			version = 2
		default:
			return result, fmt.Errorf("%w: no migration from schema version %d", ErrUnsupportedStorage, version)
		}
		if err != nil {
			return result, err
		}
	}
	result.ToVersion = version
	if err = validateCaseCatalog(ctx, db, id); err != nil {
		return result, err
	}
	return result, nil
}

func (r *Repository) resolveCaseForMaintenance(ctx context.Context, selector CaseSelector) (CaseID, error) {
	var row *sql.Row
	if selector.id != "" {
		row = r.db.QueryRowContext(ctx, "SELECT id FROM cases WHERE id=? AND state IN ('active','maintenance')", selector.id)
	} else {
		lookup, err := normalizeCaseName(selector.name)
		if err != nil {
			return "", err
		}
		row = r.db.QueryRowContext(ctx, "SELECT id FROM cases WHERE lookup_key=? AND state IN ('active','maintenance')", lookup)
	}
	var id CaseID
	if err := row.Scan(&id); errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", mapSQLError(err)
	}
	return id, nil
}

func (r *Repository) acquireMaintenanceLease(ctx context.Context, id CaseID, holder string, duration time.Duration) error {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if _, err = tx.ExecContext(ctx, "DELETE FROM maintenance_leases WHERE case_id=? AND expires_at<=?", id, now.Format(time.RFC3339Nano)); err != nil {
		return mapSQLError(err)
	}
	var existing string
	err = tx.QueryRowContext(ctx, "SELECT holder FROM maintenance_leases WHERE case_id=?", id).Scan(&existing)
	if err == nil {
		return fmt.Errorf("%w: case has an active maintenance lease", ErrBusy)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return mapSQLError(err)
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO maintenance_leases(case_id,holder,acquired_at,expires_at) VALUES(?,?,?,?)", id, holder, now.Format(time.RFC3339Nano), now.Add(duration).Format(time.RFC3339Nano)); err != nil {
		return mapSQLError(err)
	}
	if result, updateErr := tx.ExecContext(ctx, "UPDATE cases SET state='maintenance' WHERE id=? AND state IN ('active','maintenance')", id); updateErr != nil {
		return mapSQLError(updateErr)
	} else if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrNotFound
	}
	return mapSQLError(tx.Commit())
}

func (r *Repository) releaseMaintenanceLease(ctx context.Context, id CaseID, holder string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return mapSQLError(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM maintenance_leases WHERE case_id=? AND holder=?", id, holder); err != nil {
		return mapSQLError(err)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE cases SET state='active' WHERE id=? AND state='maintenance' AND NOT EXISTS (SELECT 1 FROM maintenance_leases WHERE case_id=?)", id, id); err != nil {
		return mapSQLError(err)
	}
	return mapSQLError(tx.Commit())
}

func verifySQLiteBackup(ctx context.Context, path string, busy time.Duration, id CaseID, version int) error {
	db, err := openSQLiteReadOnly(ctx, path, busy)
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("%w: migration backup integrity check: %s: %v", ErrIntegrity, integrity, err)
	}
	var gotID CaseID
	var gotVersion int
	if err = db.QueryRowContext(ctx, "SELECT id,schema_version FROM case_info WHERE singleton=1").Scan(&gotID, &gotVersion); err != nil {
		return mapSQLError(err)
	}
	if gotID != id || gotVersion != version {
		return fmt.Errorf("%w: migration backup identity/version mismatch", ErrIntegrity)
	}
	return nil
}

func migrateCaseV1ToV2(ctx context.Context, db *sql.DB, id CaseID) (int64, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, mapSQLError(err)
	}
	defer tx.Rollback()
	columns := []struct{ table, name, declaration string }{
		{"activities", "parent_activity_id", "TEXT REFERENCES activities(id)"},
		{"activities", "execution_json", "TEXT"},
		{"activities", "reported_started_at", "TEXT"},
		{"activities", "reported_finished_at", "TEXT"},
		{"activities", "time_source", "TEXT NOT NULL DEFAULT ''"},
		{"artifact_values", "schema_uri", "TEXT NOT NULL DEFAULT ''"},
		{"artifact_values", "encoding", "TEXT NOT NULL DEFAULT ''"},
		{"artifact_values", "interpretation", "TEXT NOT NULL DEFAULT ''"},
		{"tree_entries", "raw_path", "BLOB NOT NULL DEFAULT X''"},
		{"tree_entries", "path_encoding", "TEXT NOT NULL DEFAULT ''"},
		{"tree_entries", "path_separator", "TEXT NOT NULL DEFAULT ''"},
		{"finding_revisions", "review_state", "TEXT NOT NULL DEFAULT ''"},
		{"finding_revisions", "assignees_json", "TEXT NOT NULL DEFAULT '[]'"},
		{"finding_revisions", "vulnerability_json", "TEXT"},
		{"deliverables", "format", "TEXT NOT NULL DEFAULT ''"},
		{"deliverables", "closure", "TEXT NOT NULL DEFAULT ''"},
		{"deliverables", "manifest_object_id", "TEXT REFERENCES objects(id)"},
		{"deliverables", "spec_json", "TEXT NOT NULL DEFAULT '{}'"},
		{"deliverables", "version", "TEXT NOT NULL DEFAULT ''"},
		{"deliverables", "predecessor_id", "TEXT REFERENCES deliverables(id)"},
		{"deliverables", "recipient", "TEXT NOT NULL DEFAULT ''"},
		{"deliverables", "purpose", "TEXT NOT NULL DEFAULT ''"},
		{"deliverables", "redaction_policy", "TEXT NOT NULL DEFAULT ''"},
		{"deliverables", "verification_json", "TEXT NOT NULL DEFAULT '{}'"},
	}
	for _, column := range columns {
		if err = addColumnIfMissing(ctx, tx, column.table, column.name, column.declaration); err != nil {
			return 0, err
		}
	}
	if err = execTxSchema(ctx, tx, caseSchemaV2Additions); err != nil {
		return 0, err
	}
	var revision int64
	var head string
	if err = tx.QueryRowContext(ctx, "SELECT revision,audit_head FROM case_info WHERE singleton=1").Scan(&revision, &head); err != nil {
		return 0, mapSQLError(err)
	}
	var actor AgentID
	if err = tx.QueryRowContext(ctx, "SELECT id FROM agents ORDER BY created_at,id LIMIT 1").Scan(&actor); err != nil {
		return 0, mapSQLError(err)
	}
	next := revision + 1
	now := time.Now().UTC().Format(time.RFC3339Nano)
	requestDigest, _, _ := digestJSON(struct{ From, To int }{1, 2})
	event := mutationEvent{Domain: "forensic-audit-v1", Sequence: next, Revision: next, PreviousHash: head, Actor: actor, Operation: "schema.migrate", Affected: []string{string(id)}, RequestDigest: requestDigest, RecordedAt: now}
	body, err := canonicalJSON(event)
	if err != nil {
		return 0, err
	}
	hash := sha256.New()
	hash.Write([]byte(event.Domain))
	hash.Write([]byte(fmt.Sprint(next)))
	hash.Write([]byte(head))
	hash.Write(body)
	eventHash := hex.EncodeToString(hash.Sum(nil))
	statements := []struct {
		query string
		args  []any
	}{
		{"INSERT INTO schema_migrations(version,applied_at) VALUES(2,?)", []any{now}},
		{"INSERT INTO revisions(revision,recorded_at,operation) VALUES(?,?,'schema.migrate')", []any{next, now}},
		{"INSERT INTO audit_events(sequence,revision,previous_hash,event_json,event_hash) VALUES(?,?,?,?,?)", []any{next, next, head, string(body), eventHash}},
		{"UPDATE case_info SET schema_version=2,revision=?,audit_head=? WHERE singleton=1 AND schema_version=1", []any{next, eventHash}},
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return 0, mapSQLError(err)
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, mapSQLError(err)
	}
	return next, nil
}

const caseSchemaV2Additions = `
CREATE TABLE IF NOT EXISTS activity_agents (
  activity_id TEXT NOT NULL REFERENCES activities(id), agent_id TEXT NOT NULL REFERENCES agents(id),
  role TEXT NOT NULL, PRIMARY KEY(activity_id,agent_id,role)
);
CREATE TABLE IF NOT EXISTS temporal_values (
  artifact_id TEXT NOT NULL REFERENCES artifacts(id), value_ordinal INTEGER NOT NULL,
  temporal_json TEXT NOT NULL, utc_start TEXT, utc_end TEXT, semantic_role TEXT NOT NULL,
  PRIMARY KEY(artifact_id,value_ordinal),
  FOREIGN KEY(artifact_id,value_ordinal) REFERENCES artifact_values(artifact_id,ordinal)
);
CREATE INDEX IF NOT EXISTS temporal_values_range ON temporal_values(semantic_role,utc_start,utc_end,artifact_id);
CREATE TABLE IF NOT EXISTS projection_exclusions (
  projection_id TEXT NOT NULL REFERENCES projections(id), ordinal INTEGER NOT NULL,
  entity_id TEXT NOT NULL REFERENCES entities(id), kind TEXT NOT NULL, reason TEXT NOT NULL,
  PRIMARY KEY(projection_id,ordinal), UNIQUE(projection_id,entity_id)
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
CREATE TABLE IF NOT EXISTS maintenance_leases (
  name TEXT PRIMARY KEY, holder TEXT NOT NULL, acquired_at TEXT NOT NULL, expires_at TEXT NOT NULL
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

func addColumnIfMissing(ctx context.Context, tx *sql.Tx, table, column, declaration string) error {
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return mapSQLError(err)
	}
	found := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue any
		if err = rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = tx.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+declaration)
	return mapSQLError(err)
}

func execTxSchema(ctx context.Context, tx *sql.Tx, schema string) error {
	for _, statement := range strings.Split(schema, ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return mapSQLError(err)
		}
	}
	return nil
}
