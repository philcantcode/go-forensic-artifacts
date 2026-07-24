package forensic

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// InspectRecovery reports recoverable repository state without changing or
// deleting anything. In-progress directories are never inferred from names
// alone; a valid self-identifying marker and catalog are required.
func (r *Repository) InspectRecovery(ctx context.Context) (RepositoryRecoveryReport, error) {
	if err := r.checkOpen(); err != nil {
		return RepositoryRecoveryReport{}, err
	}
	registry := map[CaseID]string{}
	rows, err := r.db.QueryContext(ctx, "SELECT id,state FROM cases")
	if err != nil {
		return RepositoryRecoveryReport{}, mapSQLError(err)
	}
	for rows.Next() {
		var id CaseID
		var state string
		if err = rows.Scan(&id, &state); err != nil {
			rows.Close()
			return RepositoryRecoveryReport{}, err
		}
		registry[id] = state
	}
	if err = rows.Close(); err != nil {
		return RepositoryRecoveryReport{}, err
	}
	var report RepositoryRecoveryReport
	casesRoot := filepath.Join(r.root, "cases")
	entries, err := os.ReadDir(casesRoot)
	if err != nil {
		return report, err
	}
	seen := map[CaseID]bool{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(casesRoot, entry.Name())
		candidate := inspectCaseDirectory(ctx, r, path)
		if candidate.ID != "" {
			seen[candidate.ID] = true
			candidate.RegistryState = registry[candidate.ID]
		}
		partial := strings.HasPrefix(entry.Name(), ".creating-")
		switch {
		case !candidate.Valid:
			report.Issues = append(report.Issues, candidate)
		case partial:
			candidate.CanComplete = candidate.RegistryState == "creating"
			report.Creating = append(report.Creating, candidate)
		case candidate.RegistryState == "":
			candidate.CanComplete = true
			report.Unregistered = append(report.Unregistered, candidate)
		case candidate.RegistryState == "creating":
			candidate.CanComplete = true
			report.Creating = append(report.Creating, candidate)
		}
	}
	for id, state := range registry {
		if state == "creating" && !seen[id] {
			report.Creating = append(report.Creating, RecoveryCaseDirectory{ID: id, RegistryState: state, Path: filepath.Join(casesRoot, string(id)), Detail: "registry reservation has no case directory"})
		}
	}
	sortRecoveryCases(report.Creating)
	sortRecoveryCases(report.Unregistered)
	sortRecoveryCases(report.Issues)
	return report, nil
}

func inspectCaseDirectory(ctx context.Context, repository *Repository, path string) RecoveryCaseDirectory {
	candidate := RecoveryCaseDirectory{Path: path}
	body, err := os.ReadFile(filepath.Join(path, "case.json"))
	if err != nil {
		candidate.Detail = "missing case marker: " + err.Error()
		return candidate
	}
	var marker caseMarker
	if json.Unmarshal(body, &marker) != nil || marker.Format != CaseFormat || marker.ID == "" {
		candidate.Detail = "invalid case marker"
		return candidate
	}
	candidate.ID = marker.ID
	catalogPath := filepath.Join(path, "catalog.sqlite3")
	if _, err = os.Stat(catalogPath); err != nil {
		candidate.Detail = "missing catalog: " + err.Error()
		return candidate
	}
	db, err := openSQLiteReadOnly(ctx, catalogPath, repository.busy)
	if err != nil {
		candidate.Detail = "cannot open catalog: " + err.Error()
		return candidate
	}
	defer db.Close()
	if err = validateCaseCatalog(ctx, db, marker.ID); err != nil {
		candidate.Detail = err.Error()
		return candidate
	}
	candidate.Valid = true
	return candidate
}

func sortRecoveryCases(cases []RecoveryCaseDirectory) {
	sort.Slice(cases, func(i, j int) bool {
		if cases[i].ID == cases[j].ID {
			return cases[i].Path < cases[j].Path
		}
		return cases[i].ID < cases[j].ID
	})
}

// RecoverCaseRegistration completes a specifically named valid case
// registration. It may publish a valid .creating directory for that ID or
// re-register a valid final directory. It never removes a directory.
func (r *Repository) RecoverCaseRegistration(ctx context.Context, id CaseID) (*Case, error) {
	if err := r.checkOpen(); err != nil {
		return nil, err
	}
	if !validID(string(id), "case_") {
		return nil, fmt.Errorf("%w: invalid case ID", ErrInvalid)
	}
	casesRoot := filepath.Join(r.root, "cases")
	finalPath := filepath.Join(casesRoot, string(id))
	partialPath := filepath.Join(casesRoot, ".creating-"+string(id))
	changed := false
	if _, err := os.Stat(finalPath); errors.Is(err, os.ErrNotExist) {
		candidate := inspectCaseDirectory(ctx, r, partialPath)
		if !candidate.Valid || candidate.ID != id {
			return nil, fmt.Errorf("%w: no valid recoverable case directory for %s", ErrNotFound, id)
		}
		if err = renameWithRetry(ctx, partialPath, finalPath); err != nil {
			return nil, err
		}
		changed = true
		_ = syncDirectory(casesRoot)
	} else if err != nil {
		return nil, err
	}
	candidate := inspectCaseDirectory(ctx, r, finalPath)
	if !candidate.Valid || candidate.ID != id {
		return nil, fmt.Errorf("%w: invalid case directory for %s: %s", ErrIntegrity, id, candidate.Detail)
	}
	db, err := openSQLite(ctx, filepath.Join(finalPath, "catalog.sqlite3"), r.busy)
	if err != nil {
		return nil, err
	}
	var name, description, createdAt string
	if err = db.QueryRowContext(ctx, "SELECT name,description,created_at FROM case_info WHERE singleton=1").Scan(&name, &description, &createdAt); err != nil {
		db.Close()
		return nil, err
	}
	_ = db.Close()
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer tx.Rollback()
	var state string
	err = tx.QueryRowContext(ctx, "SELECT state FROM cases WHERE id=?", id).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		lookup, normalizeErr := normalizeCaseName(name)
		if normalizeErr != nil {
			return nil, normalizeErr
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO cases(id,lookup_key,name,description,state,created_at) VALUES(?,?,?,?,?,?)", id, lookup, name, description, "active", createdAt); err != nil {
			return nil, mapSQLError(err)
		}
		changed = true
	} else if err != nil {
		return nil, mapSQLError(err)
	} else if state == "creating" {
		if _, err = tx.ExecContext(ctx, "UPDATE cases SET state='active' WHERE id=? AND state='creating'", id); err != nil {
			return nil, mapSQLError(err)
		}
		changed = true
	} else if state != "active" {
		return nil, fmt.Errorf("%w: case registry state is %s", ErrConflict, state)
	}
	if err = tx.Commit(); err != nil {
		return nil, mapSQLError(err)
	}
	caseRef, err := r.OpenCase(ctx, ByID(id))
	if err != nil {
		return nil, err
	}
	if !changed {
		return caseRef, nil
	}
	_, auditErr := caseRef.mutate(ctx, caseRef.defaultAgent.ID, "", "recovery.case-registration", "", []string{string(id)}, func(*sql.Tx, int64) error { return nil })
	if auditErr != nil {
		caseRef.Close()
		return nil, auditErr
	}
	return caseRef, nil
}

// InspectRecovery reports case-local staging files, final CAS orphans, and
// running activities. It is read-only and does not guess whether a process is
// still alive.
func (c *Case) InspectRecovery(ctx context.Context) (CaseRecoveryReport, error) {
	if err := c.checkOpen(); err != nil {
		return CaseRecoveryReport{}, err
	}
	report := CaseRecoveryReport{Case: c.id}
	stagingRoot := filepath.Join(c.root, "staging")
	if err := filepath.WalkDir(stagingRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(c.root, path)
		report.StagingFiles = append(report.StagingFiles, RecoveryFile{Path: filepath.ToSlash(rel), Size: info.Size(), Modified: info.ModTime().UTC()})
		return nil
	}); err != nil {
		return report, err
	}
	referenced := map[string]bool{}
	rows, err := c.db.QueryContext(ctx, "SELECT DISTINCT blob_digest FROM objects")
	if err != nil {
		return report, mapSQLError(err)
	}
	for rows.Next() {
		var blob BlobRef
		if err = rows.Scan(&blob); err != nil {
			rows.Close()
			return report, err
		}
		referenced[string(blob)] = true
	}
	if err = rows.Close(); err != nil {
		return report, err
	}
	blobRoot := filepath.Join(c.root, "blobs", "sha256")
	if err = filepath.WalkDir(blobRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		name := filepath.Base(path)
		if len(name) != 64 || referenced["sha256:"+name] {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		rel, _ := filepath.Rel(c.root, path)
		report.OrphanBlobs = append(report.OrphanBlobs, RecoveryFile{Path: filepath.ToSlash(rel), Size: info.Size(), Modified: info.ModTime().UTC(), Blob: BlobRef("sha256:" + name)})
		return nil
	}); err != nil {
		return report, err
	}
	runningRows, err := c.db.QueryContext(ctx, "SELECT id FROM activities WHERE state=? ORDER BY id", ActivityRunning)
	if err != nil {
		return report, mapSQLError(err)
	}
	var runningIDs []ActivityID
	for runningRows.Next() {
		var id ActivityID
		if err = runningRows.Scan(&id); err != nil {
			runningRows.Close()
			return report, err
		}
		runningIDs = append(runningIDs, id)
	}
	if err = runningRows.Close(); err != nil {
		return report, err
	}
	for _, id := range runningIDs {
		activity, loadErr := c.Activity(ctx, id)
		if loadErr != nil {
			return report, loadErr
		}
		report.RunningActivities = append(report.RunningActivities, activity)
	}
	sort.Slice(report.StagingFiles, func(i, j int) bool { return report.StagingFiles[i].Path < report.StagingFiles[j].Path })
	sort.Slice(report.OrphanBlobs, func(i, j int) bool { return report.OrphanBlobs[i].Path < report.OrphanBlobs[j].Path })
	return report, nil
}

// MarkActivitiesInterrupted explicitly terminates named running activities in
// one recovery transaction. The caller, not an age heuristic, decides that no
// live process owns them.
func (c *Case) MarkActivitiesInterrupted(ctx context.Context, activities []ActivityID, reason string) error {
	if err := c.checkOpen(); err != nil {
		return err
	}
	if len(activities) == 0 || strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: activity IDs and interruption reason required", ErrInvalid)
	}
	ids := append([]ActivityID(nil), activities...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for i := range ids {
		if ids[i] == "" || (i > 0 && ids[i] == ids[i-1]) {
			return fmt.Errorf("%w: empty or duplicate activity ID", ErrInvalid)
		}
	}
	affected := make([]string, len(ids))
	for i := range ids {
		affected[i] = string(ids[i])
	}
	fingerprint, _, err := digestJSON(struct {
		Activities []ActivityID
		Reason     string
	}{ids, reason})
	if err != nil {
		return err
	}
	_, err = c.mutate(ctx, c.defaultAgent.ID, "", "recovery.interrupt-activities", fingerprint, affected, func(tx *sql.Tx, revision int64) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		outcome, _ := canonicalJSON(Outcome{State: ActivityInterrupted, Summary: reason})
		for _, id := range ids {
			result, execErr := tx.ExecContext(ctx, "UPDATE activities SET state=?,inputs_sealed=1,sealed_revision=COALESCE(sealed_revision,?),finished_at=?,outcome_json=? WHERE id=? AND state=?", ActivityInterrupted, revision, now, string(outcome), id, ActivityRunning)
			if execErr != nil {
				return execErr
			}
			updated, _ := result.RowsAffected()
			if updated != 1 {
				return fmt.Errorf("%w: activity %s is not running", ErrConflict, id)
			}
		}
		return nil
	})
	return err
}
