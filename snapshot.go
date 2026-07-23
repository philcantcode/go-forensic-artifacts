package forensic

import (
	"context"
	"crypto/sha256"
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

const portableCaseFormat = 1

func (c *Case) Snapshot(ctx context.Context, spec SnapshotSpec) (Deliverable, error) {
	if err := c.checkOpen(); err != nil {
		return Deliverable{}, err
	}
	if strings.TrimSpace(spec.Destination) == "" {
		return Deliverable{}, fmt.Errorf("%w: snapshot destination required", ErrInvalid)
	}
	dest, err := filepath.Abs(spec.Destination)
	if err != nil {
		return Deliverable{}, err
	}
	inside, _ := pathWithin(c.root, dest)
	if inside {
		return Deliverable{}, fmt.Errorf("%w: snapshot cannot be inside the case", ErrInvalid)
	}
	if _, err = os.Lstat(dest); err == nil {
		return Deliverable{}, ErrConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return Deliverable{}, err
	}
	did, err := newDeliverableID()
	if err != nil {
		return Deliverable{}, err
	}
	partial := dest + ".partial-" + string(did)
	if err = os.MkdirAll(filepath.Join(partial, "blobs", "sha256"), 0700); err != nil {
		return Deliverable{}, err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(partial)
		}
	}()
	catalogPath := filepath.Join(partial, "catalog.sqlite3")
	if err = onlineBackup(ctx, c.db, catalogPath); err != nil {
		return Deliverable{}, err
	}
	if err = c.injectFault("after-snapshot-backup"); err != nil {
		return Deliverable{}, err
	}
	snapshotDB, err := openSQLite(ctx, catalogPath, c.repo.busy)
	if err != nil {
		return Deliverable{}, err
	}
	var manifest PortableCaseManifest
	manifest.Format = portableCaseFormat
	if err = snapshotDB.QueryRowContext(ctx, "SELECT id,name,description,revision,audit_head FROM case_info WHERE singleton=1").Scan(&manifest.Case, &manifest.Name, &manifest.Description, &manifest.Revision, &manifest.AuditHead); err != nil {
		snapshotDB.Close()
		return Deliverable{}, err
	}
	rows, err := snapshotDB.QueryContext(ctx, "SELECT DISTINCT b.digest,b.size FROM blobs b JOIN objects o ON o.blob_digest=b.digest ORDER BY b.digest")
	if err != nil {
		snapshotDB.Close()
		return Deliverable{}, err
	}
	for rows.Next() {
		var b PortableBlob
		if err = rows.Scan(&b.Blob, &b.Size); err != nil {
			rows.Close()
			snapshotDB.Close()
			return Deliverable{}, err
		}
		digest := strings.TrimPrefix(string(b.Blob), "sha256:")
		if len(digest) != 64 {
			rows.Close()
			snapshotDB.Close()
			return Deliverable{}, ErrIntegrity
		}
		b.Path = filepath.ToSlash(filepath.Join("blobs", "sha256", digest[:2], digest[2:4], digest))
		target := filepath.Join(partial, filepath.FromSlash(b.Path))
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			rows.Close()
			snapshotDB.Close()
			return Deliverable{}, err
		}
		if err = copyFileContext(ctx, c.blobPath(b.Blob), target); err != nil {
			rows.Close()
			snapshotDB.Close()
			return Deliverable{}, err
		}
		if err = c.injectFault("after-snapshot-copy"); err != nil {
			rows.Close()
			snapshotDB.Close()
			return Deliverable{}, err
		}
		if err = verifyBlobFile(ctx, target, b.Blob, b.Size); err != nil {
			rows.Close()
			snapshotDB.Close()
			return Deliverable{}, err
		}
		manifest.Blobs = append(manifest.Blobs, b)
	}
	if err = rows.Close(); err != nil {
		snapshotDB.Close()
		return Deliverable{}, err
	}
	if err = snapshotDB.Close(); err != nil {
		return Deliverable{}, err
	}
	catalogDigest, _, err := digestFile(ctx, catalogPath)
	if err != nil {
		return Deliverable{}, err
	}
	manifest.CatalogSHA256 = catalogDigest
	if err = writeJSONAtomic(filepath.Join(partial, "portable-case.json"), manifest); err != nil {
		return Deliverable{}, err
	}
	if err = c.injectFault("after-snapshot-manifest"); err != nil {
		return Deliverable{}, err
	}
	if err = renameWithRetry(ctx, partial, dest); err != nil {
		return Deliverable{}, err
	}
	published = true
	if err = c.injectFault("after-snapshot-publish"); err != nil {
		return Deliverable{}, err
	}
	packageDigest, err := directoryInventoryDigest(ctx, dest)
	if err != nil {
		return Deliverable{}, err
	}
	mf, err := os.Open(filepath.Join(dest, "portable-case.json"))
	if err != nil {
		return Deliverable{}, err
	}
	staged, err := c.stageBlob(ctx, mf)
	_ = mf.Close()
	if err != nil {
		return Deliverable{}, err
	}
	if err = c.publishBlob(ctx, staged); err != nil {
		return Deliverable{}, err
	}
	aid, err := newActivityID()
	if err != nil {
		return Deliverable{}, err
	}
	oid, err := newObjectID()
	if err != nil {
		return Deliverable{}, err
	}
	fp, cfg, err := digestJSON(struct {
		Destination, PackageDigest string
		Revision                   int64
	}{dest, packageDigest, manifest.Revision})
	if err != nil {
		return Deliverable{}, err
	}
	result := Deliverable{ID: did, Path: dest, SHA256: packageDigest}
	_, err = c.mutate(ctx, c.defaultAgent.ID, "", "case.snapshot", fp, []string{string(did), string(oid)}, func(tx *sql.Tx, rev int64) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		out, _ := canonicalJSON(OutcomeSucceeded())
		if _, e := tx.ExecContext(ctx, "INSERT INTO activities(id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json) VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?)", aid, c.defaultAgent.ID, ActivityDeliverablePackage, "Create portable case snapshot", string(cfg), fp, CaptureLibrary, ActivitySucceeded, rev, now, now, string(out)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO blobs(digest,size,created_at) VALUES(?,?,?)", staged.ref, staged.size, now); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,media_type,display_name) VALUES(?,?,?,?,?,?,?)", oid, EntityManifest, aid, rev, now, "application/json", "portable-case.json"); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO objects(id,blob_digest,size,role,path_display) VALUES(?,?,?,?,?)", oid, staged.ref, staged.size, "manifest", "portable-case.json"); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", did, EntityDeliverable, aid, rev, now, spec.Name); e != nil {
			return e
		}
		inputRows, e := tx.QueryContext(ctx, "SELECT id FROM entities WHERE created_revision<=? ORDER BY id", manifest.Revision)
		if e != nil {
			return e
		}
		for inputRows.Next() {
			var input string
			if e = inputRows.Scan(&input); e != nil {
				inputRows.Close()
				return e
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'snapshot-member')", aid, input); e != nil {
				inputRows.Close()
				return e
			}
		}
		if e = inputRows.Close(); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO deliverables(id,selection_id,path_hint,package_sha256) VALUES(?,NULL,?,?)", did, dest, packageDigest); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'manifest'),(?,?,'deliverable')", aid, oid, aid, did); e != nil {
			return e
		}
		result.CreatedRevision = rev
		return nil
	})
	return result, err
}

func directoryInventoryDigest(ctx context.Context, root string) (string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type().IsRegular() {
			rel, e := filepath.Rel(root, path)
			if e != nil {
				return e
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, rel := range files {
		digest, _, e := digestFile(ctx, filepath.Join(root, filepath.FromSlash(rel)))
		if e != nil {
			return "", e
		}
		_, _ = h.Write([]byte(rel + "\x00" + digest + "\n"))
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (r *Repository) RestoreCase(ctx context.Context, spec RestoreSpec) (*Case, error) {
	if err := r.checkOpen(); err != nil {
		return nil, err
	}
	source, err := filepath.Abs(spec.Source)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(source, "portable-case.json"))
	if err != nil {
		return nil, err
	}
	var manifest PortableCaseManifest
	if json.Unmarshal(b, &manifest) != nil || manifest.Format != portableCaseFormat || !validID(string(manifest.Case), "case_") {
		return nil, fmt.Errorf("%w: invalid portable case manifest", ErrIntegrity)
	}
	got, _, err := digestFile(ctx, filepath.Join(source, "catalog.sqlite3"))
	if err != nil || got != manifest.CatalogSHA256 {
		return nil, fmt.Errorf("%w: catalog digest mismatch", ErrIntegrity)
	}
	for _, blob := range manifest.Blobs {
		expected := portableBlobPath(blob.Blob)
		if blob.Path != expected {
			return nil, fmt.Errorf("%w: unsafe blob path", ErrIntegrity)
		}
		path := filepath.Join(source, filepath.FromSlash(blob.Path))
		if ok, _ := pathWithin(source, path); !ok {
			return nil, fmt.Errorf("%w: blob escapes package", ErrIntegrity)
		}
		if err = verifyBlobFile(ctx, path, blob.Blob, blob.Size); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrIntegrity, err)
		}
	}
	lookup, err := normalizeCaseName(manifest.Name)
	if err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, mapSQLError(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, "INSERT INTO cases(id,lookup_key,name,description,state,created_at) VALUES(?,?,?,?,?,?)", manifest.Case, lookup, manifest.Name, manifest.Description, "creating", now); err != nil {
		tx.Rollback()
		return nil, mapSQLError(err)
	}
	if err = tx.Commit(); err != nil {
		return nil, mapSQLError(err)
	}
	tmp := filepath.Join(r.root, "cases", ".creating-"+string(manifest.Case))
	final := filepath.Join(r.root, "cases", string(manifest.Case))
	if err = os.MkdirAll(filepath.Join(tmp, "blobs", "sha256"), 0700); err != nil {
		return nil, err
	}
	for _, d := range []string{filepath.Join(tmp, "checkpoints"), filepath.Join(tmp, "staging", "ingest"), filepath.Join(tmp, "staging", "package")} {
		if err = os.MkdirAll(d, 0700); err != nil {
			return nil, err
		}
	}
	if err = copyFileContext(ctx, filepath.Join(source, "catalog.sqlite3"), filepath.Join(tmp, "catalog.sqlite3")); err != nil {
		return nil, err
	}
	if err = writeJSONAtomic(filepath.Join(tmp, "case.json"), caseMarker{Format: CaseFormat, ID: manifest.Case, CreatedAt: time.Now().UTC()}); err != nil {
		return nil, err
	}
	for _, blob := range manifest.Blobs {
		target := filepath.Join(tmp, filepath.FromSlash(blob.Path))
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return nil, err
		}
		if err = copyFileContext(ctx, filepath.Join(source, filepath.FromSlash(blob.Path)), target); err != nil {
			return nil, err
		}
	}
	if err = renameWithRetry(ctx, tmp, final); err != nil {
		return nil, err
	}
	if _, err = r.db.ExecContext(ctx, "UPDATE cases SET state='active' WHERE id=?", manifest.Case); err != nil {
		return nil, mapSQLError(err)
	}
	return r.OpenCase(ctx, ByID(manifest.Case))
}

func portableBlobPath(ref BlobRef) string {
	digest := strings.TrimPrefix(string(ref), "sha256:")
	if len(digest) != 64 {
		return ""
	}
	return filepath.ToSlash(filepath.Join("blobs", "sha256", digest[:2], digest[2:4], digest))
}
