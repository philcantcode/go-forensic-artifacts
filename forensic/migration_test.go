package forensic

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExplicitV1ToV2Migration(t *testing.T) {
	ctx, _, repo, c := openTestRepo(t)
	id := c.ID()
	before, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	caseRoot := c.Root()
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := openSQLite(ctx, caseRoot+string(os.PathSeparator)+"catalog.sqlite3", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise a real missing v2 column rather than changing only the version
	// marker. DROP COLUMN is supported by the SQLite floor used by the module.
	if _, err = db.ExecContext(ctx, "ALTER TABLE artifact_values DROP COLUMN encoding"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "UPDATE case_info SET schema_version=1 WHERE singleton=1"); err == nil {
		_, err = db.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version=2")
	}
	if err == nil {
		_, err = db.ExecContext(ctx, "INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,?)", time.Now().UTC().Format(time.RFC3339Nano))
	}
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.OpenCase(ctx, ByID(id)); !errors.Is(err, ErrUnsupportedStorage) {
		t.Fatalf("ordinary open must fail closed for an old schema: %v", err)
	}
	result, err := repo.MigrateCase(ctx, ByID(id), MigrationSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if result.FromVersion != 1 || result.ToVersion != SchemaVersion || result.Revision != before.Revision+1 {
		t.Fatalf("unexpected migration result: %#v", result)
	}
	if stat, statErr := os.Stat(result.BackupPath); statErr != nil || stat.Size() == 0 {
		t.Fatalf("verified migration backup missing: %#v %v", stat, statErr)
	}
	c, err = repo.OpenCase(ctx, ByID(id))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if report, verifyErr := c.Verify(ctx, VerifySpec{Mode: VerifyFull}); verifyErr != nil || !report.OK {
		t.Fatalf("migrated case verification: %#v %v", report, verifyErr)
	}
	var encodingColumn int
	if err = c.db.QueryRowContext(ctx, "SELECT count(*) FROM pragma_table_info('artifact_values') WHERE name='encoding'").Scan(&encodingColumn); err != nil || encodingColumn != 1 {
		t.Fatalf("v2 encoding column missing: %d %v", encodingColumn, err)
	}
	var operation string
	if err = c.db.QueryRowContext(ctx, "SELECT operation FROM revisions WHERE revision=?", result.Revision).Scan(&operation); err != nil || operation != "schema.migrate" {
		t.Fatalf("migration audit revision missing: %q %v", operation, err)
	}
}

func TestMaintenanceLeaseBlocksOpen(t *testing.T) {
	ctx, _, repo, c := openTestRepo(t)
	id := c.ID()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := repo.acquireMaintenanceLease(ctx, id, "test-holder", time.Minute); err != nil {
		t.Fatal(err)
	}
	defer repo.releaseMaintenanceLease(context.Background(), id, "test-holder")
	if _, err := repo.OpenCase(ctx, ByID(id)); !errors.Is(err, ErrBusy) {
		t.Fatalf("open during maintenance = %v, want ErrBusy", err)
	}
}

func TestRestoreSupportedOldPortableCaseWithExplicitMigration(t *testing.T) {
	ctx, base, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "old.txt", EvidenceSpec{Label: "old portable fixture"}, strings.NewReader("stable bytes"))
	if err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(base, "portable-v1")
	if _, err = c.Snapshot(ctx, SnapshotSpec{Name: "v1 fixture", Destination: packagePath}); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(packagePath, "catalog.sqlite3")
	db, err := openSQLite(ctx, catalogPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "ALTER TABLE artifact_values DROP COLUMN encoding"); err == nil {
		_, err = db.ExecContext(ctx, "UPDATE case_info SET schema_version=1 WHERE singleton=1")
	}
	if err == nil {
		_, err = db.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version=2")
	}
	if err == nil {
		_, err = db.ExecContext(ctx, "INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,?)", time.Now().UTC().Format(time.RFC3339Nano))
	}
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(packagePath, "portable-case.json")
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest PortableCaseManifest
	if err = json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.SchemaVersion = 1
	manifest.CatalogSHA256, _, err = digestFile(ctx, catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	if err = writeJSONAtomic(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}

	restoredRepo, err := Open(ctx, Config{Root: filepath.Join(base, "restored-old")})
	if err != nil {
		t.Fatal(err)
	}
	defer restoredRepo.Close()
	if _, err = restoredRepo.RestoreCase(ctx, RestoreSpec{Source: packagePath}); !errors.Is(err, ErrUnsupportedStorage) {
		t.Fatalf("old restore without migration = %v", err)
	}
	if cases, listErr := restoredRepo.ListCases(ctx); listErr != nil || len(cases) != 0 {
		t.Fatalf("failed preflight mutated repository: %#v %v", cases, listErr)
	}
	restored, err := restoredRepo.RestoreCase(ctx, RestoreSpec{Source: packagePath, Migrate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.ID() != c.ID() {
		t.Fatalf("case ID changed: %s != %s", restored.ID(), c.ID())
	}
	object, err := restored.Object(ctx, evidence.RootObject.ID)
	if err != nil || object.Blob != evidence.RootObject.Blob {
		t.Fatalf("stable object/blob IDs were not preserved: %#v %v", object, err)
	}
	if report, verifyErr := restored.Verify(ctx, VerifySpec{Mode: VerifyFull}); verifyErr != nil || !report.OK {
		t.Fatalf("restored migrated case verification: %#v %v", report, verifyErr)
	}
}
