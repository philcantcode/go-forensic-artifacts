package forensic

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSQLiteConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.sqlite3")
	pragmas := []string{"busy_timeout=5000", "foreign_keys=ON", "journal_mode=WAL", "synchronous=FULL", "trusted_schema=OFF"}
	for n := 0; n <= len(pragmas); n++ {
		q := url.Values{}
		for _, p := range pragmas[:n] {
			q.Add("_pragma", p)
		}
		dsn := path
		if len(q) > 0 {
			dsn += "?" + q.Encode()
		}
		db, err := sql.Open("sqlite", dsn)
		if err == nil {
			err = db.PingContext(context.Background())
		}
		if db != nil {
			_ = db.Close()
		}
		if err != nil {
			t.Fatalf("%d pragmas (%s): %v", n, dsn, err)
		}
	}
}

func TestRepositorySafetyAndForwardSchemaRejection(t *testing.T) {
	ctx := context.Background()
	nonEmpty := t.TempDir()
	if err := os.WriteFile(filepath.Join(nonEmpty, "unrelated.txt"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, Config{Root: nonEmpty}); !errors.Is(err, ErrUnsupportedStorage) {
		t.Fatalf("non-repository directory = %v", err)
	}
	base := t.TempDir()
	repo, err := Open(ctx, Config{Root: filepath.Join(base, "repo")})
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	c, err := repo.CreateCase(ctx, CaseSpec{Name: "forward schema"})
	if err != nil {
		t.Fatal(err)
	}
	id := c.ID()
	if _, err = c.db.ExecContext(ctx, "UPDATE case_info SET schema_version=? WHERE singleton=1", SchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.OpenCase(ctx, ByID(id)); !errors.Is(err, ErrUnsupportedStorage) {
		t.Fatalf("forward schema = %v", err)
	}
}
