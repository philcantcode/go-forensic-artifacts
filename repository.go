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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Repository struct {
	root         string
	db           *sql.DB
	busy         time.Duration
	defaultAgent AgentSpec
	closed       atomic.Bool
	closeOnce    sync.Once
}

type Case struct {
	repo         *Repository
	root         string
	db           *sql.DB
	id           CaseID
	defaultAgent AgentRef
	closed       atomic.Bool
	closeOnce    sync.Once
	faultMu      sync.RWMutex
	fault        func(string) error
}

type repositoryMarker struct {
	Format    int       `json:"format"`
	CreatedAt time.Time `json:"created_at"`
}
type caseMarker struct {
	Format    int       `json:"format"`
	ID        CaseID    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

func Open(ctx context.Context, cfg Config) (*Repository, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Root) == "" {
		return nil, fmt.Errorf("%w: repository root is required", ErrInvalid)
	}
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, err
	}
	if cfg.BusyTimeout <= 0 {
		cfg.BusyTimeout = 5 * time.Second
	}
	if cfg.DefaultAgent.Name == "" {
		cfg.DefaultAgent = AgentSpec{Kind: AgentSoftware, Name: "forensic-library"}
	}
	if cfg.DefaultAgent.Kind == "" {
		cfg.DefaultAgent.Kind = AgentUnknown
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("create repository: %w", err)
	}
	markerPath := filepath.Join(root, "repository.json")
	if b, e := os.ReadFile(markerPath); e == nil {
		var m repositoryMarker
		if json.Unmarshal(b, &m) != nil || m.Format != RepositoryFormat {
			return nil, fmt.Errorf("%w: unsupported repository marker", ErrUnsupportedStorage)
		}
	} else if errors.Is(e, os.ErrNotExist) {
		entries, readErr := os.ReadDir(root)
		if readErr != nil {
			return nil, readErr
		}
		if len(entries) != 0 {
			return nil, fmt.Errorf("%w: refusing to initialize a non-empty directory", ErrUnsupportedStorage)
		}
		if err = writeJSONAtomic(markerPath, repositoryMarker{Format: RepositoryFormat, CreatedAt: time.Now().UTC()}); err != nil {
			return nil, err
		}
	} else {
		return nil, e
	}
	for _, d := range []string{"cases", "workspaces"} {
		if err = os.MkdirAll(filepath.Join(root, d), 0700); err != nil {
			return nil, err
		}
	}
	db, err := openSQLite(ctx, filepath.Join(root, "repository.sqlite3"), cfg.BusyTimeout)
	if err != nil {
		return nil, err
	}
	if err = execSchema(ctx, db, repositorySchema); err != nil {
		db.Close()
		return nil, err
	}
	_, err = db.ExecContext(ctx, "INSERT OR IGNORE INTO repository_info(singleton,format_version,created_at) VALUES(1,?,?)", RepositoryFormat, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		db.Close()
		return nil, mapSQLError(err)
	}
	return &Repository{root: root, db: db, busy: cfg.BusyTimeout, defaultAgent: cfg.DefaultAgent}, nil
}

func (r *Repository) Root() string { return r.root }
func (r *Repository) checkOpen() error {
	if r == nil || r.closed.Load() {
		return ErrClosed
	}
	return nil
}
func (r *Repository) Close() error {
	if r == nil {
		return nil
	}
	var err error
	r.closeOnce.Do(func() { r.closed.Store(true); err = r.db.Close() })
	return err
}

func normalizeCaseName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "", fmt.Errorf("%w: case name is required", ErrInvalid)
	}
	if strings.ContainsAny(n, "\x00\r\n") {
		return "", fmt.Errorf("%w: invalid case name", ErrInvalid)
	}
	return strings.ToLower(n), nil
}

func (r *Repository) CreateCase(ctx context.Context, spec CaseSpec) (*Case, error) {
	if err := r.checkOpen(); err != nil {
		return nil, err
	}
	lookup, err := normalizeCaseName(spec.Name)
	if err != nil {
		return nil, err
	}
	fp, _, err := digestJSON(struct{ Name, Description string }{strings.TrimSpace(spec.Name), spec.Description})
	if err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, mapSQLError(err)
	}
	if spec.IdempotencyKey != "" {
		var oldFP, result string
		e := tx.QueryRowContext(ctx, "SELECT fingerprint,result_json FROM idempotency WHERE scope='repository' AND operation='case.create' AND key=?", spec.IdempotencyKey).Scan(&oldFP, &result)
		if e == nil {
			tx.Rollback()
			if oldFP != fp {
				return nil, fmt.Errorf("%w: idempotency key reused", ErrConflict)
			}
			var v struct {
				ID CaseID `json:"id"`
			}
			if json.Unmarshal([]byte(result), &v) != nil {
				return nil, ErrIntegrity
			}
			return r.OpenCase(ctx, ByID(v.ID))
		}
		if !errors.Is(e, sql.ErrNoRows) {
			tx.Rollback()
			return nil, mapSQLError(e)
		}
	}
	id, err := newCaseID()
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "INSERT INTO cases(id,lookup_key,name,description,state,created_at) VALUES(?,?,?,?,?,?)", id, lookup, strings.TrimSpace(spec.Name), spec.Description, "creating", now.Format(time.RFC3339Nano))
	if err == nil && spec.IdempotencyKey != "" {
		b, _ := canonicalJSON(struct {
			ID CaseID `json:"id"`
		}{id})
		_, err = tx.ExecContext(ctx, "INSERT INTO idempotency(scope,operation,key,fingerprint,result_json) VALUES('repository','case.create',?,?,?)", spec.IdempotencyKey, fp, string(b))
	}
	if err != nil {
		tx.Rollback()
		return nil, mapSQLError(err)
	}
	if err = tx.Commit(); err != nil {
		return nil, mapSQLError(err)
	}
	tmp := filepath.Join(r.root, "cases", ".creating-"+string(id))
	final := filepath.Join(r.root, "cases", string(id))
	if err = os.Mkdir(tmp, 0700); err != nil {
		return nil, fmt.Errorf("initialize case: %w", err)
	}
	for _, d := range []string{filepath.Join(tmp, "blobs", "sha256"), filepath.Join(tmp, "checkpoints"), filepath.Join(tmp, "staging", "ingest"), filepath.Join(tmp, "staging", "package")} {
		if err = os.MkdirAll(d, 0700); err != nil {
			return nil, err
		}
	}
	if err = writeJSONAtomic(filepath.Join(tmp, "case.json"), caseMarker{Format: CaseFormat, ID: id, CreatedAt: now}); err != nil {
		return nil, err
	}
	db, err := openSQLite(ctx, filepath.Join(tmp, "catalog.sqlite3"), r.busy)
	if err != nil {
		return nil, err
	}
	if err = execSchema(ctx, db, caseSchema); err != nil {
		db.Close()
		return nil, err
	}
	agentID, err := newAgentID()
	if err != nil {
		db.Close()
		return nil, err
	}
	activityID, err := newActivityID()
	if err != nil {
		db.Close()
		return nil, err
	}
	actor := AgentRef{ID: agentID, Kind: r.defaultAgent.Kind, Name: r.defaultAgent.Name}
	if err = initializeCase(ctx, db, id, spec, actor, activityID, now); err != nil {
		db.Close()
		return nil, err
	}
	if err = db.Close(); err != nil {
		return nil, err
	}
	if err = renameWithRetry(ctx, tmp, final); err != nil {
		return nil, fmt.Errorf("publish case: %w", err)
	}
	_ = syncDirectory(filepath.Join(r.root, "cases"))
	if _, err = r.db.ExecContext(ctx, "UPDATE cases SET state='active' WHERE id=?", id); err != nil {
		return nil, mapSQLError(err)
	}
	return r.OpenCase(ctx, ByID(id))
}

func initializeCase(ctx context.Context, db *sql.DB, id CaseID, spec CaseSpec, agent AgentRef, activity ActivityID, now time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ts := now.Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, "INSERT INTO case_info(singleton,id,name,description,format_version,schema_version,created_at,revision,audit_head) VALUES(1,?,?,?,?,?,?,0,'')", id, strings.TrimSpace(spec.Name), spec.Description, CaseFormat, SchemaVersion, ts); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)", SchemaVersion, ts); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO agents(id,kind,name,created_at) VALUES(?,?,?,?)", agent.ID, agent.Kind, agent.Name, ts); err != nil {
		return err
	}
	config := "{}"
	digest := sha256Hex([]byte(config))
	outcome, _ := canonicalJSON(OutcomeSucceeded())
	if _, err = tx.ExecContext(ctx, "INSERT INTO activities(id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,started_at,finished_at,outcome_json) VALUES(?,?,?,?,?,?,?,?,1,?,?,?)", activity, agent.ID, ActivityCaseCreate, "Create case", config, digest, CaptureLibrary, ActivitySucceeded, ts, ts, string(outcome)); err != nil {
		return err
	}
	e := mutationEvent{Domain: "forensic-audit-v1", Sequence: 1, Revision: 1, PreviousHash: "", Actor: agent.ID, Operation: string(ActivityCaseCreate), Affected: []string{string(id)}, RequestDigest: digest, RecordedAt: ts}
	body, _ := canonicalJSON(e)
	h := sha256Hex(append(append(append([]byte(e.Domain), []byte("1")...), body...), []byte{}...))
	if _, err = tx.ExecContext(ctx, "INSERT INTO revisions(revision,recorded_at,operation) VALUES(1,?,?)", ts, ActivityCaseCreate); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_events(sequence,revision,previous_hash,event_json,event_hash) VALUES(1,1,'',?,?)", string(body), h); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE case_info SET revision=1,audit_head=? WHERE singleton=1", h); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) OpenCase(ctx context.Context, selector CaseSelector) (*Case, error) {
	if err := r.checkOpen(); err != nil {
		return nil, err
	}
	var id CaseID
	var row *sql.Row
	if selector.id != "" {
		row = r.db.QueryRowContext(ctx, "SELECT id FROM cases WHERE id=? AND state='active'", selector.id)
	} else {
		lookup, err := normalizeCaseName(selector.name)
		if err != nil {
			return nil, err
		}
		row = r.db.QueryRowContext(ctx, "SELECT id FROM cases WHERE lookup_key=? AND state='active'", lookup)
	}
	if err := row.Scan(&id); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, mapSQLError(err)
	}
	root := filepath.Join(r.root, "cases", string(id))
	b, err := os.ReadFile(filepath.Join(root, "case.json"))
	if err != nil {
		return nil, fmt.Errorf("%w: missing case marker", ErrIntegrity)
	}
	var m caseMarker
	if json.Unmarshal(b, &m) != nil || m.Format != CaseFormat || m.ID != id {
		return nil, fmt.Errorf("%w: invalid case marker", ErrIntegrity)
	}
	db, err := openSQLite(ctx, filepath.Join(root, "catalog.sqlite3"), r.busy)
	if err != nil {
		return nil, err
	}
	if err = validateCaseCatalog(ctx, db, id); err != nil {
		db.Close()
		return nil, err
	}
	c := &Case{repo: r, root: root, db: db, id: id}
	agent, err := c.ensureAgent(ctx, r.defaultAgent)
	if err != nil {
		db.Close()
		return nil, err
	}
	c.defaultAgent = agent
	return c, nil
}

func (r *Repository) ListCases(ctx context.Context) ([]CaseInfo, error) {
	if err := r.checkOpen(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, "SELECT id,name,description,created_at FROM cases WHERE state='active' ORDER BY id")
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var out []CaseInfo
	for rows.Next() {
		var v CaseInfo
		var ts string
		if err = rows.Scan(&v.ID, &v.Name, &v.Description, &ts); err != nil {
			return nil, err
		}
		v.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (c *Case) ID() CaseID   { return c.id }
func (c *Case) Root() string { return c.root }
func (c *Case) checkOpen() error {
	if c == nil || c.closed.Load() {
		return ErrClosed
	}
	return nil
}
func (c *Case) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() { c.closed.Store(true); err = c.db.Close() })
	return err
}

func (c *Case) injectFault(point string) error {
	c.faultMu.RLock()
	f := c.fault
	c.faultMu.RUnlock()
	if f != nil {
		return f(point)
	}
	return nil
}
func (c *Case) Info(ctx context.Context) (CaseInfo, error) {
	var v CaseInfo
	var ts string
	err := c.db.QueryRowContext(ctx, "SELECT id,name,description,created_at,revision FROM case_info WHERE singleton=1").Scan(&v.ID, &v.Name, &v.Description, &ts, &v.Revision)
	v.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return v, mapSQLError(err)
}

func (c *Case) ensureAgent(ctx context.Context, spec AgentSpec) (AgentRef, error) {
	if spec.Name == "" {
		return AgentRef{}, fmt.Errorf("%w: agent name is required", ErrInvalid)
	}
	if spec.Kind == "" {
		spec.Kind = AgentUnknown
	}
	var a AgentRef
	err := c.db.QueryRowContext(ctx, "SELECT id,kind,name FROM agents WHERE kind=? AND name=?", spec.Kind, spec.Name).Scan(&a.ID, &a.Kind, &a.Name)
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return a, mapSQLError(err)
	}
	id, e := newAgentID()
	if e != nil {
		return a, e
	}
	a = AgentRef{ID: id, Kind: spec.Kind, Name: spec.Name}
	_, e = c.mutate(ctx, c.defaultAgent.ID, "", "agent.create", "", []string{string(id)}, func(tx *sql.Tx, rev int64) error {
		_, e := tx.ExecContext(ctx, "INSERT INTO agents(id,kind,name,created_at) VALUES(?,?,?,?)", id, spec.Kind, spec.Name, time.Now().UTC().Format(time.RFC3339Nano))
		return e
	})
	if errors.Is(e, ErrConflict) {
		return c.ensureAgent(ctx, spec)
	}
	return a, e
}

func writeJSONAtomic(path string, v any) error {
	b, err := canonicalJSON(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return syncDirectory(filepath.Dir(path))
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = f.Sync(); err != nil && os.PathSeparator == '/' {
		return err
	}
	return nil
}
func sha256Hex(b []byte) string { h := sha256.Sum256(b); return fmt.Sprintf("%x", h[:]) }
