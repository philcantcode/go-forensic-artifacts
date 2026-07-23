package forensic

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Session struct {
	caseRef *Case
	info    SessionInfo
	closed  bool
	mu      sync.Mutex
}
type Activity struct {
	session   *Session
	caseRef   *Case
	id        ActivityID
	spec      ActivitySpec
	mu        sync.Mutex
	cond      *sync.Cond
	finishing bool
	terminal  bool
	captures  int
}

func (c *Case) StartSession(ctx context.Context, spec SessionSpec) (*Session, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	agent := spec.Agent
	if agent.ID == "" {
		agent = c.defaultAgent
	}
	var count int
	if err := c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE id=?", agent.ID).Scan(&count); err != nil {
		return nil, mapSQLError(err)
	}
	if count != 1 {
		return nil, ErrNotFound
	}
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	fp, _, err := digestJSON(struct {
		Agent AgentID
		Label string
	}{agent.ID, spec.Label})
	if err != nil {
		return nil, err
	}
	info := SessionInfo{ID: id, Agent: agent, Label: spec.Label, StartedAt: now}
	_, err = c.mutate(ctx, agent.ID, id, "session.start", fp, []string{string(id)}, func(tx *sql.Tx, rev int64) error {
		if spec.IdempotencyKey != "" {
			var old SessionInfo
			ok, e := lookupIdempotency(ctx, tx, string(agent.ID), "session.start", spec.IdempotencyKey, fp, &old)
			if e != nil {
				return e
			}
			if ok {
				info = old
				return nil
			}
		}
		_, e := tx.ExecContext(ctx, "INSERT INTO sessions(id,agent_id,label,started_at) VALUES(?,?,?,?)", id, agent.ID, spec.Label, now.Format(time.RFC3339Nano))
		if e != nil {
			return e
		}
		return storeIdempotency(ctx, tx, string(agent.ID), "session.start", spec.IdempotencyKey, fp, info)
	})
	if err != nil {
		return nil, err
	}
	return &Session{caseRef: c, info: info}, nil
}

func (s *Session) ID() SessionID {
	if s == nil {
		return ""
	}
	return s.info.ID
}
func (s *Session) Info() SessionInfo {
	if s == nil {
		return SessionInfo{}
	}
	return s.info
}
func (s *Session) checkOpen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return s.caseRef.checkOpen()
}
func (s *Session) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	now := time.Now().UTC()
	_, err := s.caseRef.mutate(ctx, s.info.Agent.ID, s.info.ID, "session.close", "", []string{string(s.info.ID)}, func(tx *sql.Tx, rev int64) error {
		res, e := tx.ExecContext(ctx, "UPDATE sessions SET closed_at=? WHERE id=? AND closed_at IS NULL", now.Format(time.RFC3339Nano), s.info.ID)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrConflict
		}
		return nil
	})
	return err
}

func (s *Session) BeginActivity(ctx context.Context, spec ActivitySpec) (*Activity, error) {
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	if spec.Type == "" {
		return nil, fmt.Errorf("%w: activity type is required", ErrInvalid)
	}
	if spec.CaptureMode == "" {
		spec.CaptureMode = CaptureLibrary
	}
	id, err := newActivityID()
	if err != nil {
		return nil, err
	}
	cfg, err := canonicalJSON(spec.Config)
	if err != nil {
		return nil, err
	}
	fp := sha256Hex(cfg)
	tool, _ := canonicalJSON(spec.Tool)
	now := time.Now().UTC()
	_, err = s.caseRef.mutate(ctx, s.info.Agent.ID, s.info.ID, "activity.begin", fp, []string{string(id)}, func(tx *sql.Tx, rev int64) error {
		if spec.IdempotencyKey != "" {
			var old struct {
				ID ActivityID `json:"id"`
			}
			ok, e := lookupIdempotency(ctx, tx, string(s.ID()), "activity.begin", spec.IdempotencyKey, fp, &old)
			if e != nil {
				return e
			}
			if ok {
				id = old.ID
				return nil
			}
		}
		_, e := tx.ExecContext(ctx, "INSERT INTO activities(id,session_id,agent_id,type,label,tool_json,config_json,config_digest,capture_mode,state,started_at,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", id, s.ID(), s.info.Agent.ID, spec.Type, spec.Label, string(tool), string(cfg), fp, spec.CaptureMode, ActivityRunning, now.Format(time.RFC3339Nano), spec.IdempotencyKey)
		if e != nil {
			return e
		}
		return storeIdempotency(ctx, tx, string(s.ID()), "activity.begin", spec.IdempotencyKey, fp, struct {
			ID ActivityID `json:"id"`
		}{id})
	})
	if err != nil {
		return nil, err
	}
	a := &Activity{session: s, caseRef: s.caseRef, id: id, spec: spec}
	a.cond = sync.NewCond(&a.mu)
	return a, nil
}

func (a *Activity) ID() ActivityID {
	if a == nil {
		return ""
	}
	return a.id
}
func (a *Activity) Use(ctx context.Context, input Entity, role string) error {
	if a == nil {
		return ErrClosed
	}
	a.mu.Lock()
	if a.finishing || a.terminal {
		a.mu.Unlock()
		return ErrClosed
	}
	a.mu.Unlock()
	entity := EntityRef{}
	if input != nil {
		entity = input.EntityRef()
	}
	if entity.ID == "" || role == "" {
		return fmt.Errorf("%w: entity and role are required", ErrInvalid)
	}
	_, err := a.caseRef.mutate(ctx, a.session.info.Agent.ID, a.session.ID(), "activity.use", "", []string{string(a.id), entity.ID}, func(tx *sql.Tx, rev int64) error {
		var state string
		var sealed int
		if e := tx.QueryRowContext(ctx, "SELECT state,inputs_sealed FROM activities WHERE id=?", a.id).Scan(&state, &sealed); e != nil {
			return e
		}
		if state != string(ActivityRunning) || sealed != 0 {
			return ErrConflict
		}
		_, e := tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,?)", a.id, entity.ID, role)
		return e
	})
	return err
}

func (a *Activity) SealInputs(ctx context.Context) error {
	if a == nil {
		return ErrClosed
	}
	_, err := a.caseRef.mutate(ctx, a.session.info.Agent.ID, a.session.ID(), "activity.seal-inputs", "", []string{string(a.id)}, func(tx *sql.Tx, rev int64) error {
		res, e := tx.ExecContext(ctx, "UPDATE activities SET inputs_sealed=1,sealed_revision=? WHERE id=? AND state=?", rev, a.id, ActivityRunning)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return ErrConflict
		}
		return nil
	})
	return err
}

func (a *Activity) startCapture() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.finishing || a.terminal {
		return ErrClosed
	}
	a.captures++
	return nil
}
func (a *Activity) endCapture() { a.mu.Lock(); a.captures--; a.cond.Broadcast(); a.mu.Unlock() }

func (a *Activity) CaptureFile(ctx context.Context, path string, spec ObjectSpec) (ObjectRef, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return ObjectRef{}, err
	}
	if !st.Mode().IsRegular() {
		return ObjectRef{}, fmt.Errorf("%w: import source must be a regular file", ErrInvalid)
	}
	f, err := os.Open(path)
	if err != nil {
		return ObjectRef{}, err
	}
	defer f.Close()
	if spec.DisplayName == "" {
		spec.DisplayName = filepath.Base(path)
	}
	return a.Capture(ctx, spec, f)
}

func (a *Activity) Capture(ctx context.Context, spec ObjectSpec, r io.Reader) (ObjectRef, error) {
	if err := a.startCapture(); err != nil {
		return ObjectRef{}, err
	}
	defer a.endCapture()
	staged, err := a.caseRef.stageBlob(ctx, r)
	if err != nil {
		return ObjectRef{}, err
	}
	if err = a.caseRef.publishBlob(ctx, staged); err != nil {
		return ObjectRef{}, err
	}
	id, err := newObjectID()
	if err != nil {
		return ObjectRef{}, err
	}
	pathDisplay, lt, lj, err := encodeLocator(spec.Source)
	if err != nil {
		return ObjectRef{}, err
	}
	fp, _, err := digestJSON(struct {
		Role, DisplayName, MediaType, LocatorType, LocatorJSON string
		Blob                                                   BlobRef
	}{spec.Role, spec.DisplayName, spec.MediaType, lt, lj, staged.ref})
	if err != nil {
		return ObjectRef{}, err
	}
	ref := ObjectRef{ID: id, Blob: staged.ref, Size: staged.size, DisplayName: spec.DisplayName, MediaType: spec.MediaType, Path: pathDisplay, GeneratingActivity: a.id}
	_, err = a.caseRef.mutate(ctx, a.session.info.Agent.ID, a.session.ID(), "object.capture", fp, []string{string(a.id), string(id), string(staged.ref)}, func(tx *sql.Tx, rev int64) error {
		if spec.IdempotencyKey != "" {
			var old ObjectRef
			ok, e := lookupIdempotency(ctx, tx, string(a.id), "object.capture", spec.IdempotencyKey, fp, &old)
			if e != nil {
				return e
			}
			if ok {
				ref = old
				return nil
			}
		}
		var state string
		if e := tx.QueryRowContext(ctx, "SELECT state FROM activities WHERE id=?", a.id).Scan(&state); e != nil {
			return e
		}
		if state != string(ActivityRunning) {
			return ErrConflict
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, e := tx.ExecContext(ctx, "UPDATE activities SET inputs_sealed=1,sealed_revision=COALESCE(sealed_revision,?) WHERE id=?", rev, a.id); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO blobs(digest,size,created_at) VALUES(?,?,?)", staged.ref, staged.size, now); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,media_type,display_name) VALUES(?,?,?,?,?,?,?)", id, EntityObject, a.id, rev, now, spec.MediaType, spec.DisplayName); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO objects(id,blob_digest,size,role,path_display) VALUES(?,?,?,?,?)", id, staged.ref, staged.size, spec.Role, pathDisplay); e != nil {
			return e
		}
		if lt != "" {
			if _, e := tx.ExecContext(ctx, "INSERT INTO source_locators(entity_id,locator_type,locator_json) VALUES(?,?,?)", id, lt, lj); e != nil {
				return e
			}
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,?)", a.id, id, spec.Role); e != nil {
			return e
		}
		ref.CreatedRevision = rev
		return storeIdempotency(ctx, tx, string(a.id), "object.capture", spec.IdempotencyKey, fp, ref)
	})
	return ref, err
}

func (a *Activity) Finish(ctx context.Context, outcome Outcome) error {
	if a == nil {
		return ErrClosed
	}
	if outcome.State == "" {
		outcome.State = ActivitySucceeded
	}
	if outcome.State == ActivityRunning {
		return fmt.Errorf("%w: terminal outcome required", ErrInvalid)
	}
	a.mu.Lock()
	if a.terminal {
		a.mu.Unlock()
		return nil
	}
	if a.finishing {
		a.mu.Unlock()
		return ErrConflict
	}
	a.finishing = true
	for a.captures > 0 {
		if ctx.Err() != nil {
			a.finishing = false
			a.mu.Unlock()
			return ctx.Err()
		}
		a.cond.Wait()
	}
	a.mu.Unlock()
	body, err := canonicalJSON(outcome)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = a.caseRef.mutate(ctx, a.session.info.Agent.ID, a.session.ID(), "activity.finish", "", []string{string(a.id)}, func(tx *sql.Tx, rev int64) error {
		res, e := tx.ExecContext(ctx, "UPDATE activities SET state=?,inputs_sealed=1,sealed_revision=COALESCE(sealed_revision,?),finished_at=?,outcome_json=? WHERE id=? AND state=?", outcome.State, rev, now.Format(time.RFC3339Nano), string(body), a.id, ActivityRunning)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			var state string
			if e = tx.QueryRowContext(ctx, "SELECT state FROM activities WHERE id=?", a.id).Scan(&state); e == nil && state == string(outcome.State) {
				return nil
			}
			return ErrConflict
		}
		return nil
	})
	a.mu.Lock()
	if err == nil {
		a.terminal = true
	}
	a.finishing = false
	a.cond.Broadcast()
	a.mu.Unlock()
	return err
}

func (c *Case) ImportEvidenceFile(ctx context.Context, path string, spec EvidenceSpec) (Evidence, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return Evidence{}, err
	}
	if !st.Mode().IsRegular() {
		return Evidence{}, fmt.Errorf("%w: evidence source must be a regular file", ErrInvalid)
	}
	f, err := os.Open(path)
	if err != nil {
		return Evidence{}, err
	}
	defer f.Close()
	return c.ImportEvidence(ctx, filepath.Base(path), spec, f)
}

func (c *Case) ImportEvidence(ctx context.Context, name string, spec EvidenceSpec, r io.Reader) (Evidence, error) {
	if strings.TrimSpace(name) == "" {
		return Evidence{}, fmt.Errorf("%w: evidence name required", ErrInvalid)
	}
	staged, err := c.stageBlob(ctx, r)
	if err != nil {
		return Evidence{}, err
	}
	if want := strings.ToLower(spec.Acquisition.SuppliedHashes["sha256"]); want != "" && want != staged.digest {
		_ = os.Remove(staged.path)
		return Evidence{}, fmt.Errorf("%w: supplied SHA-256 does not match managed bytes", ErrIntegrity)
	}
	if err = c.publishBlob(ctx, staged); err != nil {
		return Evidence{}, err
	}
	eid, err := newEvidenceID()
	if err != nil {
		return Evidence{}, err
	}
	oid, err := newObjectID()
	if err != nil {
		return Evidence{}, err
	}
	aid, err := newActivityID()
	if err != nil {
		return Evidence{}, err
	}
	fp, _, err := digestJSON(struct {
		Name string
		Spec EvidenceSpec
		Blob BlobRef
	}{name, spec, staged.ref})
	if err != nil {
		return Evidence{}, err
	}
	result := Evidence{ID: eid, Label: spec.Label, Acquisition: spec.Acquisition, RootObject: ObjectRef{ID: oid, Blob: staged.ref, Size: staged.size, DisplayName: name, GeneratingActivity: aid}}
	_, err = c.mutate(ctx, c.defaultAgent.ID, "", "evidence.import", fp, []string{string(eid), string(oid), string(staged.ref)}, func(tx *sql.Tx, rev int64) error {
		if spec.IdempotencyKey != "" {
			var old Evidence
			ok, e := lookupIdempotency(ctx, tx, string(c.id), "evidence.import", spec.IdempotencyKey, fp, &old)
			if e != nil {
				return e
			}
			if ok {
				result = old
				return nil
			}
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		cfg, _ := canonicalJSON(spec.Acquisition)
		out, _ := canonicalJSON(OutcomeSucceeded())
		if _, e := tx.ExecContext(ctx, "INSERT INTO activities(id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json,idempotency_key) VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?,?)", aid, c.defaultAgent.ID, ActivityImport, "Import evidence "+name, string(cfg), fp, CaptureLibrary, ActivitySucceeded, rev, now, now, string(out), spec.IdempotencyKey); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO blobs(digest,size,created_at) VALUES(?,?,?)", staged.ref, staged.size, now); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", eid, EntityEvidence, aid, rev, now, spec.Label); e != nil {
			return e
		}
		acq, _ := canonicalJSON(spec.Acquisition)
		if _, e := tx.ExecContext(ctx, "INSERT INTO evidence(id,label,acquisition_json) VALUES(?,?,?)", eid, spec.Label, string(acq)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", oid, EntityObject, aid, rev, now, name); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO objects(id,blob_digest,size,role,path_display) VALUES(?,?,?,?,?)", oid, staged.ref, staged.size, "original", name); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO evidence_objects(evidence_id,object_id,role) VALUES(?,?,'root')", eid, oid); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'evidence'),(?,?,'original')", aid, eid, aid, oid); e != nil {
			return e
		}
		result.CreatedRevision = rev
		result.RootObject.CreatedRevision = rev
		return storeIdempotency(ctx, tx, string(c.id), "evidence.import", spec.IdempotencyKey, fp, result)
	})
	return result, err
}

func encodeLocator(loc SourceLocator) (path, typ, data string, err error) {
	if loc == nil {
		return "", "", "", nil
	}
	b, e := canonicalJSON(loc)
	if e != nil {
		return "", "", "", e
	}
	typ = string(loc.LocatorType())
	data = string(b)
	if p, ok := loc.(PathLocator); ok {
		path = p.Display
	}
	if pp, ok := loc.(*PathLocator); ok {
		path = pp.Display
	}
	return
}

func (c *Case) Object(ctx context.Context, id ObjectID) (ObjectRef, error) {
	var o ObjectRef
	var act ActivityID
	err := c.db.QueryRowContext(ctx, "SELECT o.id,o.blob_digest,o.size,e.display_name,e.media_type,o.path_display,e.generating_activity_id,e.created_revision FROM objects o JOIN entities e ON e.id=o.id WHERE o.id=?", id).Scan(&o.ID, &o.Blob, &o.Size, &o.DisplayName, &o.MediaType, &o.Path, &act, &o.CreatedRevision)
	o.GeneratingActivity = act
	if errors.Is(err, sql.ErrNoRows) {
		return o, ErrNotFound
	}
	return o, mapSQLError(err)
}

func (c *Case) OpenObject(ctx context.Context, id ObjectID) (ObjectReader, error) {
	o, err := c.Object(ctx, id)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(c.blobPath(o.Blob))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	return &managedObjectReader{File: f, object: o}, nil
}
