package forensic

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

func validValueType(t ValueType) bool {
	switch t {
	case ValueString, ValueInteger, ValueUnsigned, ValueReal, ValueBoolean, ValueBytes, ValueTime, ValueDuration, ValueURI, ValueJSON, ValueObjectRef, ValueArtifactRef, ValueNull:
		return true
	}
	return false
}

func (a *Activity) EmitArtifact(ctx context.Context, key ProducerKey, draft ArtifactDraft) (ArtifactRef, error) {
	if err := a.startCapture(); err != nil {
		return ArtifactRef{}, err
	}
	defer a.endCapture()
	if strings.TrimSpace(draft.Type) == "" || draft.Source == "" {
		return ArtifactRef{}, fmt.Errorf("%w: artifact type and source are required", ErrInvalid)
	}
	draft.Values = append([]ArtifactValue(nil), draft.Values...)
	for i := range draft.Values {
		if draft.Values[i].Property == "" || !validValueType(draft.Values[i].Type) {
			return ArtifactRef{}, fmt.Errorf("%w: invalid artifact value %d", ErrInvalid, i)
		}
		if draft.Values[i].Temporal != nil {
			if draft.Values[i].Type != ValueTime {
				return ArtifactRef{}, fmt.Errorf("%w: temporal metadata requires a time value", ErrInvalid)
			}
			temporal, e := normalizeTemporalValue(*draft.Values[i].Temporal)
			if e != nil {
				return ArtifactRef{}, fmt.Errorf("%w: invalid temporal value %d: %v", ErrInvalid, i, e)
			}
			draft.Values[i].Temporal = &temporal
		}
	}
	fp, err := artifactDraftFingerprint(draft)
	if err != nil {
		return ArtifactRef{}, err
	}
	id, err := newArtifactID()
	if err != nil {
		return ArtifactRef{}, err
	}
	ref := ArtifactRef{ID: id, Type: draft.Type, DisplayName: draft.DisplayName, Source: draft.Source, GeneratingActivity: a.id, Values: append([]ArtifactValue(nil), draft.Values...)}
	_, err = a.caseRef.mutate(ctx, a.session.info.Agent.ID, a.session.ID(), "artifact.emit", fp, []string{string(a.id), string(id)}, func(tx *sql.Tx, rev int64) error {
		if key != "" {
			var oldID ArtifactID
			var oldFP string
			e := tx.QueryRowContext(ctx, "SELECT id,producer_fingerprint FROM artifacts WHERE generating_activity_id=? AND producer_key=?", a.id, key).Scan(&oldID, &oldFP)
			if e == nil {
				if oldFP != fp {
					return ErrConflict
				}
				old, e2 := loadArtifact(ctx, tx, oldID)
				if e2 == nil {
					ref = old
				}
				if e2 != nil {
					return e2
				}
				return errIdempotentReplay
			}
			if !errors.Is(e, sql.ErrNoRows) {
				return e
			}
		}
		var state string
		var used int
		if e := tx.QueryRowContext(ctx, "SELECT state FROM activities WHERE id=?", a.id).Scan(&state); e != nil {
			return e
		}
		if state != string(ActivityRunning) {
			return ErrConflict
		}
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM activity_inputs WHERE activity_id=? AND entity_id=?", a.id, draft.Source).Scan(&used); e != nil {
			return e
		}
		if used == 0 {
			return fmt.Errorf("%w: artifact source must be an activity input", ErrInvalid)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, e := tx.ExecContext(ctx, "UPDATE activities SET inputs_sealed=1,sealed_revision=COALESCE(sealed_revision,?) WHERE id=?", rev, a.id); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,schema_uri,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?,?)", id, EntityArtifact, draft.Type, a.id, rev, now, draft.DisplayName); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO artifacts(id,artifact_type,source_object_id,producer_key,producer_fingerprint,generating_activity_id) VALUES(?,?,?,?,?,?)", id, draft.Type, draft.Source, key, fp, a.id); e != nil {
			return e
		}
		for i, v := range draft.Values {
			norm, typ, data, e := encodeArtifactValue(v)
			if e != nil {
				return e
			}
			var conf any
			if v.Confidence != nil {
				conf = *v.Confidence
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO artifact_values(artifact_id,ordinal,property,schema_uri,value_type,raw,normalized_json,unit,encoding,language,confidence,interpretation,locator_type,locator_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", id, i, v.Property, v.SchemaURI, v.Type, v.Raw, norm, v.Unit, v.Encoding, v.Language, conf, v.Interpretation, typ, data); e != nil {
				return e
			}
			if v.Temporal != nil {
				temporalJSON, e := canonicalJSON(v.Temporal)
				if e != nil {
					return e
				}
				var start, end any
				if v.Temporal.UTCStart != nil {
					start = v.Temporal.UTCStart.Format(time.RFC3339Nano)
				}
				if v.Temporal.UTCEnd != nil {
					end = v.Temporal.UTCEnd.Format(time.RFC3339Nano)
				}
				if _, e = tx.ExecContext(ctx, "INSERT INTO temporal_values(artifact_id,value_ordinal,temporal_json,utc_start,utc_end,semantic_role) VALUES(?,?,?,?,?,?)", id, i, string(temporalJSON), start, end, v.Temporal.SemanticRole); e != nil {
					return e
				}
			}
			text := v.Raw
			if text == "" {
				text = norm
			}
			if text != "" {
				if _, e = tx.ExecContext(ctx, "INSERT INTO artifact_fts(artifact_id,property,text) VALUES(?,?,?)", id, v.Property, text); e != nil {
					return e
				}
			}
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'artifact')", a.id, id); e != nil {
			return e
		}
		ref.CreatedRevision = rev
		return nil
	})
	return ref, err
}

func artifactDraftFingerprint(d ArtifactDraft) (string, error) {
	type value struct {
		Property                 string
		SchemaURI                string
		Type                     ValueType
		Raw                      string
		Normalized               any
		Unit, Encoding, Language string
		Confidence               *float64
		Interpretation           string
		Ordinal                  int
		LocatorType, LocatorJSON string
		Temporal                 *TemporalValue
	}
	values := make([]value, len(d.Values))
	for i, v := range d.Values {
		_, lt, lj, err := encodeLocator(v.Source)
		if err != nil {
			return "", err
		}
		values[i] = value{v.Property, v.SchemaURI, v.Type, v.Raw, v.Normalized, v.Unit, v.Encoding, v.Language, v.Confidence, v.Interpretation, v.Ordinal, lt, lj, v.Temporal}
	}
	digest, _, err := digestJSON(struct {
		Type, DisplayName string
		Source            ObjectID
		Values            []value
	}{d.Type, d.DisplayName, d.Source, values})
	return digest, err
}

func encodeArtifactValue(v ArtifactValue) (norm, locatorType, locatorJSON string, err error) {
	if v.Normalized != nil {
		b, e := canonicalJSON(v.Normalized)
		if e != nil {
			return "", "", "", e
		}
		norm = string(b)
	}
	_, locatorType, locatorJSON, err = encodeLocator(v.Source)
	return
}

type dbQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadArtifact(ctx context.Context, q dbQuery, id ArtifactID) (ArtifactRef, error) {
	var a ArtifactRef
	err := q.QueryRowContext(ctx, "SELECT a.id,a.artifact_type,e.display_name,a.source_object_id,e.generating_activity_id,e.created_revision FROM artifacts a JOIN entities e ON e.id=a.id WHERE a.id=?", id).Scan(&a.ID, &a.Type, &a.DisplayName, &a.Source, &a.GeneratingActivity, &a.CreatedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	rows, err := q.QueryContext(ctx, `SELECT av.ordinal,av.property,av.schema_uri,av.value_type,av.raw,av.normalized_json,av.unit,av.encoding,av.language,av.confidence,av.interpretation,av.locator_type,av.locator_json,tv.temporal_json FROM artifact_values av LEFT JOIN temporal_values tv ON tv.artifact_id=av.artifact_id AND tv.value_ordinal=av.ordinal WHERE av.artifact_id=? ORDER BY av.ordinal`, id)
	if err != nil {
		return a, err
	}
	defer rows.Close()
	for rows.Next() {
		var v ArtifactValue
		var norm sql.NullString
		var conf sql.NullFloat64
		var lt, lj sql.NullString
		var temporalJSON sql.NullString
		if err = rows.Scan(&v.Ordinal, &v.Property, &v.SchemaURI, &v.Type, &v.Raw, &norm, &v.Unit, &v.Encoding, &v.Language, &conf, &v.Interpretation, &lt, &lj, &temporalJSON); err != nil {
			return a, err
		}
		if norm.Valid {
			dec := json.NewDecoder(bytes.NewBufferString(norm.String))
			dec.UseNumber()
			_ = dec.Decode(&v.Normalized)
		}
		if conf.Valid {
			v.Confidence = &conf.Float64
		}
		v.Source = decodeLocator(lt.String, lj.String)
		if temporalJSON.Valid {
			var temporal TemporalValue
			if json.Unmarshal([]byte(temporalJSON.String), &temporal) != nil {
				return a, ErrIntegrity
			}
			v.Temporal = &temporal
		}
		a.Values = append(a.Values, v)
	}
	return a, rows.Err()
}

func decodeLocator(typ, data string) SourceLocator {
	if typ == "" || data == "" {
		return nil
	}
	switch LocatorType(typ) {
	case LocatorPath:
		var v PathLocator
		if json.Unmarshal([]byte(data), &v) == nil {
			return v
		}
	case LocatorExtent:
		var v ExtentLocator
		if json.Unmarshal([]byte(data), &v) == nil {
			return v
		}
	case LocatorSQLite:
		var v SQLiteLocator
		if json.Unmarshal([]byte(data), &v) == nil {
			return v
		}
	case LocatorJSON:
		var v JSONLocator
		if json.Unmarshal([]byte(data), &v) == nil {
			return v
		}
	case LocatorXML:
		var v XMLLocator
		if json.Unmarshal([]byte(data), &v) == nil {
			return v
		}
	case LocatorArchive:
		var v ArchiveLocator
		if json.Unmarshal([]byte(data), &v) == nil {
			return v
		}
	case LocatorRegistry:
		var v RegistryLocator
		if json.Unmarshal([]byte(data), &v) == nil {
			return v
		}
	case LocatorAPI:
		var v APILocator
		if json.Unmarshal([]byte(data), &v) == nil {
			return v
		}
	case LocatorCustom:
		var v CustomLocator
		if json.Unmarshal([]byte(data), &v) == nil {
			return v
		}
	}
	return CustomLocator{Type: typ, Data: map[string]any{"raw": data}}
}

func normalizeTemporalValue(v TemporalValue) (TemporalValue, error) {
	if v.UTCStart == nil && v.UTCEnd != nil {
		return TemporalValue{}, fmt.Errorf("interval end requires a start")
	}
	if v.UTCStart != nil {
		start := v.UTCStart.UTC()
		v.UTCStart = &start
		if v.UTCEnd == nil {
			end := start
			v.UTCEnd = &end
		} else {
			end := v.UTCEnd.UTC()
			if end.Before(start) {
				return TemporalValue{}, fmt.Errorf("interval ends before it starts")
			}
			v.UTCEnd = &end
		}
	}
	if v.Confidence != nil && (*v.Confidence < 0 || *v.Confidence > 1) {
		return TemporalValue{}, fmt.Errorf("confidence must be between zero and one")
	}
	switch v.TimezoneBasis {
	case "", TimezoneExplicit, TimezoneAssumed, TimezoneInferred, TimezoneUnknown:
	default:
		return TemporalValue{}, fmt.Errorf("unknown timezone basis")
	}
	return v, nil
}

func (c *Case) Artifact(ctx context.Context, id ArtifactID) (ArtifactRef, error) {
	if err := c.checkOpen(); err != nil {
		return ArtifactRef{}, err
	}
	a, err := loadArtifact(ctx, c.db, id)
	return a, mapSQLError(err)
}

func (a *Activity) EmitObject(ctx context.Context, key ProducerKey, spec ObjectSpec, r io.Reader) (ObjectRef, error) {
	spec.IdempotencyKey = string(key)
	return a.Capture(ctx, spec, r)
}

func (a *Activity) Relate(ctx context.Context, key ProducerKey, spec AssertionSpec) (AssertionRef, error) {
	if err := a.startCapture(); err != nil {
		return AssertionRef{}, err
	}
	defer a.endCapture()
	if spec.Type == "" || len(spec.Targets) == 0 {
		return AssertionRef{}, fmt.Errorf("%w: assertion type and targets are required", ErrInvalid)
	}
	fp, _, err := digestJSON(spec)
	if err != nil {
		return AssertionRef{}, err
	}
	id, err := newAssertionID()
	if err != nil {
		return AssertionRef{}, err
	}
	ref := AssertionRef{ID: id, Type: spec.Type, Body: spec.Body, Targets: append([]EntityRef(nil), spec.Targets...), Confidence: spec.Confidence, Supersedes: spec.Supersedes, GeneratingActivity: a.id}
	_, err = a.caseRef.mutate(ctx, a.session.info.Agent.ID, a.session.ID(), "assertion.emit", fp, []string{string(a.id), string(id)}, func(tx *sql.Tx, rev int64) error {
		if key != "" {
			var oldID AssertionID
			var oldFP string
			e := tx.QueryRowContext(ctx, "SELECT id,producer_fingerprint FROM assertions WHERE generating_activity_id=? AND producer_key=?", a.id, key).Scan(&oldID, &oldFP)
			if e == nil {
				if oldFP != fp {
					return ErrConflict
				}
				if e = tx.QueryRowContext(ctx, "SELECT e.created_revision FROM entities e WHERE e.id=?", oldID).Scan(&ref.CreatedRevision); e != nil {
					return e
				}
				ref.ID = oldID
				return errIdempotentReplay
			}
			if !errors.Is(e, sql.ErrNoRows) {
				return e
			}
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		var state string
		if e := tx.QueryRowContext(ctx, "SELECT state FROM activities WHERE id=?", a.id).Scan(&state); e != nil {
			return e
		}
		if state != string(ActivityRunning) {
			return ErrConflict
		}
		if _, e := tx.ExecContext(ctx, "UPDATE activities SET inputs_sealed=1,sealed_revision=COALESCE(sealed_revision,?) WHERE id=?", rev, a.id); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", id, EntityAssertion, a.id, rev, now, spec.Type); e != nil {
			return e
		}
		var confidence any
		if spec.Confidence != nil {
			confidence = *spec.Confidence
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO assertions(id,assertion_type,body,confidence,supersedes_id,producer_key,producer_fingerprint,generating_activity_id) VALUES(?,?,?,?,?,?,?,?)", id, spec.Type, spec.Body, confidence, nullString(string(spec.Supersedes)), key, fp, a.id); e != nil {
			return e
		}
		for _, target := range spec.Targets {
			if _, e := tx.ExecContext(ctx, "INSERT INTO assertion_targets(assertion_id,target_id,target_kind) VALUES(?,?,?)", id, target.ID, target.Kind); e != nil {
				return e
			}
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'assertion')", a.id, id); e != nil {
			return e
		}
		ref.CreatedRevision = rev
		return nil
	})
	return ref, err
}

func (a *Activity) Flush(context.Context) error { return nil }
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Session) AuthorFinding(ctx context.Context, spec FindingSpec) (FindingRef, error) {
	if err := s.checkOpen(); err != nil {
		return FindingRef{}, err
	}
	if strings.TrimSpace(spec.Title) == "" {
		return FindingRef{}, fmt.Errorf("%w: finding title is required", ErrInvalid)
	}
	if spec.Status == "" {
		spec.Status = FindingDraft
	}
	if err := validateFindingFields(spec.Status, spec.Confidence); err != nil {
		return FindingRef{}, err
	}
	assignees, err := normalizeAgentIDs(spec.Assignees)
	if err != nil {
		return FindingRef{}, err
	}
	spec.Assignees = assignees
	fid, err := newFindingID()
	if err != nil {
		return FindingRef{}, err
	}
	rid, err := newFindingRevisionID()
	if err != nil {
		return FindingRef{}, err
	}
	aid, err := newActivityID()
	if err != nil {
		return FindingRef{}, err
	}
	fp, cfg, err := digestJSON(spec)
	if err != nil {
		return FindingRef{}, err
	}
	ref := FindingRef{ID: fid, Current: rid, Version: 1, Title: spec.Title, Body: spec.Body, Status: spec.Status, Confidence: spec.Confidence, Severity: spec.Severity, ReviewState: spec.ReviewState, Assignees: append([]AgentID(nil), spec.Assignees...), Vulnerability: spec.Vulnerability}
	_, err = s.caseRef.mutate(ctx, s.info.Agent.ID, s.ID(), "finding.author", fp, []string{string(fid), string(rid)}, func(tx *sql.Tx, rev int64) error {
		if spec.IdempotencyKey != "" {
			var old FindingRef
			ok, e := lookupIdempotency(ctx, tx, string(s.ID()), "finding.author", spec.IdempotencyKey, fp, &old)
			if e != nil {
				return e
			}
			if ok {
				ref = old
				return errIdempotentReplay
			}
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		out, _ := canonicalJSON(OutcomeSucceeded())
		if _, e := tx.ExecContext(ctx, "INSERT INTO activities(id,session_id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?)", aid, s.ID(), s.info.Agent.ID, ActivityFindingAuthor, "Author finding: "+spec.Title, string(cfg), fp, CaptureLibrary, ActivitySucceeded, rev, now, now, string(out)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO findings(id,title,current_revision_id,current_version) VALUES(?,?,?,1)", fid, spec.Title, rid); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", rid, EntityFindingRevision, aid, rev, now, spec.Title); e != nil {
			return e
		}
		var confidence any
		if spec.Confidence != nil {
			confidence = *spec.Confidence
		}
		assigneesJSON, _ := canonicalJSON(spec.Assignees)
		vulnerabilityJSON, _ := canonicalJSON(spec.Vulnerability)
		if _, e := tx.ExecContext(ctx, "INSERT INTO finding_revisions(id,finding_id,version,body,status,confidence,severity,review_state,assignees_json,vulnerability_json) VALUES(?,?,?,?,?,?,?,?,?,?)", rid, fid, 1, spec.Body, spec.Status, confidence, spec.Severity, spec.ReviewState, string(assigneesJSON), nullString(string(vulnerabilityJSON))); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_agents(activity_id,agent_id,role) VALUES(?,?,'author')", aid, s.info.Agent.ID); e != nil {
			return e
		}
		for _, assignee := range spec.Assignees {
			inserted, e := tx.ExecContext(ctx, "INSERT INTO activity_agents(activity_id,agent_id,role) SELECT ?,?,'assignee' WHERE EXISTS(SELECT 1 FROM agents WHERE id=?)", aid, assignee, assignee)
			if e != nil {
				return e
			}
			if count, _ := inserted.RowsAffected(); count != 1 {
				return ErrNotFound
			}
		}
		members := flattenMembers(spec.Members)
		for _, m := range members {
			if _, e := tx.ExecContext(ctx, "INSERT INTO finding_members(revision_id,entity_id,role) VALUES(?,?,?)", rid, m.Ref.ID, m.Role); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,?)", aid, m.Ref.ID, m.Role); e != nil {
				return e
			}
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'finding-revision')", aid, rid); e != nil {
			return e
		}
		ref.CreatedRevision = rev
		return storeIdempotency(ctx, tx, string(s.ID()), "finding.author", spec.IdempotencyKey, fp, ref)
	})
	return ref, err
}

func (s *Session) ReviseFinding(ctx context.Context, id FindingID, spec FindingRevisionSpec) (FindingRef, error) {
	if err := s.checkOpen(); err != nil {
		return FindingRef{}, err
	}
	if spec.ExpectedRevision == "" {
		return FindingRef{}, fmt.Errorf("%w: expected revision is required", ErrInvalid)
	}
	if spec.Status == "" {
		spec.Status = FindingDraft
	}
	if err := validateFindingFields(spec.Status, spec.Confidence); err != nil {
		return FindingRef{}, err
	}
	assignees, err := normalizeAgentIDs(spec.Assignees)
	if err != nil {
		return FindingRef{}, err
	}
	spec.Assignees = assignees
	rid, err := newFindingRevisionID()
	if err != nil {
		return FindingRef{}, err
	}
	aid, err := newActivityID()
	if err != nil {
		return FindingRef{}, err
	}
	fp, cfg, err := digestJSON(struct {
		ID   FindingID
		Spec FindingRevisionSpec
	}{id, spec})
	if err != nil {
		return FindingRef{}, err
	}
	var ref FindingRef
	_, err = s.caseRef.mutate(ctx, s.info.Agent.ID, s.ID(), "finding.revise", fp, []string{string(id), string(rid)}, func(tx *sql.Tx, rev int64) error {
		if spec.IdempotencyKey != "" {
			var old FindingRef
			ok, e := lookupIdempotency(ctx, tx, string(s.ID()), "finding.revise", spec.IdempotencyKey, fp, &old)
			if e != nil {
				return e
			}
			if ok {
				ref = old
				return errIdempotentReplay
			}
		}
		var title string
		var current FindingRevisionID
		var version int
		if e := tx.QueryRowContext(ctx, "SELECT title,current_revision_id,current_version FROM findings WHERE id=?", id).Scan(&title, &current, &version); errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		} else if e != nil {
			return e
		}
		if current != spec.ExpectedRevision {
			return ErrConflict
		}
		version++
		now := time.Now().UTC().Format(time.RFC3339Nano)
		out, _ := canonicalJSON(OutcomeSucceeded())
		if _, e := tx.ExecContext(ctx, "INSERT INTO activities(id,session_id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?)", aid, s.ID(), s.info.Agent.ID, ActivityFindingReview, "Revise finding: "+title, string(cfg), fp, CaptureLibrary, ActivitySucceeded, rev, now, now, string(out)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", rid, EntityFindingRevision, aid, rev, now, title); e != nil {
			return e
		}
		var confidence any
		if spec.Confidence != nil {
			confidence = *spec.Confidence
		}
		assigneesJSON, _ := canonicalJSON(spec.Assignees)
		vulnerabilityJSON, _ := canonicalJSON(spec.Vulnerability)
		if _, e := tx.ExecContext(ctx, "INSERT INTO finding_revisions(id,finding_id,version,body,status,confidence,severity,review_state,assignees_json,vulnerability_json,predecessor_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)", rid, id, version, spec.Body, spec.Status, confidence, spec.Severity, spec.ReviewState, string(assigneesJSON), nullString(string(vulnerabilityJSON)), current); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_agents(activity_id,agent_id,role) VALUES(?,?,'reviewer')", aid, s.info.Agent.ID); e != nil {
			return e
		}
		for _, assignee := range spec.Assignees {
			inserted, e := tx.ExecContext(ctx, "INSERT INTO activity_agents(activity_id,agent_id,role) SELECT ?,?,'assignee' WHERE EXISTS(SELECT 1 FROM agents WHERE id=?)", aid, assignee, assignee)
			if e != nil {
				return e
			}
			if count, _ := inserted.RowsAffected(); count != 1 {
				return ErrNotFound
			}
		}
		for _, m := range flattenMembers(spec.Members) {
			if _, e := tx.ExecContext(ctx, "INSERT INTO finding_members(revision_id,entity_id,role) VALUES(?,?,?)", rid, m.Ref.ID, m.Role); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,?)", aid, m.Ref.ID, m.Role); e != nil {
				return e
			}
		}
		if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'predecessor')", aid, current); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'finding-revision')", aid, rid); e != nil {
			return e
		}
		res, e := tx.ExecContext(ctx, "UPDATE findings SET current_revision_id=?,current_version=? WHERE id=? AND current_revision_id=?", rid, version, id, current)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return ErrConflict
		}
		ref = FindingRef{ID: id, Current: rid, Version: version, Title: title, Body: spec.Body, Status: spec.Status, Confidence: spec.Confidence, Severity: spec.Severity, ReviewState: spec.ReviewState, Assignees: append([]AgentID(nil), spec.Assignees...), Vulnerability: spec.Vulnerability, CreatedRevision: rev}
		return storeIdempotency(ctx, tx, string(s.ID()), "finding.revise", spec.IdempotencyKey, fp, ref)
	})
	return ref, err
}

type memberRole struct {
	Role string
	Ref  EntityRef
}

func flattenMembers(m map[string][]EntityRef) []memberRole {
	var roles []string
	for r := range m {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	var out []memberRole
	for _, r := range roles {
		refs := append([]EntityRef(nil), m[r]...)
		sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
		for _, ref := range refs {
			out = append(out, memberRole{r, ref})
		}
	}
	return out
}

func (c *Case) Finding(ctx context.Context, id FindingID) (FindingRef, error) {
	var f FindingRef
	var confidence sql.NullFloat64
	var assigneesJSON string
	var vulnerabilityJSON sql.NullString
	err := c.db.QueryRowContext(ctx, "SELECT f.id,f.current_revision_id,f.current_version,f.title,r.body,r.status,r.confidence,r.severity,r.review_state,r.assignees_json,r.vulnerability_json,e.created_revision FROM findings f JOIN finding_revisions r ON r.id=f.current_revision_id JOIN entities e ON e.id=r.id WHERE f.id=?", id).Scan(&f.ID, &f.Current, &f.Version, &f.Title, &f.Body, &f.Status, &confidence, &f.Severity, &f.ReviewState, &assigneesJSON, &vulnerabilityJSON, &f.CreatedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	if err != nil {
		return f, mapSQLError(err)
	}
	if confidence.Valid {
		f.Confidence = &confidence.Float64
	}
	if json.Unmarshal([]byte(assigneesJSON), &f.Assignees) != nil {
		return f, ErrIntegrity
	}
	if vulnerabilityJSON.Valid && vulnerabilityJSON.String != "null" {
		var vulnerability VulnerabilityDetails
		if json.Unmarshal([]byte(vulnerabilityJSON.String), &vulnerability) != nil {
			return f, ErrIntegrity
		}
		f.Vulnerability = &vulnerability
	}
	return f, nil
}

func validateFindingFields(status FindingStatus, confidence *float64) error {
	switch status {
	case FindingDraft, FindingConfirmed, FindingRejected, FindingResolved:
	default:
		return fmt.Errorf("%w: invalid finding status", ErrInvalid)
	}
	if confidence != nil && (*confidence < 0 || *confidence > 1) {
		return fmt.Errorf("%w: finding confidence must be between zero and one", ErrInvalid)
	}
	return nil
}

func normalizeAgentIDs(ids []AgentID) ([]AgentID, error) {
	result := append([]AgentID(nil), ids...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	for i, id := range result {
		if id == "" || (i > 0 && result[i-1] == id) {
			return nil, fmt.Errorf("%w: finding assignees must be unique agent IDs", ErrInvalid)
		}
	}
	return result, nil
}

func (s *Session) Parse(ctx context.Context, input ObjectRef, p Parser, config map[string]any) error {
	_, err := s.ParseObject(ctx, input, p, ParseOptions{Config: config})
	return err
}
