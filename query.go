package forensic

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

type entityView struct {
	ref          EntityRef
	activity     ActivityID
	session      SessionID
	path         string
	hash         BlobRef
	artifactType string
	values       map[string][]string
}

func validateQuery(q Query, depth *int, nodes *int) error {
	*nodes++
	if *nodes > 256 {
		return fmt.Errorf("%w: query is too large", ErrInvalid)
	}
	if *depth > 32 {
		return fmt.Errorf("%w: query is too deep", ErrInvalid)
	}
	switch q.Op {
	case QueryAll, QueryKind, QueryID, QueryPathGlob, QueryHash, QueryActivity, QuerySession, QueryArtifactType, QueryValue, QuerySelection, QueryTree:
		if len(q.Children) != 0 {
			return fmt.Errorf("%w: leaf query has children", ErrInvalid)
		}
	case QueryNot:
		if len(q.Children) != 1 {
			return fmt.Errorf("%w: not requires one child", ErrInvalid)
		}
	case QueryAnd, QueryOr:
		if len(q.Children) == 0 {
			return fmt.Errorf("%w: boolean query requires children", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unknown query operator", ErrInvalid)
	}
	for _, c := range q.Children {
		d := *depth + 1
		if err := validateQuery(c, &d, nodes); err != nil {
			return err
		}
	}
	return nil
}

func (c *Case) Query(ctx context.Context, q Query) (QueryResult, error) {
	if err := c.checkOpen(); err != nil {
		return QueryResult{}, err
	}
	d, n := 0, 0
	if err := validateQuery(q, &d, &n); err != nil {
		return QueryResult{}, err
	}
	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return QueryResult{}, mapSQLError(err)
	}
	defer tx.Rollback()
	var rev int64
	if err = tx.QueryRowContext(ctx, "SELECT revision FROM case_info WHERE singleton=1").Scan(&rev); err != nil {
		return QueryResult{}, err
	}
	views, err := loadEntityViews(ctx, tx, rev)
	if err != nil {
		return QueryResult{}, err
	}
	membershipCache := map[string]map[string]bool{}
	var out []EntityRef
	for _, v := range views {
		ok, e := matchQuery(ctx, tx, q, v, membershipCache)
		if e != nil {
			return QueryResult{}, e
		}
		if ok {
			out = append(out, v.ref)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].ID < out[j].ID
		}
		return out[i].Kind < out[j].Kind
	})
	if err = tx.Commit(); err != nil {
		return QueryResult{}, mapSQLError(err)
	}
	return QueryResult{Revision: rev, Entities: out}, nil
}

func loadEntityViews(ctx context.Context, tx *sql.Tx, rev int64) ([]entityView, error) {
	rows, err := tx.QueryContext(ctx, `SELECT e.id,e.kind,e.generating_activity_id,COALESCE(a.session_id,''),COALESCE(o.path_display,''),COALESCE(o.blob_digest,''),COALESCE(ar.artifact_type,'') FROM entities e JOIN activities a ON a.id=e.generating_activity_id LEFT JOIN objects o ON o.id=e.id LEFT JOIN artifacts ar ON ar.id=e.id WHERE e.created_revision<=? ORDER BY e.kind,e.id`, rev)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var views []entityView
	index := map[string]int{}
	for rows.Next() {
		var v entityView
		if err = rows.Scan(&v.ref.ID, &v.ref.Kind, &v.activity, &v.session, &v.path, &v.hash, &v.artifactType); err != nil {
			return nil, err
		}
		v.values = map[string][]string{}
		index[v.ref.ID] = len(views)
		views = append(views, v)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	vr, err := tx.QueryContext(ctx, `SELECT artifact_id,property,raw,COALESCE(normalized_json,'') FROM artifact_values`)
	if err != nil {
		return nil, err
	}
	defer vr.Close()
	for vr.Next() {
		var id, prop, raw, norm string
		if err = vr.Scan(&id, &prop, &raw, &norm); err != nil {
			return nil, err
		}
		if i, ok := index[id]; ok {
			views[i].values[prop] = append(views[i].values[prop], raw, norm)
		}
	}
	return views, vr.Err()
}

func matchQuery(ctx context.Context, tx *sql.Tx, q Query, v entityView, cache map[string]map[string]bool) (bool, error) {
	switch q.Op {
	case QueryAll:
		return true, nil
	case QueryKind:
		return string(v.ref.Kind) == q.Value, nil
	case QueryID:
		return v.ref.ID == q.Value, nil
	case QueryPathGlob:
		return globMatch(q.Value, v.path)
	case QueryHash:
		return string(v.hash) == q.Value, nil
	case QueryActivity:
		return string(v.activity) == q.Value, nil
	case QuerySession:
		return string(v.session) == q.Value, nil
	case QueryArtifactType:
		return v.artifactType == q.Value, nil
	case QueryValue:
		for _, x := range v.values[q.Property] {
			if x == q.Value {
				return true, nil
			}
		}
		return false, nil
	case QuerySelection:
		id := SelectionID(q.Value)
		cacheKey := "selection:" + string(id)
		members, ok := cache[cacheKey]
		if !ok {
			members = map[string]bool{}
			rows, err := tx.QueryContext(ctx, "SELECT entity_id FROM selection_members WHERE selection_id=?", id)
			if err != nil {
				return false, err
			}
			for rows.Next() {
				var x string
				if err = rows.Scan(&x); err != nil {
					rows.Close()
					return false, err
				}
				members[x] = true
			}
			rows.Close()
			cache[cacheKey] = members
		}
		return members[v.ref.ID], nil
	case QueryTree:
		id := TreeID(q.Value)
		cacheKey := "tree:" + string(id)
		members, ok := cache[cacheKey]
		if !ok {
			members = map[string]bool{}
			rows, err := tx.QueryContext(ctx, `SELECT id FROM (SELECT id FROM source_trees WHERE id=? UNION SELECT manifest_object_id FROM source_trees WHERE id=? UNION SELECT object_id FROM tree_entries WHERE tree_id=? AND object_id IS NOT NULL)`, id, id, id)
			if err != nil {
				return false, err
			}
			for rows.Next() {
				var entityID string
				if err = rows.Scan(&entityID); err != nil {
					rows.Close()
					return false, err
				}
				members[entityID] = true
			}
			if err = rows.Err(); err != nil {
				rows.Close()
				return false, err
			}
			if err = rows.Close(); err != nil {
				return false, err
			}
			cache[cacheKey] = members
		}
		return members[v.ref.ID], nil
	case QueryNot:
		ok, err := matchQuery(ctx, tx, q.Children[0], v, cache)
		return !ok, err
	case QueryAnd:
		for _, child := range q.Children {
			ok, err := matchQuery(ctx, tx, child, v, cache)
			if err != nil || !ok {
				return ok, err
			}
		}
		return true, nil
	case QueryOr:
		for _, child := range q.Children {
			ok, err := matchQuery(ctx, tx, child, v, cache)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	return false, ErrInvalid
}

func globMatch(pattern, value string) (bool, error) {
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	value = strings.ReplaceAll(value, "\\", "/")
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteByte('$')
	r, err := regexp.Compile(b.String())
	if err != nil {
		return false, fmt.Errorf("%w: invalid glob", ErrInvalid)
	}
	return r.MatchString(value), nil
}

func (s *Session) Freeze(ctx context.Context, spec FreezeSpec) (Selection, error) {
	if err := s.checkOpen(); err != nil {
		return Selection{}, err
	}
	if strings.TrimSpace(spec.Name) == "" {
		return Selection{}, fmt.Errorf("%w: selection name required", ErrInvalid)
	}
	result, err := s.caseRef.Query(ctx, spec.Query)
	if err != nil {
		return Selection{}, err
	}
	id, err := newSelectionID()
	if err != nil {
		return Selection{}, err
	}
	aid, err := newActivityID()
	if err != nil {
		return Selection{}, err
	}
	fp, qjson, err := digestJSON(spec.Query)
	if err != nil {
		return Selection{}, err
	}
	selection := Selection{ID: id, Name: spec.Name, Revision: result.Revision, Query: spec.Query, Members: append([]EntityRef(nil), result.Entities...)}
	_, err = s.caseRef.mutate(ctx, s.info.Agent.ID, s.ID(), "selection.freeze", fp, []string{string(id)}, func(tx *sql.Tx, rev int64) error {
		if spec.IdempotencyKey != "" {
			var old Selection
			ok, e := lookupIdempotency(ctx, tx, string(s.ID()), "selection.freeze", spec.IdempotencyKey, fp, &old)
			if e != nil {
				return e
			}
			if ok {
				selection = old
				return nil
			}
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		out, _ := canonicalJSON(OutcomeSucceeded())
		if _, e := tx.ExecContext(ctx, "INSERT INTO activities(id,session_id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?)", aid, s.ID(), s.info.Agent.ID, ActivitySelectionFreeze, "Freeze selection: "+spec.Name, string(qjson), fp, CaptureLibrary, ActivitySucceeded, rev, now, now, string(out)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", id, EntitySelection, aid, rev, now, spec.Name); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO selections(id,name,observed_revision,query_json,query_digest) VALUES(?,?,?,?,?)", id, spec.Name, result.Revision, string(qjson), fp); e != nil {
			return e
		}
		for i, m := range result.Entities {
			if _, e := tx.ExecContext(ctx, "INSERT INTO selection_members(selection_id,ordinal,entity_id,kind) VALUES(?,?,?,?)", id, i, m.ID, m.Kind); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'member')", aid, m.ID); e != nil {
				return e
			}
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'selection')", aid, id); e != nil {
			return e
		}
		selection.CreatedRevision = rev
		return storeIdempotency(ctx, tx, string(s.ID()), "selection.freeze", spec.IdempotencyKey, fp, selection)
	})
	return selection, err
}

func (c *Case) Selection(ctx context.Context, id SelectionID) (Selection, error) {
	var s Selection
	var qj string
	err := c.db.QueryRowContext(ctx, "SELECT s.id,s.name,s.observed_revision,s.query_json,e.created_revision FROM selections s JOIN entities e ON e.id=s.id WHERE s.id=?", id).Scan(&s.ID, &s.Name, &s.Revision, &qj, &s.CreatedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	if err != nil {
		return s, mapSQLError(err)
	}
	if json.Unmarshal([]byte(qj), &s.Query) != nil {
		return s, ErrIntegrity
	}
	rows, err := c.db.QueryContext(ctx, "SELECT entity_id,kind FROM selection_members WHERE selection_id=? ORDER BY ordinal", id)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var e EntityRef
		if err = rows.Scan(&e.ID, &e.Kind); err != nil {
			return s, err
		}
		s.Members = append(s.Members, e)
	}
	return s, rows.Err()
}
