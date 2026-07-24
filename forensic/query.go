package forensic

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

type entityView struct {
	ref           EntityRef
	activity      ActivityID
	session       SessionID
	path          string
	hash          BlobRef
	artifactType  string
	schema        string
	mediaType     string
	size          int64
	agent         AgentID
	toolName      string
	toolVersion   string
	created       int64
	assertionType string
	values        map[string][]string
	times         map[string][]TemporalValue
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
	case QueryAll, QueryKind, QueryID, QueryPathGlob, QueryHash, QueryActivity, QuerySession, QueryArtifactType, QueryValue, QuerySelection, QueryTree, QueryTimeRange, QuerySchema, QueryMediaType, QueryExtension, QuerySizeRange, QueryAgent, QueryTool, QueryEvidence, QueryFinding, QueryDescendant, QueryRevision, QueryAssertionType:
		if len(q.Children) != 0 {
			return fmt.Errorf("%w: leaf query has children", ErrInvalid)
		}
		if q.Op == QueryTimeRange {
			start, startErr := time.Parse(time.RFC3339Nano, q.Start)
			end, endErr := time.Parse(time.RFC3339Nano, q.End)
			if q.Property == "" || startErr != nil || endErr != nil || end.Before(start) {
				return fmt.Errorf("%w: invalid time range", ErrInvalid)
			}
		}
		if (q.Op == QuerySizeRange || q.Op == QueryRevision) && (q.Min < 0 || q.Max < q.Min) {
			return fmt.Errorf("%w: invalid numeric query range", ErrInvalid)
		}
		switch q.Op {
		case QueryKind, QueryID, QueryPathGlob, QueryHash, QueryActivity, QuerySession, QueryArtifactType, QuerySelection, QueryTree, QuerySchema, QueryMediaType, QueryExtension, QueryAgent, QueryTool, QueryEvidence, QueryFinding, QueryDescendant, QueryAssertionType:
			if strings.TrimSpace(q.Value) == "" {
				return fmt.Errorf("%w: query value required", ErrInvalid)
			}
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

// QueryPage evaluates a typed query in deterministic entity-kind/ID order.
// Pass the returned Revision and Next cursor into the following request to
// keep a traversal pinned while concurrent writers extend the case.
func (c *Case) QueryPage(ctx context.Context, spec QueryPageSpec) (QueryPageResult, error) {
	if err := c.checkOpen(); err != nil {
		return QueryPageResult{}, err
	}
	depth, nodes := 0, 0
	if err := validateQuery(spec.Query, &depth, &nodes); err != nil {
		return QueryPageResult{}, err
	}
	if spec.Limit <= 0 {
		spec.Limit = 1000
	}
	if spec.Limit > 10000 {
		return QueryPageResult{}, fmt.Errorf("%w: query page limit is too large", ErrInvalid)
	}
	if (spec.After.ID == "") != (spec.After.Kind == "") {
		return QueryPageResult{}, fmt.Errorf("%w: query cursor requires kind and ID", ErrInvalid)
	}
	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return QueryPageResult{}, mapSQLError(err)
	}
	defer tx.Rollback()
	var current int64
	if err = tx.QueryRowContext(ctx, "SELECT revision FROM case_info WHERE singleton=1").Scan(&current); err != nil {
		return QueryPageResult{}, mapSQLError(err)
	}
	if spec.Revision == 0 {
		spec.Revision = current
	}
	if spec.Revision < 1 || spec.Revision > current {
		return QueryPageResult{}, fmt.Errorf("%w: query revision is unavailable", ErrInvalid)
	}
	result := QueryPageResult{Revision: spec.Revision}
	after := spec.After
	membershipCache := map[string]map[string]bool{}
	const candidateBatch = 512
	for len(result.Entities) < spec.Limit {
		views, loadErr := loadEntityViewsPage(ctx, tx, spec.Revision, after, candidateBatch)
		if loadErr != nil {
			return QueryPageResult{}, loadErr
		}
		if len(views) == 0 {
			break
		}
		for _, view := range views {
			after = view.ref
			matched, matchErr := matchQuery(ctx, tx, spec.Query, view, membershipCache)
			if matchErr != nil {
				return QueryPageResult{}, matchErr
			}
			if matched {
				result.Entities = append(result.Entities, view.ref)
				if len(result.Entities) == spec.Limit {
					result.Next = after
					break
				}
			}
		}
		if result.Next.ID != "" || len(views) < candidateBatch {
			break
		}
	}
	if err = tx.Commit(); err != nil {
		return QueryPageResult{}, mapSQLError(err)
	}
	return result, nil
}

func loadEntityViews(ctx context.Context, tx *sql.Tx, rev int64) ([]entityView, error) {
	return loadEntityViewsPage(ctx, tx, rev, EntityRef{}, 0)
}

func loadEntityViewsPage(ctx context.Context, tx *sql.Tx, rev int64, after EntityRef, limit int) ([]entityView, error) {
	query := `SELECT e.id,e.kind,e.generating_activity_id,COALESCE(a.session_id,''),COALESCE(o.path_display,''),COALESCE(o.blob_digest,''),COALESCE(ar.artifact_type,''),e.schema_uri,e.media_type,COALESCE(o.size,-1),a.agent_id,COALESCE(a.tool_json,''),e.created_revision,COALESCE(asn.assertion_type,'') FROM entities e JOIN activities a ON a.id=e.generating_activity_id LEFT JOIN objects o ON o.id=e.id LEFT JOIN artifacts ar ON ar.id=e.id LEFT JOIN assertions asn ON asn.id=e.id WHERE e.created_revision<=?`
	args := []any{rev}
	if after.ID != "" {
		query += " AND (e.kind>? OR (e.kind=? AND e.id>?))"
		args = append(args, after.Kind, after.Kind, after.ID)
	}
	query += " ORDER BY e.kind,e.id"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var views []entityView
	index := map[string]int{}
	for rows.Next() {
		var v entityView
		var toolJSON string
		if err = rows.Scan(&v.ref.ID, &v.ref.Kind, &v.activity, &v.session, &v.path, &v.hash, &v.artifactType, &v.schema, &v.mediaType, &v.size, &v.agent, &toolJSON, &v.created, &v.assertionType); err != nil {
			return nil, err
		}
		if toolJSON != "" && toolJSON != "null" {
			var tool ToolDescriptor
			if json.Unmarshal([]byte(toolJSON), &tool) != nil {
				return nil, ErrIntegrity
			}
			v.toolName, v.toolVersion = tool.Name, tool.Version
		}
		v.values = map[string][]string{}
		v.times = map[string][]TemporalValue{}
		index[v.ref.ID] = len(views)
		views = append(views, v)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	artifactIDs := make([]string, 0, len(views))
	for i := range views {
		if views[i].ref.Kind == EntityArtifact {
			artifactIDs = append(artifactIDs, views[i].ref.ID)
		}
	}
	if len(artifactIDs) == 0 {
		return views, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(artifactIDs)), ",")
	valueArgs := make([]any, len(artifactIDs))
	for i := range artifactIDs {
		valueArgs[i] = artifactIDs[i]
	}
	vr, err := tx.QueryContext(ctx, `SELECT artifact_id,property,raw,COALESCE(normalized_json,'') FROM artifact_values WHERE artifact_id IN (`+placeholders+`)`, valueArgs...)
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
	if err = vr.Err(); err != nil {
		return nil, err
	}
	tr, err := tx.QueryContext(ctx, `SELECT tv.artifact_id,av.property,tv.temporal_json FROM temporal_values tv JOIN artifact_values av ON av.artifact_id=tv.artifact_id AND av.ordinal=tv.value_ordinal WHERE tv.artifact_id IN (`+placeholders+`)`, valueArgs...)
	if err != nil {
		return nil, err
	}
	defer tr.Close()
	for tr.Next() {
		var id, property, body string
		if err = tr.Scan(&id, &property, &body); err != nil {
			return nil, err
		}
		if i, ok := index[id]; ok {
			var temporal TemporalValue
			if json.Unmarshal([]byte(body), &temporal) != nil {
				return nil, ErrIntegrity
			}
			views[i].times[property] = append(views[i].times[property], temporal)
		}
	}
	return views, tr.Err()
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
	case QuerySchema:
		return v.schema == q.Value, nil
	case QueryMediaType:
		return strings.EqualFold(v.mediaType, q.Value), nil
	case QueryExtension:
		extension := q.Value
		if !strings.HasPrefix(extension, ".") {
			extension = "." + extension
		}
		return strings.EqualFold(path.Ext(strings.ReplaceAll(v.path, "\\", "/")), extension), nil
	case QuerySizeRange:
		return v.size >= q.Min && v.size <= q.Max, nil
	case QueryAgent:
		return string(v.agent) == q.Value, nil
	case QueryTool:
		return v.toolName == q.Value && (q.Role == "" || v.toolVersion == q.Role), nil
	case QueryRevision:
		return v.created >= q.Min && v.created <= q.Max, nil
	case QueryAssertionType:
		return v.assertionType == q.Value, nil
	case QueryValue:
		for _, x := range v.values[q.Property] {
			if x == q.Value {
				return true, nil
			}
		}
		return false, nil
	case QueryTimeRange:
		start, _ := time.Parse(time.RFC3339Nano, q.Start)
		end, _ := time.Parse(time.RFC3339Nano, q.End)
		for _, temporal := range v.times[q.Property] {
			if temporal.UTCStart == nil || temporal.UTCEnd == nil || (q.Role != "" && temporal.SemanticRole != q.Role) {
				continue
			}
			if !temporal.UTCEnd.Before(start) && !temporal.UTCStart.After(end) {
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
	case QueryEvidence:
		cacheKey := "evidence:" + q.Value
		members, ok := cache[cacheKey]
		if !ok {
			members = map[string]bool{}
			rows, err := tx.QueryContext(ctx, `WITH RECURSIVE related(id) AS (SELECT ? UNION SELECT object_id FROM evidence_objects WHERE evidence_id=? UNION SELECT ao.entity_id FROM related r JOIN activity_inputs ai ON ai.entity_id=r.id JOIN activity_outputs ao ON ao.activity_id=ai.activity_id) SELECT id FROM related`, q.Value, q.Value)
			if err != nil {
				return false, err
			}
			for rows.Next() {
				var id string
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return false, err
				}
				members[id] = true
			}
			if err = rows.Close(); err != nil {
				return false, err
			}
			cache[cacheKey] = members
		}
		return members[v.ref.ID], nil
	case QueryFinding:
		cacheKey := "finding:" + q.Value
		members, ok := cache[cacheKey]
		if !ok {
			members = map[string]bool{}
			rows, err := tx.QueryContext(ctx, `SELECT id FROM finding_revisions WHERE finding_id=? UNION SELECT fm.entity_id FROM finding_members fm JOIN finding_revisions fr ON fr.id=fm.revision_id WHERE fr.finding_id=?`, q.Value, q.Value)
			if err != nil {
				return false, err
			}
			for rows.Next() {
				var id string
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return false, err
				}
				members[id] = true
			}
			if err = rows.Close(); err != nil {
				return false, err
			}
			cache[cacheKey] = members
		}
		return members[v.ref.ID], nil
	case QueryDescendant:
		cacheKey := "descendant:" + q.Value
		members, ok := cache[cacheKey]
		if !ok {
			members = map[string]bool{}
			rows, err := tx.QueryContext(ctx, `WITH RECURSIVE descendants(id) AS (SELECT ? UNION SELECT ao.entity_id FROM descendants d JOIN activity_inputs ai ON ai.entity_id=d.id JOIN activity_outputs ao ON ao.activity_id=ai.activity_id) SELECT id FROM descendants`, q.Value)
			if err != nil {
				return false, err
			}
			for rows.Next() {
				var id string
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return false, err
				}
				members[id] = true
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
				return errIdempotentReplay
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
