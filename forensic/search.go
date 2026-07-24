package forensic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

func (c *Case) SearchText(ctx context.Context, literal string, limit int) ([]TextSearchHit, error) {
	if strings.TrimSpace(literal) == "" {
		return nil, fmt.Errorf("%w: search text is required", ErrInvalid)
	}
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		return nil, fmt.Errorf("%w: search limit is too large", ErrInvalid)
	}
	term := `"` + strings.ReplaceAll(literal, `"`, `""`) + `"`
	rows, err := c.db.QueryContext(ctx, "SELECT artifact_id,property,text FROM artifact_fts WHERE artifact_fts MATCH ? ORDER BY artifact_id,property,text LIMIT ?", term, limit)
	if err != nil {
		return nil, mapSQLError(err)
	}
	defer rows.Close()
	var hits []TextSearchHit
	for rows.Next() {
		var h TextSearchHit
		if err = rows.Scan(&h.Artifact, &h.Property, &h.Text); err != nil {
			return nil, err
		}
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

const byteSearchChunk = 64 << 10
const byteSearchRegexpWindow = 1 << 20

func (c *Case) SearchBytes(ctx context.Context, spec ByteSearchSpec) ([]ByteSearchHit, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if len(spec.Literal) == 0 && spec.Regexp == "" {
		return nil, fmt.Errorf("%w: literal or regexp is required", ErrInvalid)
	}
	if len(spec.Literal) > byteSearchRegexpWindow {
		return nil, fmt.Errorf("%w: literal is too large", ErrInvalid)
	}
	if spec.ContextBytes < 0 || spec.ContextBytes > 4096 {
		return nil, fmt.Errorf("%w: invalid context size", ErrInvalid)
	}
	if spec.Limit <= 0 {
		spec.Limit = 1000
	}
	if spec.Limit > 100000 {
		return nil, fmt.Errorf("%w: byte search limit is too large", ErrInvalid)
	}
	if len(spec.Regexp) > 64<<10 {
		return nil, fmt.Errorf("%w: byte search regexp is too large", ErrInvalid)
	}
	var re *regexp.Regexp
	var err error
	if spec.Regexp != "" {
		re, err = regexp.Compile(spec.Regexp)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	selection, err := c.Selection(ctx, spec.Selection)
	if err != nil {
		return nil, err
	}
	var hits []ByteSearchHit
	for _, entity := range selection.Members {
		if entity.Kind != EntityObject && entity.Kind != EntityManifest {
			continue
		}
		obj, err := c.objectByEntity(ctx, entity.ID)
		if err != nil {
			return nil, err
		}
		reader, err := c.OpenObject(ctx, obj.ID)
		if err != nil {
			return nil, err
		}
		for base := int64(0); base < obj.Size && len(hits) < spec.Limit; base += byteSearchChunk {
			if err = ctx.Err(); err != nil {
				closeReader(reader)
				return nil, err
			}
			before := int64(spec.ContextBytes)
			if before > base {
				before = base
			}
			lookahead := len(spec.Literal) - 1
			if re != nil {
				lookahead = byteSearchRegexpWindow
			}
			readStart := base - before
			readEnd := base + byteSearchChunk + int64(lookahead+spec.ContextBytes)
			if readEnd > obj.Size {
				readEnd = obj.Size
			}
			buf := make([]byte, int(readEnd-readStart))
			n, readErr := reader.ReadAt(buf, readStart)
			buf = buf[:n]
			if readErr != nil && readErr != io.EOF {
				closeReader(reader)
				return nil, readErr
			}
			var matches [][]int
			if re != nil {
				matches = re.FindAllIndex(buf, spec.Limit-len(hits))
			} else {
				for off := 0; len(matches) < spec.Limit-len(hits); {
					i := bytes.Index(buf[off:], spec.Literal)
					if i < 0 {
						break
					}
					start := off + i
					matches = append(matches, []int{start, start + len(spec.Literal)})
					off = start + max(1, len(spec.Literal))
				}
			}
			for _, m := range matches {
				absolute := readStart + int64(m[0])
				if absolute < base || absolute >= base+byteSearchChunk {
					continue
				}
				lo := max(0, m[0]-spec.ContextBytes)
				hi := min(len(buf), m[1]+spec.ContextBytes)
				contextBytes := append([]byte(nil), buf[lo:hi]...)
				contextDigest := sha256.Sum256(contextBytes)
				hits = append(hits, ByteSearchHit{Object: obj.ID, Offset: absolute, Length: m[1] - m[0], Context: contextBytes, ContextSHA256: hex.EncodeToString(contextDigest[:])})
				if len(hits) >= spec.Limit {
					break
				}
			}
		}
		closeReader(reader)
		if len(hits) >= spec.Limit {
			break
		}
	}
	return hits, nil
}

// SearchMetadata performs bounded literal or Go-RE2 regular-expression
// matching over authoritative catalog text. It never passes a regular
// expression to SQLite and reports candidate/result truncation explicitly.
func (c *Case) SearchMetadata(ctx context.Context, spec MetadataSearchSpec) (MetadataSearchResult, error) {
	if err := c.checkOpen(); err != nil {
		return MetadataSearchResult{}, err
	}
	if (spec.Literal == "") == (spec.Regexp == "") {
		return MetadataSearchResult{}, fmt.Errorf("%w: specify exactly one literal or regexp", ErrInvalid)
	}
	if len(spec.Literal) > 1<<20 || len(spec.Regexp) > 64<<10 {
		return MetadataSearchResult{}, fmt.Errorf("%w: metadata search expression is too large", ErrInvalid)
	}
	if spec.CandidateLimit <= 0 {
		spec.CandidateLimit = 100000
	}
	if spec.CandidateLimit > 1000000 {
		return MetadataSearchResult{}, fmt.Errorf("%w: metadata candidate limit is too large", ErrInvalid)
	}
	if spec.Limit <= 0 {
		spec.Limit = 1000
	}
	if spec.Limit > 10000 {
		return MetadataSearchResult{}, fmt.Errorf("%w: metadata result limit is too large", ErrInvalid)
	}
	if spec.MaxResultBytes <= 0 {
		spec.MaxResultBytes = 1 << 20
	}
	if spec.MaxResultBytes > 16<<20 {
		return MetadataSearchResult{}, fmt.Errorf("%w: metadata result byte limit is too large", ErrInvalid)
	}
	var re *regexp.Regexp
	var err error
	if spec.Regexp != "" {
		pattern := spec.Regexp
		if !spec.CaseSensitive {
			pattern = "(?i)" + pattern
		}
		re, err = regexp.Compile(pattern)
		if err != nil {
			return MetadataSearchResult{}, fmt.Errorf("%w: invalid metadata regexp: %v", ErrInvalid, err)
		}
	}
	allowedFields := map[MetadataField]bool{}
	if len(spec.Fields) == 0 {
		for _, field := range []MetadataField{MetadataDisplayName, MetadataMediaType, MetadataPath, MetadataValueRaw, MetadataValueNorm, MetadataFinding, MetadataAssertion} {
			allowedFields[field] = true
		}
	} else {
		for _, field := range spec.Fields {
			switch field {
			case MetadataDisplayName, MetadataMediaType, MetadataPath, MetadataValueRaw, MetadataValueNorm, MetadataFinding, MetadataAssertion:
				allowedFields[field] = true
			default:
				return MetadataSearchResult{}, fmt.Errorf("%w: unknown metadata field %q", ErrInvalid, field)
			}
		}
	}
	selected := map[string]bool(nil)
	if spec.Selection != "" {
		selection, loadErr := c.Selection(ctx, spec.Selection)
		if loadErr != nil {
			return MetadataSearchResult{}, loadErr
		}
		selected = make(map[string]bool, len(selection.Members))
		for _, entity := range selection.Members {
			selected[entity.ID] = true
		}
	}
	rows, err := c.db.QueryContext(ctx, `
SELECT entity_id,kind,field,property,value,locator_type,locator_json FROM (
 SELECT e.id AS entity_id,e.kind AS kind,'display_name' AS field,'' AS property,e.display_name AS value,'' AS locator_type,'' AS locator_json FROM entities e WHERE e.display_name<>''
 UNION ALL SELECT e.id,e.kind,'media_type','',e.media_type,'','' FROM entities e WHERE e.media_type<>''
 UNION ALL SELECT e.id,e.kind,'path','',o.path_display,'','' FROM objects o JOIN entities e ON e.id=o.id WHERE o.path_display<>''
 UNION ALL SELECT e.id,e.kind,'value.raw',av.property,av.raw,COALESCE(av.locator_type,''),COALESCE(av.locator_json,'') FROM artifact_values av JOIN entities e ON e.id=av.artifact_id WHERE av.raw<>''
 UNION ALL SELECT e.id,e.kind,'value.normalized',av.property,av.normalized_json,COALESCE(av.locator_type,''),COALESCE(av.locator_json,'') FROM artifact_values av JOIN entities e ON e.id=av.artifact_id WHERE av.normalized_json IS NOT NULL AND av.normalized_json<>''
 UNION ALL SELECT e.id,e.kind,'finding','title',f.title,'','' FROM finding_revisions fr JOIN findings f ON f.id=fr.finding_id JOIN entities e ON e.id=fr.id WHERE f.title<>''
 UNION ALL SELECT e.id,e.kind,'finding','body',fr.body,'','' FROM finding_revisions fr JOIN entities e ON e.id=fr.id WHERE fr.body<>''
 UNION ALL SELECT e.id,e.kind,'assertion','body',a.body,'','' FROM assertions a JOIN entities e ON e.id=a.id WHERE a.body<>''
) ORDER BY entity_id,field,property,value LIMIT ?`, spec.CandidateLimit+1)
	if err != nil {
		return MetadataSearchResult{}, mapSQLError(err)
	}
	defer rows.Close()
	var result MetadataSearchResult
	resultBytes := 0
	for rows.Next() {
		if result.CandidatesScanned >= spec.CandidateLimit {
			result.Truncated = true
			break
		}
		var entity EntityRef
		var field MetadataField
		var property, value, locatorType, locatorJSON string
		if err = rows.Scan(&entity.ID, &entity.Kind, &field, &property, &value, &locatorType, &locatorJSON); err != nil {
			return MetadataSearchResult{}, err
		}
		result.CandidatesScanned++
		if !allowedFields[field] || (selected != nil && !selected[entity.ID]) {
			continue
		}
		matched := false
		if re != nil {
			matched = re.MatchString(value)
		} else if spec.CaseSensitive {
			matched = strings.Contains(value, spec.Literal)
		} else {
			matched = strings.Contains(strings.ToLower(value), strings.ToLower(spec.Literal))
		}
		if !matched {
			continue
		}
		if len(result.Hits) >= spec.Limit || resultBytes+len(value) > spec.MaxResultBytes {
			result.Truncated = true
			break
		}
		result.Hits = append(result.Hits, MetadataSearchHit{Entity: entity, Field: field, Property: property, Value: value, Source: decodeLocator(locatorType, locatorJSON)})
		resultBytes += len(value)
	}
	if err = rows.Err(); err != nil {
		return MetadataSearchResult{}, err
	}
	sort.Slice(result.Hits, func(i, j int) bool {
		a, b := result.Hits[i], result.Hits[j]
		if a.Entity.ID != b.Entity.ID {
			return a.Entity.ID < b.Entity.ID
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		if a.Property != b.Property {
			return a.Property < b.Property
		}
		return a.Value < b.Value
	})
	return result, nil
}

// SaveByteSearch runs a byte search and commits its exact hits plus a frozen
// selection in one catalog transaction. The search activity uses the source
// selection and every matched object, making saved results reproducible and
// traceable to bytes.
func (s *Session) SaveByteSearch(ctx context.Context, spec SavedByteSearchSpec) (SavedSearch, error) {
	if err := s.checkOpen(); err != nil {
		return SavedSearch{}, err
	}
	if strings.TrimSpace(spec.Name) == "" {
		return SavedSearch{}, fmt.Errorf("%w: saved search name required", ErrInvalid)
	}
	sourceSelection, err := s.caseRef.Selection(ctx, spec.Search.Selection)
	if err != nil {
		return SavedSearch{}, err
	}
	hits, err := s.caseRef.SearchBytes(ctx, spec.Search)
	if err != nil {
		return SavedSearch{}, err
	}
	type hitFingerprint struct {
		Object, ContextSHA256 string
		Offset                int64
		Length                int
	}
	fingerprintHits := make([]hitFingerprint, len(hits))
	for i, hit := range hits {
		fingerprintHits[i] = hitFingerprint{string(hit.Object), hit.ContextSHA256, hit.Offset, hit.Length}
	}
	fingerprint, configJSON, err := digestJSON(struct {
		Name     string
		Search   ByteSearchSpec
		Revision int64
		Hits     []hitFingerprint
	}{spec.Name, spec.Search, sourceSelection.Revision, fingerprintHits})
	if err != nil {
		return SavedSearch{}, err
	}
	activityID, err := newActivityID()
	if err != nil {
		return SavedSearch{}, err
	}
	selectionID, err := newSelectionID()
	if err != nil {
		return SavedSearch{}, err
	}
	artifacts := make([]ArtifactRef, len(hits))
	for i, hit := range hits {
		id, idErr := newArtifactID()
		if idErr != nil {
			return SavedSearch{}, idErr
		}
		artifacts[i] = ArtifactRef{
			ID: id, Type: "urn:forensic:artifact:byte-search-hit/v1", DisplayName: fmt.Sprintf("%s hit %d", spec.Name, i+1),
			Source: hit.Object, GeneratingActivity: activityID,
			Values: []ArtifactValue{
				{Property: "offset", Type: ValueInteger, Raw: fmt.Sprint(hit.Offset), Normalized: hit.Offset, Source: ExtentLocator{Parent: hit.Object, Offset: hit.Offset, Length: int64(hit.Length)}},
				{Property: "length", Type: ValueInteger, Raw: fmt.Sprint(hit.Length), Normalized: hit.Length},
				{Property: "context_sha256", Type: ValueString, Raw: hit.ContextSHA256, Normalized: hit.ContextSHA256},
			},
		}
	}
	query := IDIs("__no_saved_search_hits__")
	if len(artifacts) == 1 {
		query = IDIs(string(artifacts[0].ID))
	} else if len(artifacts) > 1 {
		children := make([]Query, len(artifacts))
		for i := range artifacts {
			children[i] = IDIs(string(artifacts[i].ID))
		}
		query = Or(children...)
	}
	queryDigest, queryJSON, err := digestJSON(query)
	if err != nil {
		return SavedSearch{}, err
	}
	result := SavedSearch{Activity: activityID, Hits: artifacts, Selection: Selection{ID: selectionID, Name: spec.Name, Revision: 0, Query: query}}
	affected := []string{string(activityID), string(selectionID)}
	_, err = s.caseRef.mutate(ctx, s.info.Agent.ID, s.ID(), "search.save", fingerprint, affected, func(tx *sql.Tx, revision int64) error {
		if spec.IdempotencyKey != "" {
			var old SavedSearch
			found, lookupErr := lookupIdempotency(ctx, tx, string(s.ID()), "search.save", spec.IdempotencyKey, fingerprint, &old)
			if lookupErr != nil {
				return lookupErr
			}
			if found {
				result = old
				return errIdempotentReplay
			}
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		outcomeJSON, _ := canonicalJSON(OutcomeSucceeded())
		if _, execErr := tx.ExecContext(ctx, `INSERT INTO activities(id,session_id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)`, activityID, s.ID(), s.info.Agent.ID, ActivitySearch, "Save byte search: "+spec.Name, string(configJSON), fingerprint, CaptureLibrary, ActivitySucceeded, revision, now, now, string(outcomeJSON), spec.IdempotencyKey); execErr != nil {
			return execErr
		}
		if _, execErr := tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'source-selection')", activityID, spec.Search.Selection); execErr != nil {
			return execErr
		}
		usedObjects := map[ObjectID]bool{}
		for _, hit := range hits {
			if usedObjects[hit.Object] {
				continue
			}
			usedObjects[hit.Object] = true
			if _, execErr := tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'searched-object')", activityID, hit.Object); execErr != nil {
				return execErr
			}
		}
		for i := range artifacts {
			artifact := &artifacts[i]
			hit := hits[i]
			producerKey := fmt.Sprintf("%s:%d:%d:%s", hit.Object, hit.Offset, hit.Length, hit.ContextSHA256)
			draft := ArtifactDraft{Type: artifact.Type, DisplayName: artifact.DisplayName, Source: artifact.Source, Values: artifact.Values}
			producerFingerprint, fingerprintErr := artifactDraftFingerprint(draft)
			if fingerprintErr != nil {
				return fingerprintErr
			}
			if _, execErr := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,schema_uri,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?,?)", artifact.ID, EntityArtifact, artifact.Type, activityID, revision, now, artifact.DisplayName); execErr != nil {
				return execErr
			}
			if _, execErr := tx.ExecContext(ctx, "INSERT INTO artifacts(id,artifact_type,source_object_id,producer_key,producer_fingerprint,generating_activity_id) VALUES(?,?,?,?,?,?)", artifact.ID, artifact.Type, artifact.Source, producerKey, producerFingerprint, activityID); execErr != nil {
				return execErr
			}
			for ordinal, value := range artifact.Values {
				normalized, locatorType, locatorJSON, encodeErr := encodeArtifactValue(value)
				if encodeErr != nil {
					return encodeErr
				}
				if _, execErr := tx.ExecContext(ctx, "INSERT INTO artifact_values(artifact_id,ordinal,property,schema_uri,value_type,raw,normalized_json,unit,encoding,language,confidence,interpretation,locator_type,locator_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", artifact.ID, ordinal, value.Property, value.SchemaURI, value.Type, value.Raw, normalized, value.Unit, value.Encoding, value.Language, nil, value.Interpretation, nullString(locatorType), nullString(locatorJSON)); execErr != nil {
					return execErr
				}
				if _, execErr := tx.ExecContext(ctx, "INSERT INTO artifact_fts(artifact_id,property,text) VALUES(?,?,?)", artifact.ID, value.Property, value.Raw); execErr != nil {
					return execErr
				}
			}
			if _, execErr := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'search-hit')", activityID, artifact.ID); execErr != nil {
				return execErr
			}
			artifact.CreatedRevision = revision
		}
		if _, execErr := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", selectionID, EntitySelection, activityID, revision, now, spec.Name); execErr != nil {
			return execErr
		}
		if _, execErr := tx.ExecContext(ctx, "INSERT INTO selections(id,name,observed_revision,query_json,query_digest) VALUES(?,?,?,?,?)", selectionID, spec.Name, revision, string(queryJSON), queryDigest); execErr != nil {
			return execErr
		}
		for i, artifact := range artifacts {
			if _, execErr := tx.ExecContext(ctx, "INSERT INTO selection_members(selection_id,ordinal,entity_id,kind) VALUES(?,?,?,?)", selectionID, i, artifact.ID, EntityArtifact); execErr != nil {
				return execErr
			}
		}
		if _, execErr := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'hit-selection')", activityID, selectionID); execErr != nil {
			return execErr
		}
		result.Hits = artifacts
		result.Selection.Revision = revision
		result.Selection.Members = make([]EntityRef, len(artifacts))
		result.Selection.CreatedRevision = revision
		result.CreatedRevision = revision
		for i, artifact := range artifacts {
			result.Selection.Members[i] = artifact.EntityRef()
		}
		return storeIdempotency(ctx, tx, string(s.ID()), "search.save", spec.IdempotencyKey, fingerprint, result)
	})
	return result, err
}

func closeReader(r ObjectReader) {
	if c, ok := r.(io.Closer); ok {
		_ = c.Close()
	}
}
