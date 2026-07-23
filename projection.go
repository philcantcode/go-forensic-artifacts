package forensic

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

type projectionMember struct {
	Ref    EntityRef
	Reason string
}

func (s *Session) CreateProjection(ctx context.Context, spec ProjectionSpec) (Projection, error) {
	if err := s.checkOpen(); err != nil {
		return Projection{}, err
	}
	if spec.Selection == "" {
		return Projection{}, fmt.Errorf("%w: selection required", ErrInvalid)
	}
	if spec.Closure == "" {
		spec.Closure = ClosureExact
	}
	if spec.Layout == "" {
		spec.Layout = LayoutByID
	}
	if spec.Include == 0 {
		spec.Include = IncludeBytes | IncludeMetadata
	}
	if spec.MaxFiles <= 0 {
		spec.MaxFiles = 100000
	}
	if spec.MaxBytes <= 0 {
		spec.MaxBytes = 1 << 40
	}
	if spec.MaxFiles > 1000000 || spec.MaxBytes > 1<<50 {
		return Projection{}, fmt.Errorf("%w: projection resource limit is too large", ErrInvalid)
	}
	selection, err := s.caseRef.Selection(ctx, spec.Selection)
	if err != nil {
		return Projection{}, err
	}
	members, err := s.caseRef.resolveClosure(ctx, selection, spec.Closure)
	if err != nil {
		return Projection{}, err
	}
	allowedKinds := map[EntityKind]bool{}
	for _, kind := range spec.Kinds {
		if kind == "" {
			return Projection{}, fmt.Errorf("%w: empty projection entity kind", ErrInvalid)
		}
		allowedKinds[kind] = true
	}
	explicitExclusions := map[string]ProjectionExclusion{}
	for _, exclusion := range spec.Exclusions {
		if exclusion.Entity.ID == "" || strings.TrimSpace(exclusion.Reason) == "" || explicitExclusions[exclusion.Entity.ID].Entity.ID != "" {
			return Projection{}, fmt.Errorf("%w: projection exclusions require unique entity IDs and reasons", ErrInvalid)
		}
		explicitExclusions[exclusion.Entity.ID] = exclusion
	}
	var included []projectionMember
	var excluded []ProjectionExclusion
	foundExplicit := map[string]bool{}
	for _, member := range members {
		if exclusion, ok := explicitExclusions[member.Ref.ID]; ok {
			exclusion.Entity = member.Ref
			excluded = append(excluded, exclusion)
			foundExplicit[member.Ref.ID] = true
			continue
		}
		if len(allowedKinds) != 0 && !allowedKinds[member.Ref.Kind] {
			excluded = append(excluded, ProjectionExclusion{Entity: member.Ref, Reason: "entity kind excluded by projection filter"})
			continue
		}
		included = append(included, member)
	}
	for id := range explicitExclusions {
		if !foundExplicit[id] {
			return Projection{}, fmt.Errorf("%w: excluded entity %s is not in resolved closure", ErrInvalid, id)
		}
	}
	members = included
	id, err := newProjectionID()
	if err != nil {
		return Projection{}, err
	}
	aid, err := newActivityID()
	if err != nil {
		return Projection{}, err
	}
	fp, sjson, err := digestJSON(spec)
	if err != nil {
		return Projection{}, err
	}
	outMembers := make([]EntityRef, len(members))
	for i := range members {
		outMembers[i] = members[i].Ref
	}
	p := Projection{ID: id, Spec: spec, Members: outMembers, Excluded: excluded, Digest: fp}
	_, err = s.caseRef.mutate(ctx, s.info.Agent.ID, s.ID(), "projection.create", fp, []string{string(id)}, func(tx *sql.Tx, rev int64) error {
		if spec.IdempotencyKey != "" {
			var old Projection
			ok, e := lookupIdempotency(ctx, tx, string(s.ID()), "projection.create", spec.IdempotencyKey, fp, &old)
			if e != nil {
				return e
			}
			if ok {
				p = old
				return errIdempotentReplay
			}
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		out, _ := canonicalJSON(OutcomeSucceeded())
		if _, e := tx.ExecContext(ctx, "INSERT INTO activities(id,session_id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?)", aid, s.ID(), s.info.Agent.ID, ActivityProjectionCreate, "Create projection", string(sjson), fp, CaptureLibrary, ActivitySucceeded, rev, now, now, string(out)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,'projection')", id, EntityProjection, aid, rev, now); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO projections(id,selection_id,spec_json,spec_digest) VALUES(?,?,?,?)", id, spec.Selection, string(sjson), fp); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'selection')", aid, spec.Selection); e != nil {
			return e
		}
		for i, m := range members {
			if _, e := tx.ExecContext(ctx, "INSERT INTO projection_members(projection_id,ordinal,entity_id,kind,reason) VALUES(?,?,?,?,?)", id, i, m.Ref.ID, m.Ref.Kind, m.Reason); e != nil {
				return e
			}
		}
		for i, exclusion := range excluded {
			if _, e := tx.ExecContext(ctx, "INSERT INTO projection_exclusions(projection_id,ordinal,entity_id,kind,reason) VALUES(?,?,?,?,?)", id, i, exclusion.Entity.ID, exclusion.Entity.Kind, exclusion.Reason); e != nil {
				return e
			}
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'projection')", aid, id); e != nil {
			return e
		}
		p.CreatedRevision = rev
		return storeIdempotency(ctx, tx, string(s.ID()), "projection.create", spec.IdempotencyKey, fp, p)
	})
	return p, err
}

func (c *Case) resolveClosure(ctx context.Context, s Selection, policy ClosurePolicy) ([]projectionMember, error) {
	seen := map[string]projectionMember{}
	queue := make([]EntityRef, 0, len(s.Members))
	for _, m := range s.Members {
		seen[m.ID] = projectionMember{m, "selected"}
		queue = append(queue, m)
	}
	if policy == ClosureExact {
		return sortedProjectionMembers(seen), nil
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.Kind == EntitySourceTree {
			rows, err := c.db.QueryContext(ctx, `SELECT e.id,e.kind,member.role FROM (SELECT manifest_object_id AS id,'manifest' AS role,-1 AS ordinal FROM source_trees WHERE id=? UNION ALL SELECT object_id AS id,'file' AS role,ordinal FROM tree_entries WHERE tree_id=? AND object_id IS NOT NULL) member JOIN entities e ON e.id=member.id ORDER BY member.ordinal`, cur.ID, cur.ID)
			if err != nil {
				return nil, err
			}
			var added []EntityRef
			for rows.Next() {
				var entity EntityRef
				var role string
				if err = rows.Scan(&entity.ID, &entity.Kind, &role); err != nil {
					rows.Close()
					return nil, err
				}
				if _, ok := seen[entity.ID]; ok {
					continue
				}
				reason := "tree-" + role + ":" + cur.ID
				switch policy {
				case ClosureSources:
					reason = "source-metadata:" + cur.ID
				case ClosureFindingContext:
					reason = "finding-context:" + cur.ID
				}
				seen[entity.ID] = projectionMember{entity, reason}
				added = append(added, entity)
			}
			if err = rows.Err(); err != nil {
				rows.Close()
				return nil, err
			}
			if err = rows.Close(); err != nil {
				return nil, err
			}
			if policy == ClosureSources || policy == ClosureFullProvenance || policy == ClosureFindingContext {
				queue = append(queue, added...)
			}
		}
		var rows *sql.Rows
		var err error
		switch policy {
		case ClosureInputBytes:
			rows, err = c.db.QueryContext(ctx, `SELECT e.id,e.kind FROM entities e JOIN activity_inputs i ON i.entity_id=e.id JOIN entities out ON out.generating_activity_id=i.activity_id WHERE out.id=? AND e.kind IN (?,?)`, cur.ID, EntityObject, EntityManifest)
		case ClosureSources, ClosureFullProvenance:
			rows, err = c.db.QueryContext(ctx, `SELECT e.id,e.kind FROM entities out JOIN activity_inputs i ON i.activity_id=out.generating_activity_id JOIN entities e ON e.id=i.entity_id WHERE out.id=?`, cur.ID)
		case ClosureFindingContext:
			if cur.Kind == EntityFindingRevision {
				rows, err = c.db.QueryContext(ctx, `SELECT e.id,e.kind FROM finding_members m JOIN entities e ON e.id=m.entity_id WHERE m.revision_id=?`, cur.ID)
			} else {
				rows, err = c.db.QueryContext(ctx, `SELECT e.id,e.kind FROM entities out JOIN activity_inputs i ON i.activity_id=out.generating_activity_id JOIN entities e ON e.id=i.entity_id WHERE out.id=? AND e.kind IN (?,?)`, cur.ID, EntityObject, EntityArtifact)
			}
		default:
			return nil, fmt.Errorf("%w: unsupported closure", ErrInvalid)
		}
		if err != nil {
			return nil, err
		}
		var added []EntityRef
		for rows.Next() {
			var e EntityRef
			if err = rows.Scan(&e.ID, &e.Kind); err != nil {
				rows.Close()
				return nil, err
			}
			if _, ok := seen[e.ID]; !ok {
				reason := "provenance:" + cur.ID
				switch policy {
				case ClosureSources:
					reason = "source-metadata:" + cur.ID
				case ClosureInputBytes:
					reason = "input-byte:" + cur.ID
				case ClosureFindingContext:
					reason = "finding-context:" + cur.ID
				}
				seen[e.ID] = projectionMember{e, reason}
				added = append(added, e)
			}
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
		if policy == ClosureSources || policy == ClosureFullProvenance || policy == ClosureFindingContext {
			queue = append(queue, added...)
		}
	}
	return sortedProjectionMembers(seen), nil
}

func sortedProjectionMembers(m map[string]projectionMember) []projectionMember {
	out := make([]projectionMember, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ref.Kind == out[j].Ref.Kind {
			return out[i].Ref.ID < out[j].Ref.ID
		}
		return out[i].Ref.Kind < out[j].Ref.Kind
	})
	return out
}

func (c *Case) Projection(ctx context.Context, id ProjectionID) (Projection, error) {
	var p Projection
	var sj string
	err := c.db.QueryRowContext(ctx, "SELECT p.id,p.spec_json,p.spec_digest,e.created_revision FROM projections p JOIN entities e ON e.id=p.id WHERE p.id=?", id).Scan(&p.ID, &sj, &p.Digest, &p.CreatedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, mapSQLError(err)
	}
	if json.Unmarshal([]byte(sj), &p.Spec) != nil {
		return p, ErrIntegrity
	}
	rows, err := c.db.QueryContext(ctx, "SELECT entity_id,kind FROM projection_members WHERE projection_id=? ORDER BY ordinal", id)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var e EntityRef
		if err = rows.Scan(&e.ID, &e.Kind); err != nil {
			return p, err
		}
		p.Members = append(p.Members, e)
	}
	if err = rows.Err(); err != nil {
		return p, err
	}
	if err = rows.Close(); err != nil {
		return p, err
	}
	excludedRows, err := c.db.QueryContext(ctx, "SELECT entity_id,kind,reason FROM projection_exclusions WHERE projection_id=? ORDER BY ordinal", id)
	if err != nil {
		return p, err
	}
	defer excludedRows.Close()
	for excludedRows.Next() {
		var exclusion ProjectionExclusion
		if err = excludedRows.Scan(&exclusion.Entity.ID, &exclusion.Entity.Kind, &exclusion.Reason); err != nil {
			return p, err
		}
		p.Excluded = append(p.Excluded, exclusion)
	}
	return p, excludedRows.Err()
}

func (s *Session) Materialize(ctx context.Context, id ProjectionID, target DirectoryTarget) (Materialization, error) {
	if err := s.checkOpen(); err != nil {
		return Materialization{}, err
	}
	p, err := s.caseRef.Projection(ctx, id)
	if err != nil {
		return Materialization{}, err
	}
	if p.Spec.MaxFiles <= 0 {
		p.Spec.MaxFiles = 100000
	}
	if p.Spec.MaxBytes <= 0 {
		p.Spec.MaxBytes = 1 << 40
	}
	selection, err := s.caseRef.Selection(ctx, p.Spec.Selection)
	if err != nil {
		return Materialization{}, err
	}
	mid, err := newMaterializationID()
	if err != nil {
		return Materialization{}, err
	}
	if target.Path == "" {
		target.Path = filepath.Join(s.caseRef.repo.root, "workspaces", string(s.caseRef.id), string(mid))
	}
	dest, err := filepath.Abs(target.Path)
	if err != nil {
		return Materialization{}, err
	}
	inside, err := pathWithin(s.caseRef.root, dest)
	if err != nil {
		return Materialization{}, err
	}
	if inside {
		return Materialization{}, fmt.Errorf("%w: materialization cannot be inside the authoritative case", ErrInvalid)
	}
	if _, err = os.Lstat(dest); err == nil {
		return Materialization{}, fmt.Errorf("%w: destination already exists", ErrConflict)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Materialization{}, err
	}
	if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return Materialization{}, err
	}
	partial := dest + ".partial-" + string(mid)
	if err = os.Mkdir(partial, 0700); err != nil {
		return Materialization{}, err
	}
	if err = s.caseRef.injectFault("after-projection-create"); err != nil {
		return Materialization{}, err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(partial)
		}
	}()
	manifest := ProjectionManifest{Format: 1, Case: s.caseRef.id, Projection: id, Selection: p.Spec.Selection, Revision: selection.Revision, SpecDigest: p.Digest}
	used := map[string]bool{}
	emittedFiles := 0
	var total int64
	emittedFindings := map[FindingRevisionID]bool{}
	rows, err := s.caseRef.db.QueryContext(ctx, "SELECT entity_id,kind,reason FROM projection_members WHERE projection_id=? ORDER BY ordinal", id)
	if err != nil {
		return Materialization{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var entity EntityRef
		var reason string
		if err = rows.Scan(&entity.ID, &entity.Kind, &reason); err != nil {
			return Materialization{}, err
		}
		var obj ObjectRef
		obj, err = s.caseRef.objectByEntity(ctx, entity.ID)
		if errors.Is(err, ErrNotFound) {
			if p.Spec.Include&IncludeMetadata != 0 {
				var file ManifestFile
				if file, err = writeEntitySidecar(ctx, s.caseRef, partial, entity); err != nil {
					return Materialization{}, err
				}
				if err = addProjectionSupportFile(&manifest, file, &emittedFiles, &total, p.Spec); err != nil {
					return Materialization{}, err
				}
			}
			if p.Spec.Include&IncludeProvenance != 0 {
				file, writeErr := writeProvenanceSidecar(ctx, s.caseRef, partial, entity)
				if writeErr != nil {
					return Materialization{}, writeErr
				}
				if err = addProjectionSupportFile(&manifest, file, &emittedFiles, &total, p.Spec); err != nil {
					return Materialization{}, err
				}
			}
			if p.Spec.Include&IncludeFindings != 0 {
				files, writeErr := writeFindingSidecars(ctx, s.caseRef, partial, entity, emittedFindings)
				if writeErr != nil {
					return Materialization{}, writeErr
				}
				for _, file := range files {
					if err = addProjectionSupportFile(&manifest, file, &emittedFiles, &total, p.Spec); err != nil {
						return Materialization{}, err
					}
				}
			}
			continue
		}
		if err != nil {
			return Materialization{}, err
		}
		if p.Spec.Include&IncludeMetadata != 0 {
			var file ManifestFile
			if file, err = writeEntitySidecar(ctx, s.caseRef, partial, entity); err != nil {
				return Materialization{}, err
			}
			if err = addProjectionSupportFile(&manifest, file, &emittedFiles, &total, p.Spec); err != nil {
				return Materialization{}, err
			}
		}
		if p.Spec.Include&IncludeProvenance != 0 {
			file, writeErr := writeProvenanceSidecar(ctx, s.caseRef, partial, entity)
			if writeErr != nil {
				return Materialization{}, writeErr
			}
			if err = addProjectionSupportFile(&manifest, file, &emittedFiles, &total, p.Spec); err != nil {
				return Materialization{}, err
			}
		}
		if p.Spec.Include&IncludeFindings != 0 {
			files, writeErr := writeFindingSidecars(ctx, s.caseRef, partial, entity, emittedFindings)
			if writeErr != nil {
				return Materialization{}, writeErr
			}
			for _, file := range files {
				if err = addProjectionSupportFile(&manifest, file, &emittedFiles, &total, p.Spec); err != nil {
					return Materialization{}, err
				}
			}
		}
		if p.Spec.Include&IncludeBytes == 0 || (p.Spec.Closure == ClosureSources && strings.HasPrefix(reason, "source-metadata:")) {
			continue
		}
		if emittedFiles >= p.Spec.MaxFiles {
			return Materialization{}, fmt.Errorf("%w: projection file limit exceeded", ErrInvalid)
		}
		if obj.Size < 0 || obj.Size > p.Spec.MaxBytes-total {
			return Materialization{}, fmt.Errorf("%w: projection size limit exceeded", ErrInvalid)
		}
		total += obj.Size
		evidenceID := ""
		if p.Spec.Layout == LayoutByEvidencePath {
			evidenceID, err = s.caseRef.evidenceForEntity(ctx, entity.ID)
			if err != nil {
				return Materialization{}, err
			}
		}
		logical := projectionPath(p.Spec.Layout, entity, obj, evidenceID)
		if len(logical) > 4096 {
			return Materialization{}, fmt.Errorf("%w: projected path is too long", ErrInvalid)
		}
		if used[strings.ToLower(logical)] {
			logical = addIDCollision(logical, entity.ID)
		}
		used[strings.ToLower(logical)] = true
		full := filepath.Join(partial, filepath.FromSlash(logical))
		if ok, _ := pathWithin(partial, full); !ok {
			return Materialization{}, fmt.Errorf("%w: unsafe projected path", ErrInvalid)
		}
		if err = os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			return Materialization{}, err
		}
		if err = copyFileContext(ctx, s.caseRef.blobPath(obj.Blob), full); err != nil {
			return Materialization{}, err
		}
		if err = s.caseRef.injectFault("after-projection-copy"); err != nil {
			return Materialization{}, err
		}
		manifest.Entries = append(manifest.Entries, ManifestEntry{Entity: entity, Blob: obj.Blob, Size: obj.Size, Path: logical, SHA256: strings.TrimPrefix(string(obj.Blob), "sha256:"), Reason: reason})
		emittedFiles++
	}
	if err = rows.Err(); err != nil {
		return Materialization{}, err
	}
	if target.Writable {
		if err = os.MkdirAll(filepath.Join(partial, "output"), 0700); err != nil {
			return Materialization{}, err
		}
	}
	manifestPath := filepath.Join(partial, "projection-manifest.json")
	if err = writeJSONAtomic(manifestPath, manifest); err != nil {
		return Materialization{}, err
	}
	if err = s.caseRef.injectFault("after-projection-manifest"); err != nil {
		return Materialization{}, err
	}
	if !target.Writable {
		if err = filepath.WalkDir(partial, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.Type().IsRegular() {
				return os.Chmod(path, 0400)
			}
			return os.Chmod(path, 0500)
		}); err != nil {
			return Materialization{}, err
		}
	}
	if err = renameWithRetry(ctx, partial, dest); err != nil {
		return Materialization{}, err
	}
	published = true
	if err = s.caseRef.injectFault("after-projection-publish"); err != nil {
		return Materialization{}, err
	}
	_ = syncDirectory(filepath.Dir(dest))
	mf, err := os.Open(filepath.Join(dest, "projection-manifest.json"))
	if err != nil {
		return Materialization{}, err
	}
	staged, err := s.caseRef.stageBlob(ctx, mf)
	_ = mf.Close()
	if err != nil {
		return Materialization{}, err
	}
	if err = s.caseRef.publishBlob(ctx, staged); err != nil {
		return Materialization{}, err
	}
	aid, err := newActivityID()
	if err != nil {
		return Materialization{}, err
	}
	oid, err := newObjectID()
	if err != nil {
		return Materialization{}, err
	}
	fp, cfg, err := digestJSON(struct {
		Projection ProjectionID
		Target     DirectoryTarget
		Manifest   string
	}{id, target, string(staged.ref)})
	if err != nil {
		return Materialization{}, err
	}
	result := Materialization{ID: mid, Projection: id, Destination: dest, Manifest: ObjectRef{ID: oid, Blob: staged.ref, Size: staged.size, DisplayName: "projection-manifest.json", MediaType: "application/json", GeneratingActivity: aid}}
	_, err = s.caseRef.mutate(ctx, s.info.Agent.ID, s.ID(), "projection.materialize", fp, []string{string(mid), string(oid)}, func(tx *sql.Tx, rev int64) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		out, _ := canonicalJSON(OutcomeSucceeded())
		if _, e := tx.ExecContext(ctx, "INSERT INTO activities(id,session_id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?)", aid, s.ID(), s.info.Agent.ID, ActivityProjectionMaterialize, "Materialize projection", string(cfg), fp, CaptureLibrary, ActivitySucceeded, rev, now, now, string(out)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'projection')", aid, id); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO blobs(digest,size,created_at) VALUES(?,?,?)", staged.ref, staged.size, now); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,media_type,display_name) VALUES(?,?,?,?,?,?,?)", oid, EntityManifest, aid, rev, now, "application/json", "projection-manifest.json"); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO objects(id,blob_digest,size,role,path_display) VALUES(?,?,?,?,?)", oid, staged.ref, staged.size, "manifest", "projection-manifest.json"); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'manifest')", aid, oid); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO materializations(id,projection_id,destination,manifest_object_id,created_revision,created_at) VALUES(?,?,?,?,?,?)", mid, id, dest, oid, rev, now); e != nil {
			return e
		}
		result.CreatedRevision = rev
		result.Manifest.CreatedRevision = rev
		return nil
	})
	return result, err
}

func (c *Case) objectByEntity(ctx context.Context, id string) (ObjectRef, error) {
	var o ObjectRef
	err := c.db.QueryRowContext(ctx, "SELECT o.id,o.blob_digest,o.size,e.display_name,e.media_type,o.path_display,e.generating_activity_id,e.created_revision FROM objects o JOIN entities e ON e.id=o.id WHERE o.id=?", id).Scan(&o.ID, &o.Blob, &o.Size, &o.DisplayName, &o.MediaType, &o.Path, &o.GeneratingActivity, &o.CreatedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return o, ErrNotFound
	}
	return o, mapSQLError(err)
}

func projectionPath(layout Layout, e EntityRef, o ObjectRef, evidenceID string) string {
	name := sanitizeComponent(o.DisplayName)
	if name == "_" && o.Path != "" {
		parts := strings.Split(strings.ReplaceAll(o.Path, "\\", "/"), "/")
		name = sanitizeComponent(parts[len(parts)-1])
	}
	switch layout {
	case LayoutFlat:
		return "data/flat/" + name + "~" + shortID(e.ID)
	case LayoutByEvidencePath:
		path := sanitizeLogicalPath(o.Path)
		if path == "" {
			path = name
		}
		if evidenceID == "" {
			evidenceID = "unassigned"
		}
		return "data/by-evidence/" + sanitizeComponent(evidenceID) + "/" + path
	default:
		return "data/by-id/" + sanitizeComponent(string(e.Kind)) + "/" + sanitizeComponent(e.ID) + "/" + name
	}
}

func (c *Case) evidenceForEntity(ctx context.Context, id string) (string, error) {
	var evidence string
	err := c.db.QueryRowContext(ctx, `WITH RECURSIVE ancestors(id) AS (SELECT ? UNION SELECT i.entity_id FROM ancestors a JOIN entities out ON out.id=a.id JOIN activity_inputs i ON i.activity_id=out.generating_activity_id) SELECT eo.evidence_id FROM evidence_objects eo JOIN ancestors a ON a.id=eo.object_id ORDER BY eo.evidence_id LIMIT 1`, id).Scan(&evidence)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return evidence, mapSQLError(err)
}
func addIDCollision(path, id string) string {
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + "~" + shortID(id) + ext
}
func shortID(id string) string {
	if len(id) > 10 {
		return id[len(id)-10:]
	}
	return id
}

func sanitizeLogicalPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	var out []string
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			continue
		}
		out = append(out, sanitizeComponent(part))
	}
	return strings.Join(out, "/")
}
func sanitizeComponent(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r < 32 || strings.ContainsRune(`<>:"/\\|?*`, r) || unicode.IsControl(r) {
			b.WriteByte('_')
		} else {
			b.WriteRune(r)
		}
	}
	s = strings.Trim(b.String(), " .")
	if s == "" || s == "." || s == ".." {
		s = "_"
	}
	base := strings.ToUpper(strings.TrimSuffix(s, filepath.Ext(s)))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		s = "_" + s
	}
	if len([]rune(s)) > 180 {
		s = string([]rune(s)[:180])
	}
	return s
}

func pathWithin(root, path string) (bool, error) {
	r, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(r, p)
	if err != nil {
		return false, err
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)), nil
}
func copyFileContext(ctx context.Context, src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(dst)
		}
	}()
	if _, err = io.Copy(out, &contextReader{ctx: ctx, r: in}); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func renameWithRetry(ctx context.Context, oldPath, newPath string) error {
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		if err = os.Rename(oldPath, newPath); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 10 * time.Millisecond):
		}
	}
	return err
}
func writeEntitySidecar(ctx context.Context, c *Case, root string, e EntityRef) (ManifestFile, error) {
	dir := filepath.Join(root, "metadata")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ManifestFile{}, err
	}
	record, err := c.entityExportRecord(ctx, e)
	if err != nil {
		return ManifestFile{}, err
	}
	rel := filepath.ToSlash(filepath.Join("metadata", sanitizeComponent(e.ID)+".json"))
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := writeJSONAtomic(path, record); err != nil {
		return ManifestFile{}, err
	}
	digest, size, err := digestFile(ctx, path)
	if err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{Path: rel, SHA256: digest, Size: size, Role: "metadata"}, nil
}

func writeProvenanceSidecar(ctx context.Context, c *Case, root string, entity EntityRef) (ManifestFile, error) {
	graph, err := c.Trace(ctx, entity)
	if err != nil {
		return ManifestFile{}, err
	}
	rel := filepath.ToSlash(filepath.Join("provenance", sanitizeComponent(entity.ID)+".json"))
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return ManifestFile{}, err
	}
	if err = writeJSONAtomic(path, graph); err != nil {
		return ManifestFile{}, err
	}
	digest, size, err := digestFile(ctx, path)
	return ManifestFile{Path: rel, SHA256: digest, Size: size, Role: "provenance"}, err
}

func writeFindingSidecars(ctx context.Context, c *Case, root string, entity EntityRef, emitted map[FindingRevisionID]bool) ([]ManifestFile, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT DISTINCT fr.id FROM finding_revisions fr LEFT JOIN finding_members fm ON fm.revision_id=fr.id WHERE fr.id=? OR fm.entity_id=? ORDER BY fr.id`, entity.ID, entity.ID)
	if err != nil {
		return nil, mapSQLError(err)
	}
	var ids []FindingRevisionID
	for rows.Next() {
		var id FindingRevisionID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		if !emitted[id] {
			ids = append(ids, id)
		}
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	var files []ManifestFile
	for _, id := range ids {
		finding, loadErr := c.FindingRevision(ctx, id)
		if loadErr != nil {
			return nil, loadErr
		}
		rel := filepath.ToSlash(filepath.Join("findings", sanitizeComponent(string(id))+".json"))
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		if err = writeJSONAtomic(path, finding); err != nil {
			return nil, err
		}
		digest, size, digestErr := digestFile(ctx, path)
		if digestErr != nil {
			return nil, digestErr
		}
		files = append(files, ManifestFile{Path: rel, SHA256: digest, Size: size, Role: "finding"})
		emitted[id] = true
	}
	return files, nil
}

func addProjectionSupportFile(manifest *ProjectionManifest, file ManifestFile, count *int, total *int64, spec ProjectionSpec) error {
	if *count >= spec.MaxFiles {
		return fmt.Errorf("%w: projection file limit exceeded", ErrInvalid)
	}
	if file.Size < 0 || file.Size > spec.MaxBytes-*total {
		return fmt.Errorf("%w: projection size limit exceeded", ErrInvalid)
	}
	manifest.Files = append(manifest.Files, file)
	*count++
	*total += file.Size
	return nil
}

func (c *Case) Materialization(ctx context.Context, id MaterializationID) (Materialization, error) {
	var m Materialization
	err := c.db.QueryRowContext(ctx, "SELECT id,projection_id,destination,manifest_object_id,created_revision FROM materializations WHERE id=?", id).Scan(&m.ID, &m.Projection, &m.Destination, &m.Manifest.ID, &m.CreatedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrNotFound
	}
	if err != nil {
		return m, mapSQLError(err)
	}
	m.Manifest, err = c.Object(ctx, m.Manifest.ID)
	return m, err
}
