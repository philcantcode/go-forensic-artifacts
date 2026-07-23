package forensic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (c *Case) Verify(ctx context.Context, spec VerifySpec) (VerifyReport, error) {
	if err := c.checkOpen(); err != nil {
		return VerifyReport{}, err
	}
	if spec.Mode == "" {
		spec.Mode = VerifyQuick
	}
	info, err := c.Info(ctx)
	if err != nil {
		return VerifyReport{}, err
	}
	report := VerifyReport{Mode: spec.Mode, Case: c.id, Revision: info.Revision, OK: true}
	if spec.Mode == VerifyProjection {
		return c.verifyProjection(ctx, spec.Materialization, report)
	}
	var integrity string
	if err = c.db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return report, mapSQLError(err)
	}
	if integrity != "ok" {
		report.Issues = append(report.Issues, VerifyIssue{Code: "catalog-integrity", Detail: integrity})
	}
	rows, err := c.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return report, err
	}
	for rows.Next() {
		var table, parent string
		var rowid, fkid any
		if err = rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			rows.Close()
			return report, err
		}
		report.Issues = append(report.Issues, VerifyIssue{Code: "foreign-key", Detail: fmt.Sprintf("%s row %v", table, rowid)})
	}
	rows.Close()
	if err = c.verifyDomainInvariants(ctx, &report); err != nil {
		return report, err
	}
	if err = c.verifyAcquisitionHashes(ctx, &report); err != nil {
		return report, err
	}
	if err = c.verifyAudit(ctx, &report); err != nil {
		return report, err
	}
	_ = filepath.WalkDir(filepath.Join(c.root, "checkpoints"), func(path string, d os.DirEntry, e error) error {
		if e != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "checkpoint-read", Path: path, Detail: e.Error()})
			return nil
		}
		if !d.Type().IsRegular() || filepath.Ext(path) != ".json" {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "checkpoint-read", Path: path, Detail: e.Error()})
			return nil
		}
		var cp Checkpoint
		if json.Unmarshal(b, &cp) != nil || cp.Inventory.Case != c.id {
			report.Issues = append(report.Issues, VerifyIssue{Code: "checkpoint-syntax", Path: path, Detail: "invalid checkpoint"})
			return nil
		}
		if e = VerifyCheckpoint(cp); e != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "checkpoint-signature", Path: path, Detail: e.Error()})
		}
		return nil
	})
	query := "SELECT DISTINCT b.digest,b.size FROM blobs b JOIN objects o ON o.blob_digest=b.digest"
	if spec.Mode == VerifyOriginals {
		query = "SELECT DISTINCT b.digest,b.size FROM blobs b JOIN objects o ON o.blob_digest=b.digest JOIN evidence_objects eo ON eo.object_id=o.id"
	}
	br, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return report, err
	}
	referenced := map[string]bool{}
	for br.Next() {
		var ref BlobRef
		var size int64
		if err = br.Scan(&ref, &size); err != nil {
			br.Close()
			return report, err
		}
		referenced[string(ref)] = true
		path := c.blobPath(ref)
		st, e := os.Stat(path)
		if e != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "missing-blob", Path: path, Detail: e.Error()})
			continue
		}
		if st.Size() != size {
			report.Issues = append(report.Issues, VerifyIssue{Code: "blob-size", Path: path, Detail: fmt.Sprintf("got %d, want %d", st.Size(), size)})
		}
		if spec.Mode == VerifyFull || spec.Mode == VerifyOriginals {
			report.CheckedBlobs++
			if e = verifyBlobFile(ctx, path, ref, size); e != nil {
				report.Issues = append(report.Issues, VerifyIssue{Code: "blob-digest", Path: path, Detail: e.Error()})
			}
		}
	}
	if err = br.Close(); err != nil {
		return report, err
	}
	if spec.Mode == VerifyFull {
		if err = c.verifySourceTreeManifests(ctx, &report); err != nil {
			return report, err
		}
		base := filepath.Join(c.root, "blobs", "sha256")
		_ = filepath.WalkDir(base, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				report.Issues = append(report.Issues, VerifyIssue{Code: "blob-walk", Path: path, Detail: e.Error()})
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			name := filepath.Base(path)
			if len(name) == 64 && !referenced["sha256:"+name] {
				report.Issues = append(report.Issues, VerifyIssue{Code: "orphan-blob", Path: path, Detail: "managed bytes have no catalog reference"})
			}
			return nil
		})
	}
	report.OK = len(report.Issues) == 0
	return report, nil
}

func (c *Case) verifyDomainInvariants(ctx context.Context, report *VerifyReport) error {
	type invariantQuery struct {
		code   string
		detail string
		query  string
	}
	queries := []invariantQuery{
		{"missing-generation-edge", "entity has no output edge from its generating activity", `SELECT e.id,e.kind FROM entities e LEFT JOIN activity_outputs ao ON ao.entity_id=e.id AND ao.activity_id=e.generating_activity_id WHERE ao.entity_id IS NULL ORDER BY e.id`},
		{"generation-mismatch", "output edge does not match entity generating activity", `SELECT e.id,e.kind FROM entities e JOIN activity_outputs ao ON ao.entity_id=e.id WHERE ao.activity_id<>e.generating_activity_id ORDER BY e.id`},
		{"object-blob-size", "object size does not match its blob record", `SELECT e.id,e.kind FROM objects o JOIN entities e ON e.id=o.id JOIN blobs b ON b.digest=o.blob_digest WHERE o.size<>b.size ORDER BY e.id`},
		{"artifact-source-lineage", "artifact source is not an input to its parser activity", `SELECT e.id,e.kind FROM artifacts a JOIN entities e ON e.id=a.id LEFT JOIN activity_inputs ai ON ai.activity_id=a.generating_activity_id AND ai.entity_id=a.source_object_id WHERE ai.entity_id IS NULL ORDER BY e.id`},
		{"artifact-activity", "artifact and entity disagree about their generating activity", `SELECT e.id,e.kind FROM artifacts a JOIN entities e ON e.id=a.id WHERE a.generating_activity_id<>e.generating_activity_id ORDER BY e.id`},
		{"future-input", "activity input was created after an output of that activity", `SELECT DISTINCT input.id,input.kind FROM activity_inputs ai JOIN entities input ON input.id=ai.entity_id JOIN activity_outputs ao ON ao.activity_id=ai.activity_id JOIN entities output ON output.id=ao.entity_id WHERE input.created_revision>output.created_revision ORDER BY input.id`},
		{"evidence-without-object", "evidence has no associated original object", `SELECT e.id,e.kind FROM evidence ev JOIN entities e ON e.id=ev.id LEFT JOIN evidence_objects eo ON eo.evidence_id=ev.id WHERE eo.evidence_id IS NULL ORDER BY e.id`},
		{"evidence-root-count", "evidence must have exactly one root object", `SELECT e.id,e.kind FROM evidence ev JOIN entities e ON e.id=ev.id LEFT JOIN evidence_objects eo ON eo.evidence_id=ev.id AND eo.role='root' GROUP BY e.id,e.kind HAVING COUNT(eo.object_id)<>1 ORDER BY e.id`},
		{"finding-current", "finding current revision is missing or belongs to another finding", `SELECT e.id,e.kind FROM finding_revisions fr JOIN entities e ON e.id=fr.id JOIN findings f ON f.id=fr.finding_id LEFT JOIN finding_revisions current ON current.id=f.current_revision_id AND current.finding_id=f.id WHERE current.id IS NULL ORDER BY e.id`},
		{"tree-entry-object", "source-tree entry kind/object/blob relationship is inconsistent", `SELECT st.id,e.kind FROM tree_entries te JOIN source_trees st ON st.id=te.tree_id JOIN entities e ON e.id=st.id LEFT JOIN objects o ON o.id=te.object_id WHERE (te.entry_kind='file' AND (te.object_id IS NULL OR te.blob_digest IS NULL OR o.blob_digest<>te.blob_digest OR o.size<>te.size)) OR (te.entry_kind<>'file' AND (te.object_id IS NOT NULL OR te.blob_digest IS NOT NULL)) ORDER BY st.id`},
		{"tree-evidence-root", "source-tree manifest is not the evidence root object", `SELECT e.id,e.kind FROM source_trees st JOIN entities e ON e.id=st.id LEFT JOIN evidence_objects eo ON eo.evidence_id=st.evidence_id AND eo.object_id=st.manifest_object_id AND eo.role='root' WHERE eo.evidence_id IS NULL ORDER BY e.id`},
		{"deliverable-member-blob", "deliverable member blob does not match its object", `SELECT e.id,e.kind FROM deliverable_members dm JOIN entities e ON e.id=dm.entity_id LEFT JOIN objects o ON o.id=dm.entity_id WHERE dm.blob_digest IS NOT NULL AND (o.id IS NULL OR o.blob_digest<>dm.blob_digest) ORDER BY e.id`},
		{"assertion-target-kind", "assertion target kind differs from the authoritative entity kind", `SELECT e.id,e.kind FROM assertion_targets t JOIN entities e ON e.id=t.target_id WHERE t.target_kind<>e.kind ORDER BY e.id`},
		{"selection-member-kind", "selection member kind differs from the authoritative entity kind", `SELECT e.id,e.kind FROM selection_members m JOIN entities e ON e.id=m.entity_id WHERE m.kind<>e.kind ORDER BY e.id`},
		{"projection-member-kind", "projection member kind differs from the authoritative entity kind", `SELECT e.id,e.kind FROM projection_members m JOIN entities e ON e.id=m.entity_id WHERE m.kind<>e.kind ORDER BY e.id`},
		{"projection-exclusion-kind", "projection exclusion kind differs from the authoritative entity kind", `SELECT e.id,e.kind FROM projection_exclusions m JOIN entities e ON e.id=m.entity_id WHERE m.kind<>e.kind ORDER BY e.id`},
		{"deliverable-member-kind", "deliverable member kind differs from the authoritative entity kind", `SELECT e.id,e.kind FROM deliverable_members m JOIN entities e ON e.id=m.entity_id WHERE m.kind<>e.kind ORDER BY e.id`},
		{"parser-cache-output", "parser cache output was not generated by the cached source activity", `SELECT e.id,e.kind FROM parser_cache_outputs pco JOIN parser_cache pc ON pc.cache_key=pco.cache_key JOIN entities e ON e.id=pco.entity_id WHERE e.generating_activity_id<>pc.source_activity_id ORDER BY e.id`},
		{"entity-revision", "entity creation revision is absent from revision history", `SELECT e.id,e.kind FROM entities e LEFT JOIN revisions r ON r.revision=e.created_revision WHERE r.revision IS NULL ORDER BY e.id`},
	}
	for _, check := range queries {
		rows, err := c.db.QueryContext(ctx, check.query)
		if err != nil {
			return mapSQLError(err)
		}
		for rows.Next() {
			var entity EntityRef
			if err = rows.Scan(&entity.ID, &entity.Kind); err != nil {
				rows.Close()
				return err
			}
			report.Issues = append(report.Issues, VerifyIssue{Code: check.code, Entity: entity, Detail: check.detail})
		}
		if err = rows.Close(); err != nil {
			return err
		}
	}
	treeRows, err := c.db.QueryContext(ctx, `SELECT st.id,st.tree_digest,o.blob_digest,st.file_count,st.total_bytes,st.entry_count,COUNT(te.ordinal),COALESCE(SUM(CASE WHEN te.entry_kind='file' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN te.entry_kind='file' THEN te.size ELSE 0 END),0) FROM source_trees st JOIN objects o ON o.id=st.manifest_object_id LEFT JOIN tree_entries te ON te.tree_id=st.id GROUP BY st.id ORDER BY st.id`)
	if err != nil {
		return mapSQLError(err)
	}
	for treeRows.Next() {
		var id string
		var treeDigest, manifestDigest string
		var files, bytes, entries, actualEntries, actualFiles, actualBytes int64
		if err = treeRows.Scan(&id, &treeDigest, &manifestDigest, &files, &bytes, &entries, &actualEntries, &actualFiles, &actualBytes); err != nil {
			treeRows.Close()
			return err
		}
		if treeDigest != manifestDigest || files != actualFiles || bytes != actualBytes || entries != actualEntries {
			report.Issues = append(report.Issues, VerifyIssue{Code: "source-tree-summary", Entity: EntityRef{ID: id, Kind: EntitySourceTree}, Detail: "tree digest or entry/file/byte counts do not match canonical members"})
		}
	}
	if err = treeRows.Close(); err != nil {
		return err
	}
	temporalRows, err := c.db.QueryContext(ctx, "SELECT tv.artifact_id,tv.value_ordinal,tv.temporal_json,COALESCE(tv.utc_start,''),COALESCE(tv.utc_end,''),tv.semantic_role FROM temporal_values tv ORDER BY tv.artifact_id,tv.value_ordinal")
	if err != nil {
		return mapSQLError(err)
	}
	for temporalRows.Next() {
		var artifact string
		var ordinal int
		var body, start, end, role string
		if err = temporalRows.Scan(&artifact, &ordinal, &body, &start, &end, &role); err != nil {
			temporalRows.Close()
			return err
		}
		var temporal TemporalValue
		if json.Unmarshal([]byte(body), &temporal) != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "temporal-json", Entity: EntityRef{ID: artifact, Kind: EntityArtifact}, Detail: fmt.Sprintf("invalid temporal value %d", ordinal)})
			continue
		}
		normalized, normalizeErr := normalizeTemporalValue(temporal)
		wantStart, wantEnd := "", ""
		if normalized.UTCStart != nil {
			wantStart = normalized.UTCStart.Format(time.RFC3339Nano)
		}
		if normalized.UTCEnd != nil {
			wantEnd = normalized.UTCEnd.Format(time.RFC3339Nano)
		}
		if normalizeErr != nil || start != wantStart || end != wantEnd || role != normalized.SemanticRole {
			report.Issues = append(report.Issues, VerifyIssue{Code: "temporal-index", Entity: EntityRef{ID: artifact, Kind: EntityArtifact}, Detail: fmt.Sprintf("temporal value %d and range index differ", ordinal)})
		}
	}
	return temporalRows.Close()
}

func (c *Case) verifyAcquisitionHashes(ctx context.Context, report *VerifyReport) error {
	rows, err := c.db.QueryContext(ctx, `SELECT ev.id,ev.acquisition_json,o.blob_digest FROM evidence ev JOIN evidence_objects eo ON eo.evidence_id=ev.id AND eo.role='root' JOIN objects o ON o.id=eo.object_id ORDER BY ev.id`)
	if err != nil {
		return mapSQLError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, body, blob string
		if err = rows.Scan(&id, &body, &blob); err != nil {
			return err
		}
		var acquisition AcquisitionSpec
		if json.Unmarshal([]byte(body), &acquisition) != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "acquisition-json", Entity: EntityRef{ID: id, Kind: EntityEvidence}, Detail: "invalid acquisition metadata"})
			continue
		}
		if supplied := strings.ToLower(strings.TrimSpace(acquisition.SuppliedHashes["sha256"])); supplied != "" && supplied != strings.TrimPrefix(blob, "sha256:") {
			report.Issues = append(report.Issues, VerifyIssue{Code: "supplied-hash", Entity: EntityRef{ID: id, Kind: EntityEvidence}, Detail: "supplied SHA-256 differs from managed root object"})
		}
	}
	return rows.Err()
}

func (c *Case) verifySourceTreeManifests(ctx context.Context, report *VerifyReport) error {
	rows, err := c.db.QueryContext(ctx, "SELECT id FROM source_trees ORDER BY id")
	if err != nil {
		return mapSQLError(err)
	}
	var ids []TreeID
	for rows.Next() {
		var id TreeID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		tree, loadErr := c.SourceTree(ctx, id)
		if loadErr != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "source-tree-load", Entity: EntityRef{ID: string(id), Kind: EntitySourceTree}, Detail: loadErr.Error()})
			continue
		}
		reader, openErr := c.OpenObject(ctx, tree.Manifest.ID)
		if openErr != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "source-tree-manifest", Entity: tree.EntityRef(), Detail: openErr.Error()})
			continue
		}
		body, readErr := io.ReadAll(io.NewSectionReader(reader, 0, reader.Size()))
		closeReader(reader)
		if readErr != nil {
			return readErr
		}
		expected := sourceTreeManifest{Format: sourceTreeManifestFormat, Entries: make([]sourceTreeEntry, len(tree.Entries))}
		for i, entry := range tree.Entries {
			expected.Entries[i] = sourceTreeEntry{Path: entry.Path, RawPath: entry.RawPath, Encoding: entry.Encoding, Separator: entry.Separator, Kind: entry.Kind, Mode: entry.Mode, Size: entry.Size, SHA256: entry.SHA256, LinkTarget: entry.LinkTarget}
		}
		expectedBody, canonicalErr := canonicalJSON(expected)
		if canonicalErr != nil {
			return canonicalErr
		}
		if !bytes.Equal(body, expectedBody) {
			report.Issues = append(report.Issues, VerifyIssue{Code: "source-tree-manifest", Entity: tree.EntityRef(), Detail: "canonical manifest bytes differ from tree entries"})
		}
	}
	return nil
}

func (c *Case) verifyAudit(ctx context.Context, r *VerifyReport) error {
	rows, err := c.db.QueryContext(ctx, "SELECT sequence,previous_hash,event_json,event_hash FROM audit_events ORDER BY sequence")
	if err != nil {
		return err
	}
	defer rows.Close()
	prev := ""
	var expected int64 = 1
	for rows.Next() {
		var seq int64
		var storedPrev, body, got string
		if err = rows.Scan(&seq, &storedPrev, &body, &got); err != nil {
			return err
		}
		if seq != expected || storedPrev != prev {
			r.Issues = append(r.Issues, VerifyIssue{Code: "audit-order", Detail: fmt.Sprintf("sequence %d", seq)})
		}
		var event mutationEvent
		if json.Unmarshal([]byte(body), &event) != nil {
			r.Issues = append(r.Issues, VerifyIssue{Code: "audit-json", Detail: fmt.Sprintf("sequence %d", seq)})
			continue
		}
		if event.Domain != "forensic-audit-v1" || event.Sequence != seq || event.Revision != seq || event.PreviousHash != storedPrev {
			r.Issues = append(r.Issues, VerifyIssue{Code: "audit-event", Detail: fmt.Sprintf("sequence %d event fields disagree with its envelope", seq)})
		}
		h := sha256.New()
		h.Write([]byte(event.Domain))
		h.Write([]byte(fmt.Sprint(seq)))
		h.Write([]byte(storedPrev))
		h.Write([]byte(body))
		want := hex.EncodeToString(h.Sum(nil))
		if got != want {
			r.Issues = append(r.Issues, VerifyIssue{Code: "audit-hash", Detail: fmt.Sprintf("sequence %d", seq)})
		}
		prev = got
		expected++
	}
	var head string
	var revision int64
	if err = c.db.QueryRowContext(ctx, "SELECT audit_head,revision FROM case_info WHERE singleton=1").Scan(&head, &revision); err != nil {
		return err
	}
	if head != prev {
		r.Issues = append(r.Issues, VerifyIssue{Code: "audit-head", Detail: "case audit head does not match chain"})
	}
	if revision != expected-1 {
		r.Issues = append(r.Issues, VerifyIssue{Code: "audit-revision", Detail: "case revision does not match the audit sequence"})
	}
	var mismatchedRevisions int
	if err = c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
SELECT r.revision FROM revisions r LEFT JOIN audit_events a ON a.revision=r.revision WHERE a.revision IS NULL
UNION ALL
SELECT a.revision FROM audit_events a LEFT JOIN revisions r ON r.revision=a.revision WHERE r.revision IS NULL
)`).Scan(&mismatchedRevisions); err != nil {
		return err
	}
	if mismatchedRevisions != 0 {
		r.Issues = append(r.Issues, VerifyIssue{Code: "revision-history", Detail: "revision and audit event histories differ"})
	}
	return rows.Err()
}

func (c *Case) verifyProjection(ctx context.Context, id MaterializationID, r VerifyReport) (VerifyReport, error) {
	m, err := c.Materialization(ctx, id)
	if err != nil {
		return r, err
	}
	manifestPath := filepath.Join(m.Destination, "projection-manifest.json")
	if err = verifyBlobFile(ctx, manifestPath, m.Manifest.Blob, m.Manifest.Size); err != nil {
		r.Issues = append(r.Issues, VerifyIssue{Code: "manifest-digest", Path: manifestPath, Detail: err.Error()})
		r.OK = false
		return r, nil
	}
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		r.Issues = append(r.Issues, VerifyIssue{Code: "missing-manifest", Path: m.Destination, Detail: err.Error()})
		r.OK = false
		return r, nil
	}
	var manifest ProjectionManifest
	if json.Unmarshal(b, &manifest) != nil {
		r.Issues = append(r.Issues, VerifyIssue{Code: "invalid-manifest", Detail: "manifest is not valid JSON"})
		r.OK = false
		return r, nil
	}
	expected := map[string]bool{"projection-manifest.json": true}
	for _, e := range manifest.Entries {
		expected[filepath.FromSlash(e.Path)] = true
		path := filepath.Join(m.Destination, filepath.FromSlash(e.Path))
		if ok, _ := pathWithin(m.Destination, path); !ok {
			r.Issues = append(r.Issues, VerifyIssue{Code: "unsafe-path", Path: e.Path, Detail: "entry escapes destination"})
			continue
		}
		if err = verifyBlobFile(ctx, path, BlobRef("sha256:"+e.SHA256), e.Size); err != nil {
			r.Issues = append(r.Issues, VerifyIssue{Code: "projection-file", Path: e.Path, Entity: e.Entity, Detail: err.Error()})
		} else {
			r.CheckedBlobs++
		}
	}
	for _, file := range manifest.Files {
		expected[filepath.FromSlash(file.Path)] = true
		path := filepath.Join(m.Destination, filepath.FromSlash(file.Path))
		if ok, _ := pathWithin(m.Destination, path); !ok {
			r.Issues = append(r.Issues, VerifyIssue{Code: "unsafe-path", Path: file.Path, Detail: "supporting file escapes destination"})
			continue
		}
		if err = verifyBlobFile(ctx, path, BlobRef("sha256:"+file.SHA256), file.Size); err != nil {
			r.Issues = append(r.Issues, VerifyIssue{Code: "projection-file", Path: file.Path, Detail: err.Error()})
		}
	}
	_ = filepath.WalkDir(filepath.Join(m.Destination, "data"), func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return nil
		}
		if d.Type().IsRegular() {
			rel, _ := filepath.Rel(m.Destination, path)
			if !expected[rel] {
				r.Issues = append(r.Issues, VerifyIssue{Code: "unexpected-file", Path: filepath.ToSlash(rel), Detail: "file is absent from manifest"})
			}
		}
		return nil
	})
	_ = filepath.WalkDir(filepath.Join(m.Destination, "metadata"), func(path string, d os.DirEntry, e error) error {
		if e == nil && d.Type().IsRegular() {
			rel, _ := filepath.Rel(m.Destination, path)
			if !expected[rel] {
				r.Issues = append(r.Issues, VerifyIssue{Code: "unexpected-file", Path: filepath.ToSlash(rel), Detail: "file is absent from manifest"})
			}
		}
		return nil
	})
	r.OK = len(r.Issues) == 0
	return r, nil
}

func VerifyBagIt(ctx context.Context, path string) (BagItReport, error) {
	report := BagItReport{OK: true}
	if b, e := os.ReadFile(filepath.Join(path, "bagit.txt")); e != nil {
		report.Issues = append(report.Issues, VerifyIssue{Code: "missing-tag", Path: "bagit.txt", Detail: e.Error()})
	} else if !strings.Contains(string(b), "BagIt-Version: 1.0") {
		report.Issues = append(report.Issues, VerifyIssue{Code: "bag-version", Path: "bagit.txt", Detail: "BagIt 1.0 declaration is missing"})
	}
	f, err := os.Open(filepath.Join(path, "manifest-sha256.txt"))
	if err != nil {
		return report, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	expected := map[string]bool{}
	for scanner.Scan() {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		line := scanner.Text()
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 || !isLowerHex(parts[0]) {
			report.Issues = append(report.Issues, VerifyIssue{Code: "bag-manifest", Detail: "malformed manifest line"})
			continue
		}
		if !safeBagPath(parts[1], true) {
			report.Issues = append(report.Issues, VerifyIssue{Code: "unsafe-path", Path: parts[1], Detail: "unsafe BagIt payload path"})
			continue
		}
		rel := filepath.FromSlash(parts[1])
		if expected[rel] {
			report.Issues = append(report.Issues, VerifyIssue{Code: "duplicate-path", Path: parts[1], Detail: "duplicate payload manifest path"})
			continue
		}
		expected[rel] = true
		full := filepath.Join(path, rel)
		if ok, _ := pathWithin(path, full); !ok || !strings.HasPrefix(filepath.ToSlash(parts[1]), "data/") {
			report.Issues = append(report.Issues, VerifyIssue{Code: "unsafe-path", Path: parts[1], Detail: "unsafe BagIt payload path"})
			continue
		}
		st, e := os.Lstat(full)
		if e != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "missing-payload", Path: parts[1], Detail: e.Error()})
			continue
		}
		if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			report.Issues = append(report.Issues, VerifyIssue{Code: "unsafe-payload", Path: parts[1], Detail: "payload is not a regular file"})
			continue
		}
		if e = verifyBlobFile(ctx, full, BlobRef("sha256:"+parts[0]), st.Size()); e != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "payload-digest", Path: parts[1], Detail: e.Error()})
		} else {
			report.PayloadFiles++
		}
	}
	if err = scanner.Err(); err != nil {
		return report, err
	}
	tagFile, tagErr := os.Open(filepath.Join(path, "tagmanifest-sha256.txt"))
	if tagErr != nil {
		return report, tagErr
	}
	tagScanner := bufio.NewScanner(tagFile)
	tagScanner.Buffer(make([]byte, 4096), 1<<20)
	tagExpected := map[string]bool{}
	for tagScanner.Scan() {
		parts := strings.SplitN(tagScanner.Text(), "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 || !isLowerHex(parts[0]) {
			report.Issues = append(report.Issues, VerifyIssue{Code: "tag-manifest", Detail: "malformed tag manifest line"})
			continue
		}
		if !safeBagPath(parts[1], false) {
			report.Issues = append(report.Issues, VerifyIssue{Code: "unsafe-path", Path: parts[1], Detail: "unsafe BagIt tag path"})
			continue
		}
		rel := filepath.FromSlash(parts[1])
		if tagExpected[rel] {
			report.Issues = append(report.Issues, VerifyIssue{Code: "duplicate-path", Path: parts[1], Detail: "duplicate tag manifest path"})
			continue
		}
		tagExpected[rel] = true
		full := filepath.Join(path, rel)
		if ok, _ := pathWithin(path, full); !ok || strings.HasPrefix(filepath.ToSlash(parts[1]), "data/") {
			report.Issues = append(report.Issues, VerifyIssue{Code: "unsafe-path", Path: parts[1], Detail: "unsafe BagIt tag path"})
			continue
		}
		st, e := os.Lstat(full)
		if e != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "missing-tag", Path: parts[1], Detail: e.Error()})
			continue
		}
		if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			report.Issues = append(report.Issues, VerifyIssue{Code: "unsafe-tag", Path: parts[1], Detail: "tag is not a regular file"})
			continue
		}
		if e = verifyBlobFile(ctx, full, BlobRef("sha256:"+parts[0]), st.Size()); e != nil {
			report.Issues = append(report.Issues, VerifyIssue{Code: "tag-digest", Path: parts[1], Detail: e.Error()})
		}
	}
	if e := tagScanner.Err(); e != nil {
		tagFile.Close()
		return report, e
	}
	_ = tagFile.Close()
	_ = filepath.WalkDir(filepath.Join(path, "data"), func(full string, d os.DirEntry, e error) error {
		if e == nil && d.Type()&os.ModeSymlink != 0 {
			rel, _ := filepath.Rel(path, full)
			report.Issues = append(report.Issues, VerifyIssue{Code: "unsafe-payload", Path: filepath.ToSlash(rel), Detail: "active symlink in payload"})
			return filepath.SkipDir
		}
		if e == nil && d.Type().IsRegular() {
			rel, _ := filepath.Rel(path, full)
			if !expected[rel] {
				report.Issues = append(report.Issues, VerifyIssue{Code: "unexpected-payload", Path: filepath.ToSlash(rel), Detail: "payload is absent from manifest"})
			}
		}
		return nil
	})
	report.OK = len(report.Issues) == 0
	return report, nil
}

func safeBagPath(p string, payload bool) bool {
	if p == "" || strings.Contains(p, "\\") || strings.Contains(p, "\x00") || strings.HasPrefix(p, "/") || pathpkg.Clean(p) != p {
		return false
	}
	if payload {
		return strings.HasPrefix(p, "data/")
	}
	return !strings.HasPrefix(p, "data/") && p != "tagmanifest-sha256.txt"
}
func isLowerHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func digestFile(ctx context.Context, path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, &contextReader{ctx: ctx, r: f})
	return hex.EncodeToString(h.Sum(nil)), n, err
}
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
