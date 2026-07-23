package forensic

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const sourceTreeManifestFormat = 1

type sourceTreeManifest struct {
	Format  int               `json:"format"`
	Entries []sourceTreeEntry `json:"entries"`
}

type sourceTreeEntry struct {
	Path       string        `json:"path"`
	Kind       TreeEntryKind `json:"kind"`
	Mode       uint32        `json:"mode"`
	Size       int64         `json:"size,omitempty"`
	SHA256     string        `json:"sha256,omitempty"`
	LinkTarget string        `json:"link_target,omitempty"`
}

type importedTreeEntry struct {
	entry  TreeEntry
	staged stagedBlob
	object ObjectRef
}

// ImportSourceTree imports a directory as one logical evidence item. Regular
// files become distinct object occurrences, while directories and symlinks are
// retained as inert manifest metadata. Symlinks are never followed.
func (c *Case) ImportSourceTree(ctx context.Context, root string, spec SourceTreeSpec) (SourceTree, error) {
	if err := c.checkOpen(); err != nil {
		return SourceTree{}, err
	}
	if strings.TrimSpace(root) == "" {
		return SourceTree{}, fmt.Errorf("%w: source tree root required", ErrInvalid)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return SourceTree{}, err
	}
	rootInfo, err := os.Lstat(absRoot)
	if err != nil {
		return SourceTree{}, err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return SourceTree{}, fmt.Errorf("%w: source tree root must be a real directory", ErrInvalid)
	}
	insideRepository, err := pathWithin(c.repo.root, absRoot)
	if err != nil {
		return SourceTree{}, err
	}
	containsRepository, err := pathWithin(absRoot, c.repo.root)
	if err != nil {
		return SourceTree{}, err
	}
	if insideRepository || containsRepository {
		return SourceTree{}, fmt.Errorf("%w: source tree and managed repository must not overlap", ErrInvalid)
	}
	label := strings.TrimSpace(spec.Label)
	if label == "" {
		label = filepath.Base(filepath.Clean(absRoot))
	}
	if label == "." || label == string(filepath.Separator) || label == "" {
		label = "source-tree"
	}
	spec.Label = label

	entries, err := c.scanSourceTree(ctx, absRoot, spec.IncludeGitDir)
	if err != nil {
		return SourceTree{}, err
	}
	defer func() {
		for i := range entries {
			_ = os.Remove(entries[i].staged.path)
		}
	}()
	manifest := sourceTreeManifest{Format: sourceTreeManifestFormat, Entries: make([]sourceTreeEntry, len(entries))}
	for i := range entries {
		e := entries[i].entry
		manifest.Entries[i] = sourceTreeEntry{
			Path: e.Path, Kind: e.Kind, Mode: e.Mode, Size: e.Size,
			SHA256: e.SHA256, LinkTarget: e.LinkTarget,
		}
	}
	manifestBytes, err := canonicalJSON(manifest)
	if err != nil {
		return SourceTree{}, err
	}
	manifestStaged, err := c.stageBlob(ctx, strings.NewReader(string(manifestBytes)))
	if err != nil {
		return SourceTree{}, err
	}
	defer func() { _ = os.Remove(manifestStaged.path) }()
	if want := strings.ToLower(strings.TrimSpace(spec.Acquisition.SuppliedHashes["sha256"])); want != "" && want != manifestStaged.digest {
		return SourceTree{}, fmt.Errorf("%w: supplied SHA-256 does not match source-tree manifest", ErrIntegrity)
	}
	fileCount := 0
	var totalBytes int64
	for i := range entries {
		if entries[i].entry.Kind == TreeEntryFile {
			fileCount++
			totalBytes += entries[i].entry.Size
		}
	}
	treeDigest := string(manifestStaged.ref)
	fingerprint, configJSON, err := digestJSON(struct {
		Label         string          `json:"label"`
		Acquisition   AcquisitionSpec `json:"acquisition"`
		IncludeGitDir bool            `json:"include_git_dir"`
		TreeDigest    string          `json:"tree_digest"`
	}{label, spec.Acquisition, spec.IncludeGitDir, treeDigest})
	if err != nil {
		return SourceTree{}, err
	}
	// Avoid publishing unreferenced bytes for the normal idempotent retry and
	// conflict paths. The transactional check below remains authoritative for
	// concurrent callers.
	if spec.IdempotencyKey != "" {
		tx, beginErr := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if beginErr != nil {
			return SourceTree{}, mapSQLError(beginErr)
		}
		var old SourceTree
		found, lookupErr := lookupIdempotency(ctx, tx, string(c.id), "source-tree.import", spec.IdempotencyKey, fingerprint, &old)
		_ = tx.Rollback()
		if lookupErr != nil {
			return SourceTree{}, lookupErr
		}
		if found {
			return old, nil
		}
	}

	// Publish all immutable bytes before the catalog transaction. A crash can
	// leave an unreferenced CAS blob, but can never commit a missing reference.
	for i := range entries {
		if entries[i].entry.Kind != TreeEntryFile {
			continue
		}
		if err = c.publishBlob(ctx, entries[i].staged); err != nil {
			return SourceTree{}, err
		}
	}
	if err = c.publishBlob(ctx, manifestStaged); err != nil {
		return SourceTree{}, err
	}

	evidenceID, err := newEvidenceID()
	if err != nil {
		return SourceTree{}, err
	}
	treeID, err := newTreeID()
	if err != nil {
		return SourceTree{}, err
	}
	manifestObjectID, err := newObjectID()
	if err != nil {
		return SourceTree{}, err
	}
	activityID, err := newActivityID()
	if err != nil {
		return SourceTree{}, err
	}
	for i := range entries {
		if entries[i].entry.Kind != TreeEntryFile {
			continue
		}
		objectID, e := newObjectID()
		if e != nil {
			return SourceTree{}, e
		}
		mediaType := mime.TypeByExtension(filepath.Ext(entries[i].entry.Path))
		if mediaType == "" {
			mediaType = "application/octet-stream"
		}
		entries[i].object = ObjectRef{
			ID: objectID, Blob: entries[i].staged.ref, Size: entries[i].entry.Size,
			DisplayName: filepath.Base(filepath.FromSlash(entries[i].entry.Path)),
			MediaType:   mediaType, Path: entries[i].entry.Path,
			GeneratingActivity: activityID,
		}
		entries[i].entry.Object = &entries[i].object
	}
	manifestObject := ObjectRef{
		ID: manifestObjectID, Blob: manifestStaged.ref, Size: manifestStaged.size,
		DisplayName: "source-tree-manifest.json", MediaType: "application/json",
		Path: "source-tree-manifest.json", GeneratingActivity: activityID,
	}
	result := SourceTree{
		ID: treeID, Evidence: evidenceID, Label: label, TreeDigest: treeDigest,
		Manifest: manifestObject, FileCount: fileCount, TotalBytes: totalBytes,
		Entries: make([]TreeEntry, len(entries)),
	}
	for i := range entries {
		result.Entries[i] = entries[i].entry
	}

	affected := []string{string(evidenceID), string(treeID), string(manifestObjectID), result.TreeDigest}
	_, err = c.mutate(ctx, c.defaultAgent.ID, "", "source-tree.import", fingerprint, affected, func(tx *sql.Tx, revision int64) error {
		if spec.IdempotencyKey != "" {
			var old SourceTree
			found, e := lookupIdempotency(ctx, tx, string(c.id), "source-tree.import", spec.IdempotencyKey, fingerprint, &old)
			if e != nil {
				return e
			}
			if found {
				result = old
				return nil
			}
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		outcome, _ := canonicalJSON(OutcomeSucceeded())
		if _, e := tx.ExecContext(ctx, `INSERT INTO activities(id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json,idempotency_key) VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?,?)`, activityID, c.defaultAgent.ID, ActivityImport, "Import source tree "+label, string(configJSON), fingerprint, CaptureLibrary, ActivitySucceeded, revision, now, now, string(outcome), spec.IdempotencyKey); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO blobs(digest,size,created_at) VALUES(?,?,?)", manifestStaged.ref, manifestStaged.size, now); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", evidenceID, EntityEvidence, activityID, revision, now, label); e != nil {
			return e
		}
		acquisitionJSON, _ := canonicalJSON(spec.Acquisition)
		if _, e := tx.ExecContext(ctx, "INSERT INTO evidence(id,label,acquisition_json) VALUES(?,?,?)", evidenceID, label, string(acquisitionJSON)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", treeID, EntitySourceTree, activityID, revision, now, label); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,media_type,display_name) VALUES(?,?,?,?,?,?,?)", manifestObjectID, EntityObject, activityID, revision, now, manifestObject.MediaType, manifestObject.DisplayName); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO objects(id,blob_digest,size,role,path_display) VALUES(?,?,?,?,?)", manifestObjectID, manifestStaged.ref, manifestStaged.size, "tree-manifest", manifestObject.Path); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO evidence_objects(evidence_id,object_id,role) VALUES(?,?,'root')", evidenceID, manifestObjectID); e != nil {
			return e
		}
		policyJSON, _ := canonicalJSON(struct {
			IncludeGitDir bool `json:"include_git_dir"`
		}{spec.IncludeGitDir})
		if _, e := tx.ExecContext(ctx, `INSERT INTO source_trees(id,evidence_id,label,tree_digest,manifest_object_id,file_count,total_bytes,entry_count,policy_json) VALUES(?,?,?,?,?,?,?,?,?)`, treeID, evidenceID, label, result.TreeDigest, manifestObjectID, fileCount, totalBytes, len(entries), string(policyJSON)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'evidence'),(?,?,'source-tree'),(?,?,'tree-manifest')", activityID, evidenceID, activityID, treeID, activityID, manifestObjectID); e != nil {
			return e
		}
		for i := range entries {
			item := &entries[i]
			var blob any
			var object any
			if item.entry.Kind == TreeEntryFile {
				blob = item.staged.ref
				object = item.object.ID
				if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO blobs(digest,size,created_at) VALUES(?,?,?)", item.staged.ref, item.staged.size, now); e != nil {
					return e
				}
				if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,media_type,display_name) VALUES(?,?,?,?,?,?,?)", item.object.ID, EntityObject, activityID, revision, now, item.object.MediaType, item.object.DisplayName); e != nil {
					return e
				}
				if _, e := tx.ExecContext(ctx, "INSERT INTO objects(id,blob_digest,size,role,path_display) VALUES(?,?,?,?,?)", item.object.ID, item.object.Blob, item.object.Size, "tree-file", item.object.Path); e != nil {
					return e
				}
				if _, e := tx.ExecContext(ctx, "INSERT INTO evidence_objects(evidence_id,object_id,role) VALUES(?,?,'tree-file')", evidenceID, item.object.ID); e != nil {
					return e
				}
				if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'tree-file')", activityID, item.object.ID); e != nil {
					return e
				}
				_, locatorType, locatorJSON, e := encodeLocator(PathLocator{Display: item.entry.Path, Separator: "/"})
				if e != nil {
					return e
				}
				if _, e = tx.ExecContext(ctx, "INSERT INTO source_locators(entity_id,locator_type,locator_json) VALUES(?,?,?)", item.object.ID, locatorType, locatorJSON); e != nil {
					return e
				}
			}
			if _, e := tx.ExecContext(ctx, `INSERT INTO tree_entries(tree_id,ordinal,path,entry_kind,file_mode,size,blob_digest,object_id,link_target) VALUES(?,?,?,?,?,?,?,?,?)`, treeID, i, item.entry.Path, item.entry.Kind, item.entry.Mode, item.entry.Size, blob, object, item.entry.LinkTarget); e != nil {
				return e
			}
		}
		result.CreatedRevision = revision
		result.Manifest.CreatedRevision = revision
		for i := range result.Entries {
			if result.Entries[i].Object != nil {
				result.Entries[i].Object.CreatedRevision = revision
			}
		}
		return storeIdempotency(ctx, tx, string(c.id), "source-tree.import", spec.IdempotencyKey, fingerprint, result)
	})
	return result, err
}

func (c *Case) scanSourceTree(ctx context.Context, root string, includeGit bool) ([]importedTreeEntry, error) {
	var entries []importedTreeEntry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "" || rel == "." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
			return fmt.Errorf("%w: unsafe source-tree path", ErrInvalid)
		}
		if d.IsDir() && !includeGit && d.Name() == ".git" {
			return filepath.SkipDir
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		item := importedTreeEntry{entry: TreeEntry{Path: rel, Mode: uint32(info.Mode().Perm())}}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			item.entry.Kind = TreeEntrySymlink
			item.entry.LinkTarget, err = os.Readlink(path)
			if err != nil {
				return err
			}
		case info.IsDir():
			item.entry.Kind = TreeEntryDirectory
		case info.Mode().IsRegular():
			item.entry.Kind = TreeEntryFile
			f, openErr := os.Open(path)
			if openErr != nil {
				return openErr
			}
			openedInfo, statErr := f.Stat()
			if statErr != nil {
				_ = f.Close()
				return statErr
			}
			if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
				_ = f.Close()
				return fmt.Errorf("%w: source file changed during import: %s", ErrConflict, rel)
			}
			item.staged, err = c.stageBlob(ctx, f)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				_ = os.Remove(item.staged.path)
				return closeErr
			}
			postInfo, postErr := os.Lstat(path)
			if postErr != nil || !postInfo.Mode().IsRegular() || !os.SameFile(info, postInfo) || postInfo.Size() != openedInfo.Size() || !postInfo.ModTime().Equal(openedInfo.ModTime()) {
				_ = os.Remove(item.staged.path)
				return fmt.Errorf("%w: source file changed during import: %s", ErrConflict, rel)
			}
			item.entry.Size = item.staged.size
			item.entry.SHA256 = item.staged.digest
		default:
			return fmt.Errorf("%w: unsupported filesystem entry %s", ErrUnsupported, rel)
		}
		entries = append(entries, item)
		return nil
	})
	if err != nil {
		for i := range entries {
			_ = os.Remove(entries[i].staged.path)
		}
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].entry.Path < entries[j].entry.Path })
	return entries, nil
}

// SourceTree loads a source-tree entity and all canonical manifest entries.
func (c *Case) SourceTree(ctx context.Context, id TreeID) (SourceTree, error) {
	if err := c.checkOpen(); err != nil {
		return SourceTree{}, err
	}
	var tree SourceTree
	err := c.db.QueryRowContext(ctx, `SELECT st.id,st.evidence_id,st.label,st.tree_digest,st.file_count,st.total_bytes,e.created_revision,o.id,o.blob_digest,o.size,oe.display_name,oe.media_type,o.path_display,oe.generating_activity_id,oe.created_revision FROM source_trees st JOIN entities e ON e.id=st.id JOIN objects o ON o.id=st.manifest_object_id JOIN entities oe ON oe.id=o.id WHERE st.id=?`, id).Scan(
		&tree.ID, &tree.Evidence, &tree.Label, &tree.TreeDigest, &tree.FileCount, &tree.TotalBytes, &tree.CreatedRevision,
		&tree.Manifest.ID, &tree.Manifest.Blob, &tree.Manifest.Size, &tree.Manifest.DisplayName, &tree.Manifest.MediaType,
		&tree.Manifest.Path, &tree.Manifest.GeneratingActivity, &tree.Manifest.CreatedRevision,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return SourceTree{}, ErrNotFound
	}
	if err != nil {
		return SourceTree{}, mapSQLError(err)
	}
	rows, err := c.db.QueryContext(ctx, `SELECT te.path,te.entry_kind,te.file_mode,te.size,COALESCE(te.blob_digest,''),COALESCE(te.link_target,''),COALESCE(te.object_id,''),COALESCE(oe.display_name,''),COALESCE(oe.media_type,''),COALESCE(o.path_display,''),COALESCE(oe.generating_activity_id,''),COALESCE(oe.created_revision,0) FROM tree_entries te LEFT JOIN objects o ON o.id=te.object_id LEFT JOIN entities oe ON oe.id=o.id WHERE te.tree_id=? ORDER BY te.ordinal`, id)
	if err != nil {
		return SourceTree{}, mapSQLError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var entry TreeEntry
		var blob BlobRef
		var objectID ObjectID
		var displayName, mediaType, objectPath string
		var generatingActivity ActivityID
		var createdRevision int64
		if err = rows.Scan(&entry.Path, &entry.Kind, &entry.Mode, &entry.Size, &blob, &entry.LinkTarget, &objectID, &displayName, &mediaType, &objectPath, &generatingActivity, &createdRevision); err != nil {
			return SourceTree{}, err
		}
		if entry.Kind == TreeEntryFile {
			if objectID == "" || blob == "" {
				return SourceTree{}, fmt.Errorf("%w: source-tree file has no object", ErrIntegrity)
			}
			entry.SHA256 = strings.TrimPrefix(string(blob), "sha256:")
			entry.Object = &ObjectRef{ID: objectID, Blob: blob, Size: entry.Size, DisplayName: displayName, MediaType: mediaType, Path: objectPath, GeneratingActivity: generatingActivity, CreatedRevision: createdRevision}
		}
		tree.Entries = append(tree.Entries, entry)
	}
	if err = rows.Err(); err != nil {
		return SourceTree{}, err
	}
	if tree.FileCount != countTreeFiles(tree.Entries) {
		return SourceTree{}, fmt.Errorf("%w: source-tree file count mismatch", ErrIntegrity)
	}
	return tree, nil
}

func countTreeFiles(entries []TreeEntry) int {
	n := 0
	for i := range entries {
		if entries[i].Kind == TreeEntryFile {
			n++
		}
	}
	return n
}
