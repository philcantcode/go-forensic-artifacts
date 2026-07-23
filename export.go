package forensic

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (c *Case) ExportMarkdown(ctx context.Context, spec MarkdownSpec) error {
	if spec.Writer == nil {
		return fmt.Errorf("%w: writer required", ErrInvalid)
	}
	s, err := c.Selection(ctx, spec.Selection)
	if err != nil {
		return err
	}
	info, err := c.Info(ctx)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(spec.Writer)
	defer w.Flush()
	fmt.Fprintf(w, "---\ncase: %s\nrevision: %d\nselection: %s\nselection_revision: %d\nexporter: forensic-markdown/v1\n---\n\n# %s\n\n", info.ID, info.Revision, s.ID, s.Revision, escapeMarkdown(s.Name))
	for _, e := range s.Members {
		var name, media, activity string
		var created int64
		if err = c.db.QueryRowContext(ctx, "SELECT display_name,media_type,generating_activity_id,created_revision FROM entities WHERE id=?", e.ID).Scan(&name, &media, &activity, &created); err != nil {
			return err
		}
		fmt.Fprintf(w, "## %s\n\n- Kind: `%s`\n- ID: `%s`\n- Name: %s\n- Created revision: %d\n", escapeMarkdown(name), e.Kind, e.ID, escapeMarkdown(name), created)
		if media != "" {
			fmt.Fprintf(w, "- Media type: `%s`\n", escapeMarkdown(media))
		}
		if spec.IncludeProvenanceSummary {
			fmt.Fprintf(w, "- Generating activity: `%s`\n", activity)
		}
		if spec.IncludeHashes {
			var ref string
			var size int64
			if err = c.db.QueryRowContext(ctx, "SELECT blob_digest,size FROM objects WHERE id=?", e.ID).Scan(&ref, &size); err == nil {
				fmt.Fprintf(w, "- Bytes: %d\n- Digest: `%s`\n", size, ref)
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		fmt.Fprintln(w)
	}
	return w.Flush()
}
func escapeMarkdown(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;", "\r", " ", "\n", " ")
	return r.Replace(s)
}

func (c *Case) ExportJSONL(ctx context.Context, spec JSONLSpec) error {
	if spec.Writer == nil {
		return fmt.Errorf("%w: writer required", ErrInvalid)
	}
	s, err := c.Selection(ctx, spec.Selection)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(spec.Writer)
	defer w.Flush()
	for _, e := range s.Members {
		record := map[string]any{"entity": e}
		var name, media, activity string
		var created int64
		if err = c.db.QueryRowContext(ctx, "SELECT display_name,media_type,generating_activity_id,created_revision FROM entities WHERE id=?", e.ID).Scan(&name, &media, &activity, &created); err != nil {
			return err
		}
		record["display_name"] = name
		record["media_type"] = media
		record["generating_activity"] = activity
		record["created_revision"] = created
		if e.Kind == EntityObject || e.Kind == EntityManifest {
			if obj, er := c.objectByEntity(ctx, e.ID); er == nil {
				record["object"] = obj
			}
		} else if e.Kind == EntityArtifact {
			if a, er := c.Artifact(ctx, ArtifactID(e.ID)); er == nil {
				record["artifact"] = a
			}
		}
		b, err := canonicalJSON(record)
		if err != nil {
			return err
		}
		if _, err = w.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return w.Flush()
}

func (s *Session) ExportBagIt(ctx context.Context, spec BagItSpec) (Deliverable, error) {
	if err := s.checkOpen(); err != nil {
		return Deliverable{}, err
	}
	selection, err := s.caseRef.Selection(ctx, spec.Selection)
	if err != nil {
		return Deliverable{}, err
	}
	if spec.Destination == "" {
		return Deliverable{}, fmt.Errorf("%w: destination required", ErrInvalid)
	}
	dest, err := filepath.Abs(spec.Destination)
	if err != nil {
		return Deliverable{}, err
	}
	inside, _ := pathWithin(s.caseRef.root, dest)
	if inside {
		return Deliverable{}, fmt.Errorf("%w: package cannot be inside the case", ErrInvalid)
	}
	if _, err = os.Lstat(dest); err == nil {
		return Deliverable{}, ErrConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return Deliverable{}, err
	}
	did, err := newDeliverableID()
	if err != nil {
		return Deliverable{}, err
	}
	partial := dest + ".partial-" + string(did)
	if err = os.MkdirAll(filepath.Join(partial, "data"), 0700); err != nil {
		return Deliverable{}, err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(partial)
		}
	}()
	payload := map[string]string{}
	for _, e := range selection.Members {
		if e.Kind != EntityObject && e.Kind != EntityManifest {
			continue
		}
		obj, er := s.caseRef.objectByEntity(ctx, e.ID)
		if er != nil {
			return Deliverable{}, er
		}
		rel := "data/" + sanitizeComponent(e.ID) + "/" + sanitizeComponent(obj.DisplayName)
		full := filepath.Join(partial, filepath.FromSlash(rel))
		if er = os.MkdirAll(filepath.Dir(full), 0700); er != nil {
			return Deliverable{}, er
		}
		if er = copyFileContext(ctx, s.caseRef.blobPath(obj.Blob), full); er != nil {
			return Deliverable{}, er
		}
		payload[rel] = strings.TrimPrefix(string(obj.Blob), "sha256:")
	}
	if err = os.WriteFile(filepath.Join(partial, "bagit.txt"), []byte("BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n"), 0600); err != nil {
		return Deliverable{}, err
	}
	info, _ := s.caseRef.Info(ctx)
	bagInfo := fmt.Sprintf("Bagging-Date: %s\nExternal-Identifier: %s\nSource-Organization: forensic artifact store\nBag-Size: %d files\n", time.Now().UTC().Format("2006-01-02"), info.ID, len(payload))
	if err = os.WriteFile(filepath.Join(partial, "bag-info.txt"), []byte(bagInfo), 0600); err != nil {
		return Deliverable{}, err
	}
	var manifest strings.Builder
	for _, p := range sortedKeys(payload) {
		fmt.Fprintf(&manifest, "%s  %s\n", payload[p], p)
	}
	manifestBytes := []byte(manifest.String())
	if err = os.WriteFile(filepath.Join(partial, "manifest-sha256.txt"), manifestBytes, 0600); err != nil {
		return Deliverable{}, err
	}
	tags := []string{"bag-info.txt", "bagit.txt", "manifest-sha256.txt"}
	var tagManifest strings.Builder
	for _, tag := range tags {
		d, _, er := digestFile(ctx, filepath.Join(partial, tag))
		if er != nil {
			return Deliverable{}, er
		}
		fmt.Fprintf(&tagManifest, "%s  %s\n", d, tag)
	}
	if err = os.WriteFile(filepath.Join(partial, "tagmanifest-sha256.txt"), []byte(tagManifest.String()), 0600); err != nil {
		return Deliverable{}, err
	}
	if report, er := VerifyBagIt(ctx, partial); er != nil || !report.OK {
		if er != nil {
			return Deliverable{}, er
		}
		return Deliverable{}, fmt.Errorf("%w: generated BagIt package failed verification", ErrIntegrity)
	}
	if err = renameWithRetry(ctx, partial, dest); err != nil {
		return Deliverable{}, err
	}
	published = true
	inventory := sha256.New()
	all := append(append([]string(nil), sortedKeys(payload)...), "bag-info.txt", "bagit.txt", "manifest-sha256.txt", "tagmanifest-sha256.txt")
	sort.Strings(all)
	for _, p := range all {
		d, _, er := digestFile(ctx, filepath.Join(dest, filepath.FromSlash(p)))
		if er != nil {
			return Deliverable{}, er
		}
		io.WriteString(inventory, p+"\x00"+d+"\n")
	}
	packageDigest := hex.EncodeToString(inventory.Sum(nil))
	mf, err := os.Open(filepath.Join(dest, "manifest-sha256.txt"))
	if err != nil {
		return Deliverable{}, err
	}
	staged, err := s.caseRef.stageBlob(ctx, mf)
	_ = mf.Close()
	if err != nil {
		return Deliverable{}, err
	}
	if err = s.caseRef.publishBlob(ctx, staged); err != nil {
		return Deliverable{}, err
	}
	aid, err := newActivityID()
	if err != nil {
		return Deliverable{}, err
	}
	oid, err := newObjectID()
	if err != nil {
		return Deliverable{}, err
	}
	fp, cfg, err := digestJSON(struct {
		Selection SelectionID
		Digest    string
		Name      string
	}{spec.Selection, packageDigest, spec.Name})
	if err != nil {
		return Deliverable{}, err
	}
	result := Deliverable{ID: did, Selection: spec.Selection, Path: dest, SHA256: packageDigest}
	_, err = s.caseRef.mutate(ctx, s.info.Agent.ID, s.ID(), "deliverable.package", fp, []string{string(did), string(oid)}, func(tx *sql.Tx, rev int64) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		out, _ := canonicalJSON(OutcomeSucceeded())
		if _, e := tx.ExecContext(ctx, "INSERT INTO activities(id,session_id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?)", aid, s.ID(), s.info.Agent.ID, ActivityDeliverablePackage, "Package BagIt deliverable", string(cfg), fp, CaptureLibrary, ActivitySucceeded, rev, now, now, string(out)); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'selection')", aid, spec.Selection); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT OR IGNORE INTO blobs(digest,size,created_at) VALUES(?,?,?)", staged.ref, staged.size, now); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,media_type,display_name) VALUES(?,?,?,?,?,?,?)", oid, EntityManifest, aid, rev, now, "text/plain", "manifest-sha256.txt"); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO objects(id,blob_digest,size,role,path_display) VALUES(?,?,?,?,?)", oid, staged.ref, staged.size, "manifest", "manifest-sha256.txt"); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO entities(id,kind,generating_activity_id,created_revision,created_at,display_name) VALUES(?,?,?,?,?,?)", did, EntityDeliverable, aid, rev, now, spec.Name); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO deliverables(id,selection_id,path_hint,package_sha256) VALUES(?,?,?,?)", did, spec.Selection, dest, packageDigest); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'manifest'),(?,?,'deliverable')", aid, oid, aid, did); e != nil {
			return e
		}
		result.CreatedRevision = rev
		return nil
	})
	return result, err
}
