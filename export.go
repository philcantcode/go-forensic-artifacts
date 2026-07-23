package forensic

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
	projectedLinks := map[string]string{}
	if spec.Materialization != "" {
		materialization, loadErr := c.Materialization(ctx, spec.Materialization)
		if loadErr != nil {
			return loadErr
		}
		body, readErr := os.ReadFile(filepath.Join(materialization.Destination, "projection-manifest.json"))
		if readErr != nil {
			return readErr
		}
		var manifest ProjectionManifest
		if json.Unmarshal(body, &manifest) != nil {
			return ErrIntegrity
		}
		for _, entry := range manifest.Entries {
			projectedLinks[entry.Entity.ID] = entry.Path
		}
	}
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
		if link := projectedLinks[e.ID]; link != "" {
			fmt.Fprintf(w, "- Projected file: [%s](<%s>)\n", escapeMarkdown(filepath.Base(filepath.FromSlash(link))), filepath.ToSlash(link))
		}
		switch e.Kind {
		case EntityEvidence:
			evidence, loadErr := c.Evidence(ctx, EvidenceID(e.ID))
			if loadErr != nil {
				return loadErr
			}
			fmt.Fprintf(w, "- Acquisition method: %s\n- Source URI: %s\n- Custodian: %s\n", escapeMarkdown(evidence.Acquisition.Method), escapeMarkdown(evidence.Acquisition.SourceURI), escapeMarkdown(evidence.Acquisition.Custodian))
		case EntitySourceTree:
			tree, loadErr := c.SourceTree(ctx, TreeID(e.ID))
			if loadErr != nil {
				return loadErr
			}
			fmt.Fprintf(w, "- Tree digest: `%s`\n- Files: %d\n- Total bytes: %d\n\n### Tree\n\n", tree.TreeDigest, tree.FileCount, tree.TotalBytes)
			for _, entry := range tree.Entries {
				line := entry.Path
				if entry.Kind == TreeEntrySymlink {
					line += " -> " + entry.LinkTarget
				}
				fmt.Fprintf(w, "- `%s` (%s)\n", escapeMarkdown(line), entry.Kind)
			}
		case EntityObject, EntityManifest:
			object, loadErr := c.objectByEntity(ctx, e.ID)
			if loadErr != nil {
				return loadErr
			}
			if object.Path != "" {
				fmt.Fprintf(w, "- Source path: `%s`\n", escapeMarkdown(object.Path))
			}
		case EntityArtifact:
			artifact, loadErr := c.Artifact(ctx, ArtifactID(e.ID))
			if loadErr != nil {
				return loadErr
			}
			fmt.Fprintf(w, "\n### Values\n\n| Property | Type | Raw | Normalized |\n| --- | --- | --- | --- |\n")
			for _, value := range artifact.Values {
				normalized := ""
				if value.Normalized != nil {
					body, _ := canonicalJSON(value.Normalized)
					normalized = string(body)
				}
				fmt.Fprintf(w, "| %s | `%s` | %s | %s |\n", escapeMarkdown(value.Property), value.Type, escapeMarkdown(value.Raw), escapeMarkdown(normalized))
			}
		case EntityAssertion:
			assertion, loadErr := c.Assertion(ctx, AssertionID(e.ID))
			if loadErr != nil {
				return loadErr
			}
			fmt.Fprintf(w, "- Assertion type: `%s`\n\n%s\n", escapeMarkdown(assertion.Type), escapeMarkdown(assertion.Body))
		case EntityFindingRevision:
			finding, loadErr := c.FindingRevision(ctx, FindingRevisionID(e.ID))
			if loadErr != nil {
				return loadErr
			}
			fmt.Fprintf(w, "- Finding: `%s` version %d\n- Status: `%s`\n- Severity: %s\n- Review state: %s\n\n%s\n", finding.ID, finding.Version, finding.Status, escapeMarkdown(finding.Severity), escapeMarkdown(finding.ReviewState), escapeMarkdown(finding.Body))
			if finding.Vulnerability != nil {
				body, _ := canonicalJSON(finding.Vulnerability)
				fmt.Fprintf(w, "\n```json\n%s\n```\n", body)
			}
		case EntityDeliverable:
			deliverable, loadErr := c.Deliverable(ctx, DeliverableID(e.ID))
			if loadErr != nil {
				return loadErr
			}
			fmt.Fprintf(w, "- Format: `%s`\n- Package SHA-256: `%s`\n- Recipient: %s\n- Purpose: %s\n", deliverable.Format, deliverable.SHA256, escapeMarkdown(deliverable.Recipient), escapeMarkdown(deliverable.Purpose))
		}
		fmt.Fprintln(w)
	}
	return w.Flush()
}
func escapeMarkdown(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "|", "\\|", "<", "&lt;", ">", "&gt;", "\r", " ", "\n", " ")
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
		record, loadErr := c.entityExportRecord(ctx, e)
		err = loadErr
		if err != nil {
			return err
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

func (c *Case) entityExportRecord(ctx context.Context, e EntityRef) (map[string]any, error) {
	record := map[string]any{"entity": e}
	var name, media, activity string
	var created int64
	if err := c.db.QueryRowContext(ctx, "SELECT display_name,media_type,generating_activity_id,created_revision FROM entities WHERE id=?", e.ID).Scan(&name, &media, &activity, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapSQLError(err)
	}
	record["display_name"] = name
	record["media_type"] = media
	record["generating_activity"] = activity
	record["created_revision"] = created
	activityRecord, err := c.Activity(ctx, ActivityID(activity))
	if err != nil {
		return nil, err
	}
	record["activity"] = activityRecord
	switch e.Kind {
	case EntityEvidence:
		record["evidence"], err = c.Evidence(ctx, EvidenceID(e.ID))
	case EntitySourceTree:
		record["source_tree"], err = c.SourceTree(ctx, TreeID(e.ID))
	case EntityObject, EntityManifest:
		record["object"], err = c.objectByEntity(ctx, e.ID)
	case EntityArtifact:
		record["artifact"], err = c.Artifact(ctx, ArtifactID(e.ID))
	case EntityAssertion:
		record["assertion"], err = c.Assertion(ctx, AssertionID(e.ID))
	case EntityFindingRevision:
		record["finding_revision"], err = c.FindingRevision(ctx, FindingRevisionID(e.ID))
	case EntitySelection:
		record["selection"], err = c.Selection(ctx, SelectionID(e.ID))
	case EntityProjection:
		record["projection"], err = c.Projection(ctx, ProjectionID(e.ID))
	case EntityDeliverable:
		record["deliverable"], err = c.Deliverable(ctx, DeliverableID(e.ID))
	}
	return record, err
}

func (s *Session) ExportBagIt(ctx context.Context, spec BagItSpec) (Deliverable, error) {
	if err := s.checkOpen(); err != nil {
		return Deliverable{}, err
	}
	if spec.Closure == "" {
		spec.Closure = ClosureExact
	}
	if spec.Version == "" {
		spec.Version = "1"
	}
	if strings.TrimSpace(spec.Name) == "" {
		spec.Name = "BagIt deliverable"
	}
	selection, err := s.caseRef.Selection(ctx, spec.Selection)
	if err != nil {
		return Deliverable{}, err
	}
	closureMembers, err := s.caseRef.resolveClosure(ctx, selection, spec.Closure)
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
	spec.Destination = dest
	excluded := map[string]string{}
	for _, exclusion := range spec.Exclusions {
		if exclusion.Entity.ID == "" || strings.TrimSpace(exclusion.Reason) == "" || excluded[exclusion.Entity.ID] != "" {
			return Deliverable{}, fmt.Errorf("%w: exclusions require unique entity IDs and reasons", ErrInvalid)
		}
		excluded[exclusion.Entity.ID] = exclusion.Reason
	}
	foundExclusions := map[string]bool{}
	members := make([]DeliverableMember, 0, len(closureMembers))
	for _, closureMember := range closureMembers {
		member := DeliverableMember{Entity: closureMember.Ref, Reason: closureMember.Reason}
		if reason := excluded[closureMember.Ref.ID]; reason != "" {
			member.Disposition = "excluded"
			member.Reason = reason
			foundExclusions[closureMember.Ref.ID] = true
		} else if closureMember.Ref.Kind == EntityObject || closureMember.Ref.Kind == EntityManifest {
			member.Disposition = "included"
		} else {
			member.Disposition = "excluded"
			member.Reason = "BagIt payload contains byte-bearing objects only"
		}
		members = append(members, member)
	}
	for id := range excluded {
		if !foundExclusions[id] {
			return Deliverable{}, fmt.Errorf("%w: excluded entity %s is not in resolved closure", ErrInvalid, id)
		}
	}
	requestFingerprint, specJSON, err := digestJSON(struct {
		Spec              BagItSpec
		SelectionRevision int64
		Members           []DeliverableMember
	}{spec, selection.Revision, members})
	if err != nil {
		return Deliverable{}, err
	}
	if spec.IdempotencyKey != "" {
		tx, beginErr := s.caseRef.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if beginErr != nil {
			return Deliverable{}, mapSQLError(beginErr)
		}
		var old Deliverable
		found, lookupErr := lookupIdempotency(ctx, tx, string(s.ID()), "deliverable.package", spec.IdempotencyKey, requestFingerprint, &old)
		_ = tx.Rollback()
		if lookupErr != nil {
			return Deliverable{}, lookupErr
		}
		if found {
			return old, nil
		}
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
	for i := range members {
		member := &members[i]
		if member.Disposition != "included" {
			continue
		}
		obj, er := s.caseRef.objectByEntity(ctx, member.Entity.ID)
		if er != nil {
			return Deliverable{}, er
		}
		rel := "data/" + sanitizeComponent(member.Entity.ID) + "/" + sanitizeComponent(obj.DisplayName)
		full := filepath.Join(partial, filepath.FromSlash(rel))
		if er = os.MkdirAll(filepath.Dir(full), 0700); er != nil {
			return Deliverable{}, er
		}
		if er = copyFileContext(ctx, s.caseRef.blobPath(obj.Blob), full); er != nil {
			return Deliverable{}, er
		}
		payload[rel] = strings.TrimPrefix(string(obj.Blob), "sha256:")
		member.EmittedPath = rel
		member.Blob = obj.Blob
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
	verification, er := VerifyBagIt(ctx, partial)
	if er != nil || !verification.OK {
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
	result := Deliverable{ID: did, Selection: spec.Selection, Path: dest, SHA256: packageDigest, Format: "bagit-1.0", Closure: spec.Closure, Manifest: ObjectRef{ID: oid, Blob: staged.ref, Size: staged.size, DisplayName: "manifest-sha256.txt", MediaType: "text/plain", Path: "manifest-sha256.txt", GeneratingActivity: aid}, Members: members, Recipient: spec.Recipient, Purpose: spec.Purpose, RedactionPolicy: spec.RedactionPolicy, Version: spec.Version, Predecessor: spec.Predecessor}
	_, err = s.caseRef.mutate(ctx, s.info.Agent.ID, s.ID(), "deliverable.package", requestFingerprint, []string{string(did), string(oid)}, func(tx *sql.Tx, rev int64) error {
		if spec.IdempotencyKey != "" {
			var old Deliverable
			found, lookupErr := lookupIdempotency(ctx, tx, string(s.ID()), "deliverable.package", spec.IdempotencyKey, requestFingerprint, &old)
			if lookupErr != nil {
				return lookupErr
			}
			if found {
				result = old
				return errIdempotentReplay
			}
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		out, _ := canonicalJSON(OutcomeSucceeded())
		if spec.Predecessor != "" {
			var predecessorCount int
			if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM deliverables WHERE id=?", spec.Predecessor).Scan(&predecessorCount); e != nil {
				return e
			} else if predecessorCount != 1 {
				return ErrNotFound
			}
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activities(id,session_id,agent_id,type,label,config_json,config_digest,capture_mode,state,inputs_sealed,sealed_revision,started_at,finished_at,outcome_json,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)", aid, s.ID(), s.info.Agent.ID, ActivityDeliverablePackage, "Package BagIt deliverable", string(specJSON), requestFingerprint, CaptureLibrary, ActivitySucceeded, rev, now, now, string(out), spec.IdempotencyKey); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_agents(activity_id,agent_id,role) VALUES(?,?,'exporter')", aid, s.info.Agent.ID); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'selection')", aid, spec.Selection); e != nil {
			return e
		}
		for _, member := range members {
			if _, e := tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,?)", aid, member.Entity.ID, member.Disposition); e != nil {
				return e
			}
		}
		if spec.Predecessor != "" {
			if _, e := tx.ExecContext(ctx, "INSERT INTO activity_inputs(activity_id,entity_id,role) VALUES(?,?,'predecessor')", aid, spec.Predecessor); e != nil {
				return e
			}
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
		verificationJSON, _ := canonicalJSON(verification)
		if _, e := tx.ExecContext(ctx, "INSERT INTO deliverables(id,selection_id,path_hint,package_sha256,format,closure,manifest_object_id,spec_json,version,predecessor_id,recipient,purpose,redaction_policy,verification_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", did, spec.Selection, dest, packageDigest, result.Format, spec.Closure, oid, string(specJSON), spec.Version, nullString(string(spec.Predecessor)), spec.Recipient, spec.Purpose, spec.RedactionPolicy, string(verificationJSON)); e != nil {
			return e
		}
		for i, member := range members {
			if _, e := tx.ExecContext(ctx, "INSERT INTO deliverable_members(deliverable_id,ordinal,entity_id,kind,disposition,reason,emitted_path,blob_digest) VALUES(?,?,?,?,?,?,?,?)", did, i, member.Entity.ID, member.Entity.Kind, member.Disposition, member.Reason, member.EmittedPath, nullString(string(member.Blob))); e != nil {
				return e
			}
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO activity_outputs(activity_id,entity_id,role) VALUES(?,?,'manifest'),(?,?,'deliverable')", aid, oid, aid, did); e != nil {
			return e
		}
		result.CreatedRevision = rev
		result.Manifest.CreatedRevision = rev
		return storeIdempotency(ctx, tx, string(s.ID()), "deliverable.package", spec.IdempotencyKey, requestFingerprint, result)
	})
	return result, err
}

// Deliverable loads immutable package provenance and its included/excluded
// member decisions. External bytes remain non-authoritative and are verified
// with the format-specific verifier.
func (c *Case) Deliverable(ctx context.Context, id DeliverableID) (Deliverable, error) {
	if err := c.checkOpen(); err != nil {
		return Deliverable{}, err
	}
	var deliverable Deliverable
	var manifestID sql.NullString
	var predecessor sql.NullString
	err := c.db.QueryRowContext(ctx, `SELECT d.id,COALESCE(d.selection_id,''),d.path_hint,d.package_sha256,d.format,d.closure,d.manifest_object_id,d.version,d.predecessor_id,d.recipient,d.purpose,d.redaction_policy,e.created_revision FROM deliverables d JOIN entities e ON e.id=d.id WHERE d.id=?`, id).Scan(&deliverable.ID, &deliverable.Selection, &deliverable.Path, &deliverable.SHA256, &deliverable.Format, &deliverable.Closure, &manifestID, &deliverable.Version, &predecessor, &deliverable.Recipient, &deliverable.Purpose, &deliverable.RedactionPolicy, &deliverable.CreatedRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return Deliverable{}, ErrNotFound
	}
	if err != nil {
		return Deliverable{}, mapSQLError(err)
	}
	deliverable.Predecessor = DeliverableID(predecessor.String)
	if manifestID.Valid {
		deliverable.Manifest, err = c.objectByEntity(ctx, manifestID.String)
		if err != nil {
			return Deliverable{}, err
		}
	}
	rows, err := c.db.QueryContext(ctx, "SELECT entity_id,kind,disposition,reason,emitted_path,COALESCE(blob_digest,'') FROM deliverable_members WHERE deliverable_id=? ORDER BY ordinal", id)
	if err != nil {
		return Deliverable{}, mapSQLError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var member DeliverableMember
		if err = rows.Scan(&member.Entity.ID, &member.Entity.Kind, &member.Disposition, &member.Reason, &member.EmittedPath, &member.Blob); err != nil {
			return Deliverable{}, err
		}
		deliverable.Members = append(deliverable.Members, member)
	}
	return deliverable, rows.Err()
}
