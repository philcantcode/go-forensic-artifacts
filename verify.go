package forensic

import (
	"bufio"
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
	if err = c.db.QueryRowContext(ctx, "SELECT audit_head FROM case_info WHERE singleton=1").Scan(&head); err != nil {
		return err
	}
	if head != prev {
		r.Issues = append(r.Issues, VerifyIssue{Code: "audit-head", Detail: "case audit head does not match chain"})
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
