package forensic

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestSourceTreeImportQueryAndVerification(t *testing.T) {
	ctx, base, repo, c := openTestRepo(t)
	root := filepath.Join(base, "source")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "alpha.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "beta.bin"), []byte{0, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "ignored"), []byte("not evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkCreated := os.Symlink("alpha.txt", filepath.Join(root, "alpha-link")) == nil

	spec := SourceTreeSpec{
		Label:          "source sample",
		Acquisition:    AcquisitionSpec{Method: "test-copy"},
		IdempotencyKey: "source-sample-v1",
	}
	tree, err := c.ImportSourceTree(ctx, root, spec)
	if err != nil {
		t.Fatal(err)
	}
	if tree.FileCount != 2 || tree.TotalBytes != 9 {
		t.Fatalf("tree counts = %d files, %d bytes", tree.FileCount, tree.TotalBytes)
	}
	if tree.Manifest.ID == "" || tree.TreeDigest == "" || tree.CreatedRevision == 0 {
		t.Fatalf("incomplete tree identity: %#v", tree)
	}

	paths := make([]string, 0, len(tree.Entries))
	fileObjects := map[string]ObjectRef{}
	for _, entry := range tree.Entries {
		paths = append(paths, entry.Path)
		if entry.Path == ".git" || strings.HasPrefix(entry.Path, ".git/") {
			t.Fatalf("excluded .git entry was imported: %q", entry.Path)
		}
		switch entry.Kind {
		case TreeEntryFile:
			if entry.Object == nil || entry.SHA256 == "" {
				t.Fatalf("file entry lacks managed object: %#v", entry)
			}
			fileObjects[entry.Path] = *entry.Object
		case TreeEntryDirectory, TreeEntrySymlink:
			if entry.Object != nil {
				t.Fatalf("non-file entry has an object: %#v", entry)
			}
		default:
			t.Fatalf("unexpected entry kind: %#v", entry)
		}
	}
	if !sort.StringsAreSorted(paths) {
		t.Fatalf("entries are not canonical: %v", paths)
	}
	if symlinkCreated {
		found := false
		for _, entry := range tree.Entries {
			if entry.Path == "alpha-link" && entry.Kind == TreeEntrySymlink && entry.LinkTarget == "alpha.txt" {
				found = true
			}
		}
		if !found {
			t.Fatal("symlink metadata was not retained")
		}
	}

	wantBytes := map[string]string{"alpha.txt": "alpha", "sub/beta.bin": string([]byte{0, 1, 2, 3})}
	for path, object := range fileObjects {
		r, openErr := c.OpenObject(ctx, object.ID)
		if openErr != nil {
			t.Fatal(openErr)
		}
		got, readErr := io.ReadAll(io.NewSectionReader(r, 0, object.Size))
		var closeErr error
		if closer, ok := r.(io.Closer); ok {
			closeErr = closer.Close()
		}
		if readErr != nil || closeErr != nil {
			t.Fatalf("read %s: %v / %v", path, readErr, closeErr)
		}
		if string(got) != wantBytes[path] {
			t.Fatalf("%s bytes = %q", path, got)
		}
	}

	repeated, err := c.ImportSourceTree(ctx, root, spec)
	if err != nil || repeated.ID != tree.ID || repeated.TreeDigest != tree.TreeDigest {
		t.Fatalf("idempotent import mismatch: %#v %v", repeated, err)
	}
	loaded, err := c.SourceTree(ctx, tree.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TreeDigest != tree.TreeDigest || loaded.FileCount != tree.FileCount || len(loaded.Entries) != len(tree.Entries) {
		t.Fatalf("loaded tree mismatch: %#v", loaded)
	}

	result, err := c.Query(ctx, InTree(tree.ID))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entities) != tree.FileCount+2 {
		t.Fatalf("tree query returned %d entities, want %d", len(result.Entities), tree.FileCount+2)
	}

	if report, verifyErr := c.Verify(ctx, VerifySpec{Mode: VerifyFull}); verifyErr != nil || !report.OK {
		t.Fatalf("full verify: %#v %v", report, verifyErr)
	}
	if _, err = c.ImportSourceTree(ctx, repo.Root(), SourceTreeSpec{Label: "overlap"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("repository overlap = %v, want invalid", err)
	}

	if symlinkCreated {
		rootLink := filepath.Join(base, "source-link")
		if err = os.Symlink(root, rootLink); err == nil {
			if _, err = c.ImportSourceTree(ctx, rootLink, SourceTreeSpec{Label: "linked root"}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("symlink root = %v, want invalid", err)
			}
		}
	}
}
