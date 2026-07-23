package forensic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSymlinkImportAndBagTraversalAreRejected(t *testing.T) {
	ctx, base, _, c := openTestRepo(t)
	target := filepath.Join(base, "target.bin")
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := c.ImportEvidenceFile(ctx, link, EvidenceSpec{Label: "link", Acquisition: AcquisitionSpec{Method: "test"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink import = %v", err)
	}
	bag := filepath.Join(base, "unsafe-bag")
	if err := os.MkdirAll(filepath.Join(bag, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"bagit.txt": "BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n", "manifest-sha256.txt": strings.Repeat("0", 64) + "  data/../../escape\n", "tagmanifest-sha256.txt": ""}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(bag, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := VerifyBagIt(context.Background(), bag)
	if err != nil || report.OK {
		t.Fatalf("unsafe BagIt accepted: %#v %v", report, err)
	}
}
