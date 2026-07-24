package forensic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerificationDetectsSemanticCatalogTampering(t *testing.T) {
	ctx, base, _, c := openTestRepo(t)
	content := []byte("original bytes")
	digest := sha256.Sum256(content)
	evidence, err := c.ImportEvidence(ctx, "original.bin", EvidenceSpec{Label: "original", Acquisition: AcquisitionSpec{Method: "test", SuppliedHashes: map[string]string{"sha256": hex.EncodeToString(digest[:])}}}, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "semantic-tree")
	if err = os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tree, err := c.ImportSourceTree(ctx, root, SourceTreeSpec{Label: "semantic tree"})
	if err != nil {
		t.Fatal(err)
	}
	if report, verifyErr := c.Verify(ctx, VerifySpec{Mode: VerifyFull}); verifyErr != nil || !report.OK {
		t.Fatalf("clean semantic verification: %#v %v", report, verifyErr)
	}

	if _, err = c.db.ExecContext(ctx, "UPDATE source_trees SET file_count=file_count+1 WHERE id=?", tree.ID); err != nil {
		t.Fatal(err)
	}
	report, err := c.Verify(ctx, VerifySpec{Mode: VerifyQuick})
	if err != nil || report.OK || !hasVerifyIssue(report, "source-tree-summary") {
		t.Fatalf("source-tree summary tampering not detected: %#v %v", report, err)
	}
	if _, err = c.db.ExecContext(ctx, "UPDATE source_trees SET file_count=file_count-1 WHERE id=?", tree.ID); err != nil {
		t.Fatal(err)
	}

	// Use a syntactically valid but incorrect lowercase digest.
	badAcquisition := `{"method":"test","supplied_hashes":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`
	if _, err = c.db.ExecContext(ctx, "UPDATE evidence SET acquisition_json=? WHERE id=?", badAcquisition, evidence.ID); err != nil {
		t.Fatal(err)
	}
	report, err = c.Verify(ctx, VerifySpec{Mode: VerifyOriginals})
	if err != nil || report.OK || !hasVerifyIssue(report, "supplied-hash") {
		t.Fatalf("supplied acquisition hash tampering not detected: %#v %v", report, err)
	}

	acquisition, _ := canonicalJSON(evidence.Acquisition)
	if _, err = c.db.ExecContext(ctx, "UPDATE evidence SET acquisition_json=? WHERE id=?", string(acquisition), evidence.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.db.ExecContext(ctx, "DELETE FROM activity_outputs WHERE entity_id=?", evidence.RootObject.ID); err != nil {
		t.Fatal(err)
	}
	report, err = c.Verify(ctx, VerifySpec{Mode: VerifyQuick})
	if err != nil || report.OK || !hasVerifyIssue(report, "missing-generation-edge") {
		t.Fatalf("generation-edge tampering not detected: %#v %v", report, err)
	}
}

func hasVerifyIssue(report VerifyReport, code string) bool {
	for _, issue := range report.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
