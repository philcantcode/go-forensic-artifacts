package forensic

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestImportFaultBoundariesNeverCommitMissingBytes(t *testing.T) {
	points := []string{"after-stage-create", "after-stage-copy", "after-stage-sync", "after-blob-publish", "before-catalog-commit", "after-catalog-commit"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			ctx := context.Background()
			base := t.TempDir()
			repo, err := Open(ctx, Config{Root: filepath.Join(base, "repo")})
			if err != nil {
				t.Fatal(err)
			}
			c, err := repo.CreateCase(ctx, CaseSpec{Name: "fault case"})
			if err != nil {
				t.Fatal(err)
			}
			triggered := false
			c.fault = func(got string) error {
				if got == point && !triggered {
					triggered = true
					return fmt.Errorf("injected at %s", point)
				}
				return nil
			}
			_, importErr := c.ImportEvidence(ctx, "input.bin", EvidenceSpec{Label: "fault input", Acquisition: AcquisitionSpec{Method: "test"}}, bytes.NewReader([]byte("fault boundary bytes")))
			c.fault = nil
			if importErr == nil {
				t.Fatalf("fault %s did not trigger", point)
			}
			if !triggered {
				t.Fatalf("fault %s was not reached", point)
			}
			caseID := c.ID()
			_ = c.Close()
			_ = repo.Close()
			repo, err = Open(ctx, Config{Root: filepath.Join(base, "repo")})
			if err != nil {
				t.Fatal(err)
			}
			defer repo.Close()
			c, err = repo.OpenCase(ctx, ByID(caseID))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			report, err := c.Verify(ctx, VerifySpec{Mode: VerifyQuick})
			if err != nil || !report.OK {
				t.Fatalf("quick verify after %s: %#v %v", point, report, err)
			}
			result, err := c.Query(ctx, KindIs(EntityObject))
			if err != nil {
				t.Fatal(err)
			}
			if point == "after-catalog-commit" {
				if len(result.Entities) != 1 {
					t.Fatalf("committed objects=%d", len(result.Entities))
				}
				full, err := c.Verify(ctx, VerifySpec{Mode: VerifyFull})
				if err != nil || !full.OK {
					t.Fatalf("committed fault verify: %#v %v", full, err)
				}
			} else if len(result.Entities) != 0 {
				t.Fatalf("uncommitted objects=%d", len(result.Entities))
			}
			for _, issue := range report.Issues {
				if issue.Code == "missing-blob" {
					t.Fatalf("committed object points to missing bytes after %s", point)
				}
			}
		})
	}
}

func TestContextCancellationDuringImport(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err := c.ImportEvidence(cancelled, "cancel.bin", EvidenceSpec{Label: "cancel", Acquisition: AcquisitionSpec{Method: "test"}}, bytes.NewReader(make([]byte, 1024)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled import=%v", err)
	}
}
