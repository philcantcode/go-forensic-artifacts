package forensic

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaseRecoveryInspectionAndExplicitInterruption(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "input.bin", EvidenceSpec{Label: "input"}, bytes.NewReader([]byte("managed")))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "interrupted work"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	run, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityExperiment, Label: "stale experiment"})
	if err != nil {
		t.Fatal(err)
	}
	if err = run.Use(ctx, evidence.RootObject, "target"); err != nil {
		t.Fatal(err)
	}
	stagingPath := filepath.Join(c.root, "staging", "ingest", "abandoned.partial")
	if err = os.WriteFile(stagingPath, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	orphanDigest := strings.Repeat("a", 64)
	orphanPath := c.blobPath(BlobRef("sha256:" + orphanDigest))
	if err = os.MkdirAll(filepath.Dir(orphanPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(orphanPath, []byte("orphan"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := c.InspectRecovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.StagingFiles) != 1 || len(report.OrphanBlobs) != 1 || len(report.RunningActivities) != 1 || report.RunningActivities[0].ID != run.ID() {
		t.Fatalf("incomplete recovery report: %#v", report)
	}
	if _, err = os.Stat(stagingPath); err != nil {
		t.Fatalf("read-only recovery inspection removed staging data: %v", err)
	}
	if _, err = os.Stat(orphanPath); err != nil {
		t.Fatalf("read-only recovery inspection removed orphan data: %v", err)
	}
	if err = c.MarkActivitiesInterrupted(ctx, []ActivityID{run.ID()}, "owning worker was confirmed terminated"); err != nil {
		t.Fatal(err)
	}
	activity, err := c.Activity(ctx, run.ID())
	if err != nil || activity.State != ActivityInterrupted || activity.Outcome == nil || !strings.Contains(activity.Outcome.Summary, "confirmed terminated") {
		t.Fatalf("interrupted activity: %#v %v", activity, err)
	}
	if err = run.Finish(ctx, OutcomeSucceeded()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale handle finished recovered activity: %v", err)
	}
	if err = c.MarkActivitiesInterrupted(ctx, []ActivityID{run.ID()}, "again"); !errors.Is(err, ErrConflict) {
		t.Fatalf("terminal activity interruption = %v, want conflict", err)
	}
}

func TestRepositoryRecoveryReregistersSelfDescribingCase(t *testing.T) {
	ctx, _, repo, c := openTestRepo(t)
	caseID := c.ID()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.db.ExecContext(ctx, "DELETE FROM cases WHERE id=?", caseID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.OpenCase(ctx, ByID(caseID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unregistered case opened: %v", err)
	}
	report, err := repo.InspectRecovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Unregistered) != 1 || report.Unregistered[0].ID != caseID || !report.Unregistered[0].Valid || !report.Unregistered[0].CanComplete {
		t.Fatalf("unregistered case was not identified: %#v", report)
	}
	recovered, err := repo.RecoverCaseRegistration(ctx, caseID)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	info, err := recovered.Info(ctx)
	if err != nil || info.ID != caseID || info.Name != "Router firmware" {
		t.Fatalf("recovered case: %#v %v", info, err)
	}
	after, err := repo.InspectRecovery(ctx)
	if err != nil || len(after.Unregistered) != 0 || len(after.Creating) != 0 {
		t.Fatalf("registration recovery did not reconcile repository: %#v %v", after, err)
	}
	verification, err := recovered.Verify(ctx, VerifySpec{Mode: VerifyQuick})
	if err != nil || !verification.OK {
		t.Fatalf("recovered case verification: %#v %v", verification, err)
	}
}
