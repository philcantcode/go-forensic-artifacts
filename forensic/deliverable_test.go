package forensic

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

func TestBagItDeliverableRecordsPolicyMembershipAndLineage(t *testing.T) {
	ctx, base, _, c := openTestRepo(t)
	first, err := c.ImportEvidence(ctx, "first.bin", EvidenceSpec{Label: "first"}, bytes.NewReader([]byte("first payload")))
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.ImportEvidence(ctx, "second.bin", EvidenceSpec{Label: "second"}, bytes.NewReader([]byte("second payload")))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "delivery"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	parse, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityParse, Label: "parse first"})
	if err != nil {
		t.Fatal(err)
	}
	if err = parse.Use(ctx, first.RootObject, "source"); err != nil {
		t.Fatal(err)
	}
	artifact, err := parse.EmitArtifact(ctx, "summary", ArtifactDraft{Type: "urn:test:summary/v1", Source: first.RootObject.ID, Values: []ArtifactValue{{Property: "summary", Type: ValueString, Raw: "not a byte payload"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = parse.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}
	selection, err := session.Freeze(ctx, FreezeSpec{Name: "delivery candidates", Query: Or(IDIs(string(first.RootObject.ID)), IDIs(string(second.RootObject.ID)), IDIs(string(artifact.ID)))})
	if err != nil {
		t.Fatal(err)
	}
	spec := BagItSpec{
		Selection: selection.ID, Destination: filepath.Join(base, "delivery-v1"), Name: "review package",
		Closure: ClosureExact, Exclusions: []DeliverableExclusion{{Entity: second.RootObject.EntityRef(), Reason: "customer requested omission"}},
		RedactionPolicy: "only pre-redacted objects may be selected", Recipient: "vendor security team", Purpose: "coordinated disclosure", Version: "1.0", IdempotencyKey: "delivery-v1",
	}
	deliverable, err := session.ExportBagIt(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if deliverable.Format != "bagit-1.0" || deliverable.Manifest.ID == "" || deliverable.Recipient != spec.Recipient || deliverable.Purpose != spec.Purpose || len(deliverable.Members) != 3 {
		t.Fatalf("incomplete deliverable record: %#v", deliverable)
	}
	report, err := VerifyBagIt(ctx, deliverable.Path)
	if err != nil || !report.OK || report.PayloadFiles != 1 {
		t.Fatalf("BagIt verification: %#v %v", report, err)
	}
	loaded, err := c.Deliverable(ctx, deliverable.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Manifest.ID != deliverable.Manifest.ID || loaded.RedactionPolicy != spec.RedactionPolicy || len(loaded.Members) != 3 {
		t.Fatalf("deliverable round trip: %#v", loaded)
	}
	dispositions := map[string]DeliverableMember{}
	for _, member := range loaded.Members {
		dispositions[member.Entity.ID] = member
	}
	if dispositions[string(first.RootObject.ID)].Disposition != "included" || dispositions[string(first.RootObject.ID)].EmittedPath == "" || dispositions[string(first.RootObject.ID)].Blob == "" {
		t.Fatalf("included object decision missing: %#v", dispositions[string(first.RootObject.ID)])
	}
	if dispositions[string(second.RootObject.ID)].Disposition != "excluded" || dispositions[string(second.RootObject.ID)].Reason != "customer requested omission" {
		t.Fatalf("explicit exclusion missing: %#v", dispositions[string(second.RootObject.ID)])
	}
	if dispositions[string(artifact.ID)].Disposition != "excluded" {
		t.Fatalf("non-byte exclusion missing: %#v", dispositions[string(artifact.ID)])
	}
	beforeReplay, _ := c.Info(ctx)
	replayed, err := session.ExportBagIt(ctx, spec)
	if err != nil || replayed.ID != deliverable.ID {
		t.Fatalf("deliverable idempotency: %#v %v", replayed, err)
	}
	afterReplay, _ := c.Info(ctx)
	if afterReplay.Revision != beforeReplay.Revision {
		t.Fatal("deliverable replay advanced case revision")
	}
	changed := spec
	changed.Recipient = "different recipient"
	if _, err = session.ExportBagIt(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed recipient reused idempotency key: %v", err)
	}

	secondSpec := spec
	secondSpec.Destination = filepath.Join(base, "delivery-v2")
	secondSpec.Version = "2.0"
	secondSpec.Predecessor = deliverable.ID
	secondSpec.IdempotencyKey = "delivery-v2"
	successor, err := session.ExportBagIt(ctx, secondSpec)
	if err != nil {
		t.Fatal(err)
	}
	loadedSuccessor, err := c.Deliverable(ctx, successor.ID)
	if err != nil || loadedSuccessor.Predecessor != deliverable.ID {
		t.Fatalf("deliverable predecessor lineage: %#v %v", loadedSuccessor, err)
	}
	trace, err := c.Trace(ctx, loadedSuccessor)
	if err != nil {
		t.Fatal(err)
	}
	foundPredecessor := false
	foundOriginal := false
	for _, entity := range trace.Entities {
		foundPredecessor = foundPredecessor || entity.ID == string(deliverable.ID)
		foundOriginal = foundOriginal || entity.ID == string(first.RootObject.ID)
	}
	if !foundPredecessor || !foundOriginal {
		t.Fatalf("deliverable trace omitted lineage: %#v", trace.Entities)
	}
}
