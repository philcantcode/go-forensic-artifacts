package forensic

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestExternalExecutionProvenanceAndActivityIdempotency(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "service.bin", EvidenceSpec{Label: "service"}, bytes.NewReader([]byte("binary")))
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := c.RegisterAgent(ctx, AgentSpec{Kind: AgentHuman, Name: "reviewer-account"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "reported experiment"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	reportedStart := time.Date(2026, 7, 23, 12, 0, 0, 0, time.FixedZone("lab", 3600))
	reportedEnd := reportedStart.Add(8 * time.Second)
	spec := ActivitySpec{
		Type: ActivityExperiment, Label: "Reproduce malformed request", CaptureMode: CaptureReported,
		Tool:   &ToolDescriptor{Name: "harness", Version: "1.4", BuildDigest: "sha256:tool"},
		Config: map[string]any{"seed": 7, "protocol": "http"}, Agents: []ActivityAgent{{Agent: reviewer.ID, Role: "reviewer"}},
		Execution:         &ExecutionDescriptor{Command: "./harness", Arguments: []string{"--seed", "7"}, WorkingDirectory: "/work/input", Environment: map[string]string{"MODE": "asan"}, EnvironmentDigests: map[string]string{"API_TOKEN": "sha256:redacted"}, Runtime: "process", ContainerImage: "sha256:image", Sandbox: "caller-managed", Host: "lab-7"},
		ReportedStartedAt: &reportedStart, ReportedFinishedAt: &reportedEnd, TimeSource: "agent report", IdempotencyKey: "experiment-v1",
	}
	run, err := session.BeginActivity(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	beforeReplay, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := session.BeginActivity(ctx, spec)
	if err != nil || replayed.ID() != run.ID() {
		t.Fatalf("activity replay mismatch: %s %v", replayed.ID(), err)
	}
	afterReplay, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterReplay.Revision != beforeReplay.Revision {
		t.Fatal("idempotent activity begin advanced the revision")
	}
	changed := spec
	changed.Execution = &ExecutionDescriptor{Command: "./different-harness"}
	if _, err = session.BeginActivity(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed execution reused idempotency key: %v", err)
	}
	if err = run.Use(ctx, evidence.RootObject, "target"); err != nil {
		t.Fatal(err)
	}
	crash, err := run.Capture(ctx, ObjectSpec{Role: "crash-log", DisplayName: "crash.log", MediaType: "text/plain", Source: PathLocator{Display: "output/crash.log", Separator: "/"}}, bytes.NewReader([]byte("AddressSanitizer: crash")))
	if err != nil {
		t.Fatal(err)
	}
	if err = run.Finish(ctx, Outcome{State: ActivityFailed, Summary: "target crashed as expected", ExitCode: intPointer(1)}); err != nil {
		t.Fatal(err)
	}
	activity, err := c.Activity(ctx, run.ID())
	if err != nil {
		t.Fatal(err)
	}
	if activity.Execution == nil || activity.Execution.Command != "./harness" || activity.Execution.Environment["MODE"] != "asan" || activity.ReportedStartedAt == nil || !activity.ReportedStartedAt.Equal(reportedStart) || activity.TimeSource != "agent report" || activity.ConfigDigest == "" || activity.State != ActivityFailed {
		t.Fatalf("external execution provenance did not round trip: %#v", activity)
	}
	foundReviewer := false
	for _, associated := range activity.Agents {
		foundReviewer = foundReviewer || associated.Agent == reviewer.ID && associated.Role == "reviewer"
	}
	if !foundReviewer {
		t.Fatalf("associated reviewer missing: %#v", activity.Agents)
	}
	trace, err := c.Trace(ctx, crash)
	if err != nil || len(trace.Activities) == 0 {
		t.Fatalf("crash provenance: %#v %v", trace, err)
	}
}

func TestCustodyTransferIsAnEventNotDerivation(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "device-export.bin", EvidenceSpec{Label: "device export"}, bytes.NewReader([]byte("export")))
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := c.RegisterAgent(ctx, AgentSpec{Kind: AgentHuman, Name: "forensic examiner"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "custody log"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	beforeEntities, err := c.Query(ctx, All())
	if err != nil {
		t.Fatal(err)
	}
	occurred := time.Date(2026, 7, 23, 9, 30, 0, 0, time.FixedZone("BST", 3600))
	spec := CustodyTransferSpec{Item: evidence.EntityRef(), FromAgent: c.defaultAgent.ID, ToAgent: recipient.ID, FromLocation: "intake safe", ToLocation: "analysis lab", Purpose: "vulnerability analysis", ReferenceNumber: "COC-2026-0042", OccurredAt: occurred, Acknowledgement: map[string]any{"accepted": true, "method": "signed receipt"}, Signature: []byte("detached-signature"), IdempotencyKey: "custody-42"}
	event, err := session.RecordCustodyTransfer(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	afterEntities, err := c.Query(ctx, All())
	if err != nil {
		t.Fatal(err)
	}
	if len(afterEntities.Entities) != len(beforeEntities.Entities) {
		t.Fatalf("custody transfer generated a replacement entity: before=%d after=%d", len(beforeEntities.Entities), len(afterEntities.Entities))
	}
	history, err := c.CustodyEvents(ctx, evidence.EntityRef())
	if err != nil || len(history) != 1 {
		t.Fatalf("custody history: %#v %v", history, err)
	}
	if history[0].Activity != event.Activity || history[0].ToAgent != recipient.ID || history[0].ReferenceNumber != spec.ReferenceNumber || !bytes.Equal(history[0].Signature, spec.Signature) || !history[0].OccurredAt.Equal(occurred) {
		t.Fatalf("custody event did not round trip: %#v", history[0])
	}
	beforeReplay, _ := c.Info(ctx)
	repeated, err := session.RecordCustodyTransfer(ctx, spec)
	if err != nil || repeated.Activity != event.Activity {
		t.Fatalf("custody replay mismatch: %#v %v", repeated, err)
	}
	afterReplay, _ := c.Info(ctx)
	if afterReplay.Revision != beforeReplay.Revision {
		t.Fatal("idempotent custody replay advanced the revision")
	}
	activity, err := c.Activity(ctx, event.Activity)
	if err != nil || activity.Type != ActivityCustodyTransfer || activity.CaptureMode != CaptureReported {
		t.Fatalf("custody activity: %#v %v", activity, err)
	}
	report, err := c.Verify(ctx, VerifySpec{Mode: VerifyFull})
	if err != nil || !report.OK {
		t.Fatalf("verification after custody event: %#v %v", report, err)
	}
}

func intPointer(value int) *int { return &value }
