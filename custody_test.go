package forensic

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestActivityAttributionAndCustodyHistory(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	from, err := c.RegisterAgent(ctx, AgentSpec{Kind: AgentHuman, Name: "intake operator"})
	if err != nil {
		t.Fatal(err)
	}
	to, err := c.RegisterAgent(ctx, AgentSpec{Kind: AgentOrganization, Name: "analysis lab"})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := c.ImportEvidence(ctx, "device.img", EvidenceSpec{Label: "device image", Acquisition: AcquisitionSpec{Method: "write-blocked-copy"}}, strings.NewReader("evidence bytes"))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "custody and execution"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)

	reportedStart := time.Date(2026, 7, 23, 9, 30, 0, 0, time.FixedZone("source", 3600))
	reportedEnd := reportedStart.Add(5 * time.Minute)
	parent, err := session.BeginActivity(ctx, ActivitySpec{
		Type: ActivityExperiment, Label: "external examination",
		Agents: []ActivityAgent{{Agent: to.ID, Role: "reviewer"}},
		Execution: &ExecutionDescriptor{
			Command: "examiner", Arguments: []string{"--read-only"},
			Environment: map[string]string{"LANG": "C"}, Runtime: "test-runtime", Sandbox: "read-only",
		},
		ReportedStartedAt: &reportedStart, ReportedFinishedAt: &reportedEnd,
		TimeSource: "operator log", IdempotencyKey: "external-examination-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = parent.Use(ctx, evidence.RootObject, "source"); err != nil {
		t.Fatal(err)
	}
	if err = parent.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}
	loadedActivity, err := c.Activity(ctx, parent.ID())
	if err != nil {
		t.Fatal(err)
	}
	if loadedActivity.Execution == nil || loadedActivity.Execution.Command != "examiner" || loadedActivity.TimeSource != "operator log" {
		t.Fatalf("execution metadata did not round trip: %#v", loadedActivity)
	}
	if loadedActivity.ReportedStartedAt == nil || !loadedActivity.ReportedStartedAt.Equal(reportedStart) || loadedActivity.ReportedFinishedAt == nil || !loadedActivity.ReportedFinishedAt.Equal(reportedEnd) {
		t.Fatalf("reported times did not round trip: %#v", loadedActivity)
	}
	roles := map[string]AgentID{}
	for _, associated := range loadedActivity.Agents {
		roles[associated.Role] = associated.Agent
	}
	if roles["reviewer"] != to.ID || roles["operator"] == "" {
		t.Fatalf("activity attribution = %#v", loadedActivity.Agents)
	}

	child, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityParse, Label: "child analysis", Parent: parent.ID()})
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}
	loadedChild, err := c.Activity(ctx, child.ID())
	if err != nil || loadedChild.Parent != parent.ID() {
		t.Fatalf("parent activity did not round trip: %#v %v", loadedChild, err)
	}

	occurred := time.Date(2026, 7, 23, 8, 15, 0, 0, time.FixedZone("source", 3600))
	spec := CustodyTransferSpec{
		Item: evidence.EntityRef(), FromAgent: from.ID, ToAgent: to.ID,
		FromLocation: "intake", ToLocation: "evidence vault", Purpose: "analysis",
		ReferenceNumber: "TEST-001", OccurredAt: occurred,
		Acknowledgement: map[string]any{"accepted": true}, Signature: []byte("test-signature"),
		IdempotencyKey: "custody-transfer-v1",
	}
	event, err := session.RecordCustodyTransfer(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if event.Activity == "" || event.CreatedRevision == 0 || !event.OccurredAt.Equal(occurred) {
		t.Fatalf("incomplete custody event: %#v", event)
	}
	history, err := c.CustodyEvents(ctx, evidence.EntityRef())
	if err != nil || len(history) != 1 || history[0].Activity != event.Activity || history[0].ToAgent != to.ID {
		t.Fatalf("custody history: %#v %v", history, err)
	}
	custodyActivity, err := c.Activity(ctx, event.Activity)
	if err != nil || custodyActivity.Type != ActivityCustodyTransfer || custodyActivity.CaptureMode != CaptureReported {
		t.Fatalf("custody activity: %#v %v", custodyActivity, err)
	}

	beforeReplay, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := session.RecordCustodyTransfer(ctx, spec)
	if err != nil || repeated.Activity != event.Activity {
		t.Fatalf("idempotent custody replay: %#v %v", repeated, err)
	}
	afterReplay, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterReplay.Revision != beforeReplay.Revision {
		t.Fatalf("idempotent custody replay advanced revision from %d to %d", beforeReplay.Revision, afterReplay.Revision)
	}
	spec.Purpose = "changed purpose"
	if _, err = session.RecordCustodyTransfer(ctx, spec); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed custody replay = %v, want conflict", err)
	}
}
