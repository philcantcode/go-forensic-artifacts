package forensic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrappedRunnerHelperProcess(t *testing.T) {
	if os.Getenv("FORENSIC_RUNNER_HELPER") != "1" {
		return
	}
	if err := os.WriteFile(filepath.Join("output", "result.txt"), []byte("derived-result\n"), 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Fprint(os.Stdout, "runner standard output")
	fmt.Fprint(os.Stderr, "runner standard error")
}

func runnerHelperArguments() []string {
	args := []string{"-test.run=^TestWrappedRunnerHelperProcess$"}
	// A coverage-instrumented test binary exits with status 2 unless its child
	// process receives the temporary coverage directory selected by `go test`.
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-test.gocoverdir=") {
			args = append(args, arg)
		}
	}
	return args
}

func TestRunExperimentCapturesDeclaredOutputsAndLogs(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "input.txt", EvidenceSpec{Label: "input"}, bytes.NewReader([]byte("immutable input")))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "wrapped execution"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	selection, err := session.Freeze(ctx, FreezeSpec{Name: "runner input", Query: IDIs(string(evidence.RootObject.ID))})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := session.CreateProjection(ctx, ProjectionSpec{Selection: selection.ID, Include: IncludeBytes | IncludeMetadata})
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.RunExperiment(ctx, RunSpec{
		Projection:  projection.ID,
		Command:     os.Args[0],
		Arguments:   runnerHelperArguments(),
		Environment: map[string]string{"FORENSIC_RUNNER_HELPER": "1"},
		OutputPaths: []string{"result.txt"},
		MaxLogBytes: 12,
		Tool:        &ToolDescriptor{Name: "test-helper", Version: "1"},
		Sandbox:     "test-process",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome.State != ActivitySucceeded || len(result.Outputs) != 1 || !result.LogsTruncated || !result.InputCheck.OK {
		t.Fatalf("unexpected wrapped result: %#v", result)
	}
	activity, err := c.Activity(ctx, result.Activity)
	if err != nil {
		t.Fatal(err)
	}
	if activity.CaptureMode != CaptureWrapped || activity.Execution == nil || activity.Execution.Command != os.Args[0] || activity.State != ActivitySucceeded {
		t.Fatalf("wrapped execution provenance missing: %#v", activity)
	}
	reader, err := c.OpenObject(ctx, result.Outputs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := reader.(io.Closer); ok {
		defer closer.Close()
	}
	body := make([]byte, reader.Size())
	if _, err = reader.ReadAt(body, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(body) != "derived-result\n" {
		t.Fatalf("captured output = %q", body)
	}
	trace, err := c.Trace(ctx, result.Outputs[0].EntityRef())
	if err != nil {
		t.Fatal(err)
	}
	foundProjection := false
	for _, edge := range trace.Edges {
		if edge.Direction == "used" && edge.Entity.ID == string(projection.ID) {
			foundProjection = true
		}
	}
	if !foundProjection {
		t.Fatalf("output trace lacks projection input: %#v", trace)
	}
}

func TestRunExperimentRejectsUnsafeOutputBeforeExecution(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	session, err := c.StartSession(ctx, SessionSpec{Label: "runner validation"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(context.Background())
	if _, err = session.RunExperiment(ctx, RunSpec{Projection: ProjectionID("prj_invalid"), Command: os.Args[0], OutputPaths: []string{"../escape"}}); err == nil {
		t.Fatal("unsafe output path was accepted")
	}
}
