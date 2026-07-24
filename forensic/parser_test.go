package forensic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

type testParserFactory struct{ created atomic.Int32 }

func (f *testParserFactory) New() Parser {
	f.created.Add(1)
	return &testBatchParser{}
}

type testBatchParser struct{}

func (*testBatchParser) Descriptor() ParserDescriptor {
	return ParserDescriptor{ID: "urn:test:parser:batch", Version: "1.0", BuildDigest: "sha256:test-parser", MediaTypes: []string{"application/octet-stream"}, SchemaVersions: []string{"urn:test:artifact/parser-output/v1"}, Deterministic: true}
}

type countingParser struct{ calls *atomic.Int32 }

func (p *countingParser) Descriptor() ParserDescriptor {
	return ParserDescriptor{ID: "urn:test:parser:cached", Version: "1.0", BuildDigest: "sha256:cached-parser", SchemaVersions: []string{"urn:test:cached/v1"}, Deterministic: true}
}

func (*countingParser) Probe(context.Context, ObjectReader) (ProbeResult, error) {
	return ProbeResult{Supported: true, Confidence: 1}, nil
}

func (p *countingParser) Parse(ctx context.Context, request ParseRequest, sink Sink) error {
	p.calls.Add(1)
	_, err := sink.EmitArtifact(ctx, "only", ArtifactDraft{Type: "urn:test:cached/v1", DisplayName: "cached output", Source: request.Input.ID, Values: []ArtifactValue{{Property: "value", Type: ValueString, Raw: "stable"}}})
	return err
}

func (*testBatchParser) Probe(_ context.Context, reader ObjectReader) (ProbeResult, error) {
	buffer := make([]byte, min(32, int(reader.Size())))
	_, err := reader.ReadAt(buffer, 0)
	if err != nil && err != io.EOF {
		return ProbeResult{}, err
	}
	supported := !strings.HasPrefix(string(buffer), "unsupported")
	confidence := 0.95
	if !supported {
		confidence = 0.1
	}
	return ProbeResult{Supported: supported, Confidence: confidence, MediaType: "application/octet-stream"}, nil
}

func (*testBatchParser) Parse(ctx context.Context, request ParseRequest, sink Sink) error {
	content, err := io.ReadAll(io.NewSectionReader(request.Reader, 0, request.Size))
	if err != nil {
		return err
	}
	request.Config["parser_mutation"] = string(content)
	_, err = sink.EmitArtifact(ctx, "result", ArtifactDraft{Type: "urn:test:artifact/parser-output/v1", DisplayName: "parsed " + request.Input.DisplayName, Source: request.Input.ID, Values: []ArtifactValue{{Property: "content", Type: ValueString, Raw: string(content), Normalized: strings.ToUpper(string(content))}}})
	if err != nil {
		return err
	}
	if bytes.Contains(content, []byte("fail-after-output")) {
		return errors.New("intentional parser failure")
	}
	return nil
}

func TestParseManyProbesIsolatesAndRetainsPartialResults(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	contents := []string{"first", "second", "fail-after-output", "unsupported format"}
	inputs := make([]ObjectRef, len(contents))
	for i, content := range contents {
		evidence, err := c.ImportEvidence(ctx, "input-"+content, EvidenceSpec{Label: content}, strings.NewReader(content))
		if err != nil {
			t.Fatal(err)
		}
		inputs[i] = evidence.RootObject
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "parallel parsers"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	factory := &testParserFactory{}
	callerConfig := map[string]any{"profile": "strict", "nested": map[string]any{"limit": 3}}
	results, err := session.ParseMany(ctx, factory, ParseManySpec{Inputs: inputs, Config: callerConfig, Probe: true, MinimumConfidence: 0.8, Concurrency: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(inputs) || factory.created.Load() != int32(len(inputs)) {
		t.Fatalf("results/factory count mismatch: %d / %d", len(results), factory.created.Load())
	}
	if results[0].Err != nil || results[1].Err != nil {
		t.Fatalf("supported inputs failed: %#v", results)
	}
	if results[2].Err == nil || results[2].Activity == "" {
		t.Fatalf("failure after output was not represented: %#v", results[2])
	}
	if !errors.Is(results[3].Err, ErrUnsupported) || results[3].Activity != "" {
		t.Fatalf("unsupported probe unexpectedly started parse activity: %#v", results[3])
	}
	if _, changed := callerConfig["parser_mutation"]; changed {
		t.Fatal("parser mutated caller-owned configuration")
	}
	artifacts, err := c.Query(ctx, ArtifactTypeIs("urn:test:artifact/parser-output/v1"))
	if err != nil || len(artifacts.Entities) != 3 {
		t.Fatalf("partial parser outputs were not retained: %#v %v", artifacts, err)
	}
	failedActivity, err := c.Activity(ctx, results[2].Activity)
	if err != nil || failedActivity.State != ActivityFailed || failedActivity.Outcome == nil || !strings.Contains(failedActivity.Outcome.Summary, "intentional parser failure") {
		t.Fatalf("failed parser activity: %#v %v", failedActivity, err)
	}
	for i := range results {
		if results[i].Input != inputs[i].ID {
			t.Fatalf("result ordering changed at %d: %#v", i, results)
		}
	}
}

func TestDeterministicParserCacheRecordsReuseWithoutDuplicatingOutputs(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "cached-input", EvidenceSpec{Label: "cached input"}, strings.NewReader("input"))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "parser cache"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	calls := &atomic.Int32{}
	parser := &countingParser{calls: calls}
	first, err := session.ParseObject(ctx, evidence.RootObject, parser, ParseOptions{UseCache: true, Config: map[string]any{"mode": "strict"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.ParseObject(ctx, evidence.RootObject, parser, ParseOptions{UseCache: true, Config: map[string]any{"mode": "strict"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || first.Reused || !second.Reused || second.ReusedFrom != first.Activity {
		t.Fatalf("unexpected cache behavior: calls=%d first=%#v second=%#v", calls.Load(), first, second)
	}
	if len(first.Outputs) != 1 || len(second.Outputs) != 1 || first.Outputs[0] != second.Outputs[0] {
		t.Fatalf("cache did not reuse immutable output IDs: %#v %#v", first.Outputs, second.Outputs)
	}
	reuse, err := c.Activity(ctx, second.Activity)
	if err != nil || reuse.Type != ActivityParserReuse || reuse.State != ActivitySucceeded {
		t.Fatalf("reuse activity missing: %#v %v", reuse, err)
	}
	query, err := c.Query(ctx, ArtifactTypeIs("urn:test:cached/v1"))
	if err != nil || len(query.Entities) != 1 {
		t.Fatalf("cache duplicated parsed entities: %#v %v", query, err)
	}
}
