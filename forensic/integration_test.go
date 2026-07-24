package forensic

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTestRepo(t *testing.T) (context.Context, string, *Repository, *Case) {
	t.Helper()
	ctx := context.Background()
	base := t.TempDir()
	// Read-only projections chmod directories to 0500. Restore write bits before
	// t.TempDir cleanup so Unix unlink succeeds (cleanup order is LIFO).
	t.Cleanup(func() { makeTreeWritable(base) })
	repo, err := Open(ctx, Config{Root: filepath.Join(base, "repository"), DefaultAgent: AgentSpec{Kind: AgentSoftware, Name: "test-agent"}})
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	c, err := repo.CreateCase(ctx, CaseSpec{Name: "Router firmware", Description: "integration test"})
	if err != nil {
		t.Fatalf("create case: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return ctx, base, repo, c
}

func makeTreeWritable(root string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			_ = os.Chmod(path, 0o700)
			return nil
		}
		_ = os.Chmod(path, 0o600)
		return nil
	})
}

func TestEndToEndVerticalSlice(t *testing.T) {
	ctx, base, repo, c := openTestRepo(t)
	firmware := []byte("firmware-v1\x00CONFIG=enabled\n")
	evidence, err := c.ImportEvidence(ctx, "firmware.bin", EvidenceSpec{Label: "Vendor firmware", Acquisition: AcquisitionSpec{Method: "vendor-download"}, IdempotencyKey: "firmware-v1"}, bytes.NewReader(firmware))
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := c.ImportEvidence(ctx, "firmware.bin", EvidenceSpec{Label: "Vendor firmware", Acquisition: AcquisitionSpec{Method: "vendor-download"}, IdempotencyKey: "firmware-v1"}, bytes.NewReader(firmware))
	if err != nil || repeated.ID != evidence.ID || repeated.RootObject.ID != evidence.RootObject.ID {
		t.Fatalf("idempotent import mismatch: %#v %v", repeated, err)
	}
	occurrence, err := c.ImportEvidence(ctx, "firmware-copy.bin", EvidenceSpec{Label: "Second occurrence", Acquisition: AcquisitionSpec{Method: "copy"}}, bytes.NewReader(firmware))
	if err != nil {
		t.Fatal(err)
	}
	if occurrence.RootObject.ID == evidence.RootObject.ID || occurrence.RootObject.Blob != evidence.RootObject.Blob {
		t.Fatal("blob deduplication erased or failed to preserve occurrence identity")
	}

	s, err := c.StartSession(ctx, SessionSpec{Label: "HTTP parser investigation"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	extract, err := s.BeginActivity(ctx, ActivitySpec{Type: ActivityExtract, Label: "Extract config"})
	if err != nil {
		t.Fatal(err)
	}
	if err = extract.Use(ctx, evidence.RootObject, "firmware-image"); err != nil {
		t.Fatal(err)
	}
	configBytes := []byte(`{"username":"admin","enabled":true}`)
	config, err := extract.Capture(ctx, ObjectSpec{Role: "extracted-file", DisplayName: "config.json", MediaType: "application/json", Source: PathLocator{Raw: []byte("etc/config.json"), Display: "etc/config.json", Separator: "/"}}, bytes.NewReader(configBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err = extract.Use(ctx, occurrence.RootObject, "late-input"); !errors.Is(err, ErrConflict) {
		t.Fatalf("late activity input = %v, want conflict", err)
	}
	if err = extract.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}

	parse, err := s.BeginActivity(ctx, ActivitySpec{Type: ActivityParse, Label: "Parse config", Tool: &ToolDescriptor{Name: "json-test-parser", Version: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = parse.Use(ctx, config, "source"); err != nil {
		t.Fatal(err)
	}
	artifactDraft := ArtifactDraft{Type: "urn:test:config/v1", DisplayName: "Parsed config", Source: config.ID, Values: []ArtifactValue{{Property: "username", Type: ValueString, Raw: "admin", Normalized: "admin", Source: JSONLocator{Object: config.ID, Pointer: "/username"}}, {Property: "enabled", Type: ValueBoolean, Raw: "true", Normalized: true}}}
	artifact, err := parse.EmitArtifact(ctx, "config", artifactDraft)
	if err != nil {
		t.Fatal(err)
	}
	sameArtifact, err := parse.EmitArtifact(ctx, "config", artifactDraft)
	if err != nil || sameArtifact.ID != artifact.ID {
		t.Fatalf("producer-key retry mismatch: %#v %v", sameArtifact, err)
	}
	if err = parse.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}
	loadedArtifact, err := c.Artifact(ctx, artifact.ID)
	if err != nil || len(loadedArtifact.Values) != 2 || loadedArtifact.Values[0].Raw != "admin" {
		t.Fatalf("artifact round trip: %#v %v", loadedArtifact, err)
	}
	textHits, err := c.SearchText(ctx, "admin", 10)
	if err != nil || len(textHits) != 1 || textHits[0].Artifact != artifact.ID {
		t.Fatalf("full-text search: %#v %v", textHits, err)
	}
	trace, err := c.Trace(ctx, artifact)
	if err != nil || len(trace.Activities) != 3 || len(trace.Entities) != 3 {
		t.Fatalf("provenance trace: %#v %v", trace, err)
	}

	pathResults, err := c.Query(ctx, And(KindIs(EntityObject), PathGlob("**/*.json"), ProducedBySession(s.ID())))
	if err != nil || len(pathResults.Entities) != 1 || pathResults.Entities[0].ID != string(config.ID) {
		t.Fatalf("path query: %#v %v", pathResults, err)
	}
	valueResults, err := c.Query(ctx, And(ArtifactTypeIs("urn:test:config/v1"), ValueEquals("username", "admin")))
	if err != nil || len(valueResults.Entities) != 1 || valueResults.Entities[0].ID != string(artifact.ID) {
		t.Fatalf("value query: %#v %v", valueResults, err)
	}
	selection, err := s.Freeze(ctx, FreezeSpec{Name: "Config and parsed values", Query: Or(IDIs(string(config.ID)), IDIs(string(artifact.ID)))})
	if err != nil || len(selection.Members) != 2 {
		t.Fatalf("freeze: %#v %v", selection, err)
	}
	hits, err := c.SearchBytes(ctx, ByteSearchSpec{Selection: selection.ID, Literal: []byte("admin"), ContextBytes: 4})
	if err != nil || len(hits) != 1 || hits[0].Object != config.ID {
		t.Fatalf("byte search: %#v %v", hits, err)
	}
	projection, err := s.CreateProjection(ctx, ProjectionSpec{Selection: selection.ID, Closure: ClosureInputBytes, Layout: LayoutByEvidencePath, Include: IncludeBytes | IncludeMetadata | IncludeProvenance})
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := s.Materialize(ctx, projection.ID, DirectoryTarget{Path: filepath.Join(base, "workspace"), Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	report, err := c.Verify(ctx, VerifySpec{Mode: VerifyProjection, Materialization: materialized.ID})
	if err != nil || !report.OK || len(report.Issues) != 0 {
		t.Fatalf("projection verify: %#v %v", report, err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(materialized.Destination, "projection-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest ProjectionManifest
	if err = jsonUnmarshal(manifestBytes, &manifest); err != nil || len(manifest.Entries) != 2 {
		t.Fatalf("manifest: %#v %v", manifest, err)
	}
	secondMaterialization, err := s.Materialize(ctx, projection.ID, DirectoryTarget{Path: filepath.Join(base, "workspace-repeat"), Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	repeatedManifest, err := os.ReadFile(filepath.Join(secondMaterialization.Destination, "projection-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifestBytes, repeatedManifest) {
		t.Fatal("the same projection produced a different logical manifest")
	}
	var projectedLogical string
	for _, entry := range manifest.Entries {
		if entry.Entity.ID == string(config.ID) {
			projectedLogical = entry.Path
		}
	}
	if projectedLogical == "" {
		t.Fatal("config object missing from projection")
	}
	projectedPath := filepath.Join(materialized.Destination, filepath.FromSlash(projectedLogical))
	if err = os.WriteFile(projectedPath, []byte("mutated"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err = c.Verify(ctx, VerifySpec{Mode: VerifyProjection, Materialization: materialized.ID})
	if err != nil || report.OK {
		t.Fatalf("mutated projection not detected: %#v %v", report, err)
	}
	managed, err := c.OpenObject(ctx, config.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(managed, 0, config.Size))
	if closer, ok := managed.(io.Closer); ok {
		closer.Close()
	}
	if err != nil || !bytes.Equal(got, configBytes) {
		t.Fatalf("managed blob changed: %q %v", got, err)
	}

	finding, err := s.AuthorFinding(ctx, FindingSpec{Title: "Default credentials", Body: "The configuration contains a default account.", Status: FindingDraft, Severity: "high", Members: map[string][]EntityRef{"evidence": {config.EntityRef(), artifact.EntityRef()}}})
	if err != nil {
		t.Fatal(err)
	}
	revised, err := s.ReviseFinding(ctx, finding.ID, FindingRevisionSpec{ExpectedRevision: finding.Current, Body: "Confirmed default administrative credentials.", Status: FindingConfirmed, Severity: "high", Members: map[string][]EntityRef{"evidence": {config.EntityRef(), artifact.EntityRef()}}})
	if err != nil || revised.Version != 2 {
		t.Fatalf("revise finding: %#v %v", revised, err)
	}
	_, err = s.ReviseFinding(ctx, finding.ID, FindingRevisionSpec{ExpectedRevision: finding.Current, Body: "stale", Status: FindingRejected})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale finding revision = %v", err)
	}

	var md, jsonl bytes.Buffer
	if err = c.ExportMarkdown(ctx, MarkdownSpec{Selection: selection.ID, Writer: &md, IncludeHashes: true, IncludeProvenanceSummary: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), string(config.ID)) || !strings.Contains(md.String(), "sha256:") {
		t.Fatalf("incomplete Markdown: %s", md.String())
	}
	if err = c.ExportJSONL(ctx, JSONLSpec{Selection: selection.ID, Writer: &jsonl}); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(strings.TrimSpace(jsonl.String()), "\n") + 1; lines != 2 {
		t.Fatalf("JSONL lines=%d: %s", lines, jsonl.String())
	}
	deliverable, err := s.ExportBagIt(ctx, BagItSpec{Selection: selection.ID, Destination: filepath.Join(base, "delivery-bag"), Name: "research-delivery"})
	if err != nil {
		t.Fatal(err)
	}
	if bagReport, err := VerifyBagIt(ctx, deliverable.Path); err != nil || !bagReport.OK || bagReport.PayloadFiles != 1 {
		t.Fatalf("bag verify: %#v %v", bagReport, err)
	}
	deliveryTrace, err := c.Trace(ctx, deliverable)
	if err != nil {
		t.Fatal(err)
	}
	foundOriginal := false
	for _, entity := range deliveryTrace.Entities {
		if entity.ID == string(evidence.RootObject.ID) {
			foundOriginal = true
		}
	}
	if !foundOriginal {
		t.Fatal("deliverable provenance does not reach original evidence")
	}
	if err = os.WriteFile(filepath.Join(deliverable.Path, "bag-info.txt"), []byte("tampered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if bagReport, err := VerifyBagIt(ctx, deliverable.Path); err != nil || bagReport.OK {
		t.Fatalf("tampered BagIt tags not detected: %#v %v", bagReport, err)
	}

	full, err := c.Verify(ctx, VerifySpec{Mode: VerifyFull})
	if err != nil || !full.OK {
		t.Fatalf("full verify: %#v %v", full, err)
	}
	caseID := c.ID()
	if err = s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedRepo, err := Open(ctx, Config{Root: filepath.Join(base, "repository"), DefaultAgent: AgentSpec{Kind: AgentSoftware, Name: "test-agent"}})
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedRepo.Close()
	reopened, err := reopenedRepo.OpenCase(ctx, ByID(caseID))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if full, err = reopened.Verify(ctx, VerifySpec{Mode: VerifyFull}); err != nil || !full.OK {
		t.Fatalf("reopened verify: %#v %v", full, err)
	}
}

func TestAuditTamperAndProducerConflict(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	ev, err := c.ImportEvidence(ctx, "input", EvidenceSpec{Label: "input", Acquisition: AcquisitionSpec{Method: "test"}}, strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.StartSession(ctx, SessionSpec{Label: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	run, err := s.BeginActivity(ctx, ActivitySpec{Type: ActivityParse, Label: "parse"})
	if err != nil {
		t.Fatal(err)
	}
	if err = run.Use(ctx, ev.RootObject, "source"); err != nil {
		t.Fatal(err)
	}
	draft := ArtifactDraft{Type: "urn:test/v1", Source: ev.RootObject.ID, Values: []ArtifactValue{{Property: "x", Type: ValueString, Raw: "one"}}}
	first, err := run.EmitArtifact(ctx, "stable", draft)
	if err != nil {
		t.Fatal(err)
	}
	beforeReplay, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := run.EmitArtifact(ctx, "stable", draft)
	if err != nil || replayed.ID != first.ID || replayed.CreatedRevision != first.CreatedRevision {
		t.Fatalf("producer replay mismatch: %#v %#v %v", first, replayed, err)
	}
	afterReplay, err := c.Info(ctx)
	if err != nil || afterReplay.Revision != beforeReplay.Revision {
		t.Fatalf("producer replay advanced revision: %d -> %d: %v", beforeReplay.Revision, afterReplay.Revision, err)
	}
	draft.Values[0].Raw = "two"
	if _, err = run.EmitArtifact(ctx, "stable", draft); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed producer payload = %v", err)
	}
	if err = run.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}
	if _, err = c.db.ExecContext(ctx, "UPDATE audit_events SET event_json='{}' WHERE sequence=1"); err != nil {
		t.Fatal(err)
	}
	report, err := c.Verify(ctx, VerifySpec{Mode: VerifyQuick})
	if err != nil || report.OK {
		t.Fatalf("audit tampering not detected: %#v %v", report, err)
	}
}

func TestMultiProcessImports(t *testing.T) {
	if os.Getenv("FORENSIC_HELPER_PROCESS") != "" {
		t.Skip("parent-only")
	}
	ctx, _, repo, c := openTestRepo(t)
	const processes = 3
	cmds := make([]*exec.Cmd, processes)
	outputs := make([]bytes.Buffer, processes)
	for i := range cmds {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestImportHelperProcess$", "-test.v")
		cmd.Env = append(os.Environ(), "FORENSIC_HELPER_PROCESS=1", "FORENSIC_HELPER_ROOT="+repo.Root(), "FORENSIC_HELPER_CASE="+string(c.ID()))
		cmd.Stdout = &outputs[i]
		cmd.Stderr = &outputs[i]
		cmds[i] = cmd
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("helper %d: %v\n%s", i, err, outputs[i].String())
		}
	}
	result, err := c.Query(ctx, KindIs(EntityEvidence))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entities) != processes {
		t.Fatalf("evidence entities=%d, want %d", len(result.Entities), processes)
	}
	for _, kind := range []EntityKind{EntityAssertion, EntitySelection} {
		result, err = c.Query(ctx, KindIs(kind))
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Entities) != processes {
			t.Fatalf("%s entities=%d, want %d", kind, len(result.Entities), processes)
		}
	}
}

func TestImportHelperProcess(t *testing.T) {
	if os.Getenv("FORENSIC_HELPER_PROCESS") == "" {
		return
	}
	ctx := context.Background()
	repo, err := Open(ctx, Config{Root: os.Getenv("FORENSIC_HELPER_ROOT"), DefaultAgent: AgentSpec{Kind: AgentSoftware, Name: "test-agent"}})
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	c, err := repo.OpenCase(ctx, ByID(CaseID(os.Getenv("FORENSIC_HELPER_CASE"))))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	evidence, err := c.ImportEvidence(ctx, "process.bin", EvidenceSpec{Label: "process occurrence", Acquisition: AcquisitionSpec{Method: "helper"}}, strings.NewReader("shared process bytes"))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "helper process"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	run, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityAssertionRecord, Label: "helper tag"})
	if err != nil {
		t.Fatal(err)
	}
	if err = run.Use(ctx, evidence.RootObject, "target"); err != nil {
		t.Fatal(err)
	}
	if _, err = run.Relate(ctx, "tag", AssertionSpec{Type: "tag", Body: "helper", Targets: []EntityRef{evidence.RootObject.EntityRef()}}); err != nil {
		t.Fatal(err)
	}
	if err = run.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Query(ctx, KindIs(EntityObject)); err != nil {
		t.Fatal(err)
	}
	if _, err = session.Freeze(ctx, FreezeSpec{Name: "helper selection " + string(evidence.ID), Query: IDIs(string(evidence.RootObject.ID))}); err != nil {
		t.Fatal(err)
	}
}

func TestProcessTerminationAtPersistenceBoundaries(t *testing.T) {
	if os.Getenv("FORENSIC_CRASH_HELPER") != "" {
		t.Skip("parent-only")
	}
	points := []string{"after-stage-create", "after-stage-copy", "after-stage-sync", "after-blob-publish", "before-catalog-commit", "after-catalog-commit"}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			ctx := context.Background()
			base := t.TempDir()
			root := filepath.Join(base, "repo")
			repo, err := Open(ctx, Config{Root: root})
			if err != nil {
				t.Fatal(err)
			}
			c, err := repo.CreateCase(ctx, CaseSpec{Name: "crash case"})
			if err != nil {
				t.Fatal(err)
			}
			caseID := c.ID()
			_ = c.Close()
			_ = repo.Close()
			ready := filepath.Join(base, "ready")
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashBoundaryHelper$")
			cmd.Env = append(os.Environ(), "FORENSIC_CRASH_HELPER=1", "FORENSIC_CRASH_ROOT="+root, "FORENSIC_CRASH_CASE="+string(caseID), "FORENSIC_CRASH_POINT="+point, "FORENSIC_CRASH_READY="+ready)
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(20 * time.Second)
			for {
				if _, err = os.Stat(ready); err == nil {
					break
				}
				if time.Now().After(deadline) {
					_ = cmd.Process.Kill()
					t.Fatal("helper did not reach fault boundary")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			repo, err = Open(ctx, Config{Root: root})
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
				t.Fatalf("post-crash verification: %#v %v", report, err)
			}
			objects, err := c.Query(ctx, KindIs(EntityObject))
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if point == "after-catalog-commit" {
				want = 1
			}
			if len(objects.Entities) != want {
				t.Fatalf("objects=%d, want %d", len(objects.Entities), want)
			}
		})
	}
}

func TestCrashBoundaryHelper(t *testing.T) {
	if os.Getenv("FORENSIC_CRASH_HELPER") == "" {
		return
	}
	ctx := context.Background()
	repo, err := Open(ctx, Config{Root: os.Getenv("FORENSIC_CRASH_ROOT")})
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	c, err := repo.OpenCase(ctx, ByID(CaseID(os.Getenv("FORENSIC_CRASH_CASE"))))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	point := os.Getenv("FORENSIC_CRASH_POINT")
	c.faultMu.Lock()
	c.fault = func(got string) error {
		if got == point {
			if err := os.WriteFile(os.Getenv("FORENSIC_CRASH_READY"), []byte(got), 0600); err != nil {
				return err
			}
			for {
				time.Sleep(time.Second)
			}
		}
		return nil
	}
	c.faultMu.Unlock()
	_, err = c.ImportEvidence(ctx, "crash.bin", EvidenceSpec{Label: "crash", Acquisition: AcquisitionSpec{Method: "crash-test"}}, strings.NewReader("crash boundary bytes"))
	if err != nil {
		t.Fatal(err)
	}
}

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

func TestConcurrentImportsAndCorruptionDetection(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	const workers = 24
	refs := make([]Evidence, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			refs[i], errs[i] = c.ImportEvidence(ctx, "same.bin", EvidenceSpec{Label: "occurrence", Acquisition: AcquisitionSpec{Method: "test"}}, strings.NewReader("same bytes"))
		}(i)
	}
	wg.Wait()
	ids := map[EvidenceID]bool{}
	var blob BlobRef
	for i := range refs {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		if ids[refs[i].ID] {
			t.Fatalf("duplicate evidence ID %s", refs[i].ID)
		}
		ids[refs[i].ID] = true
		if i == 0 {
			blob = refs[i].RootObject.Blob
		} else if refs[i].RootObject.Blob != blob {
			t.Fatal("identical bytes were not deduplicated")
		}
	}
	report, err := c.Verify(ctx, VerifySpec{Mode: VerifyFull})
	if err != nil || !report.OK {
		t.Fatalf("pre-corruption verify: %#v %v", report, err)
	}
	path := c.blobPath(blob)
	if err = os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err = c.Verify(ctx, VerifySpec{Mode: VerifyFull})
	if err != nil || report.OK {
		t.Fatalf("corruption not detected: %#v %v", report, err)
	}
}

func TestHundredGoroutineMixedWorkload(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	base, err := c.ImportEvidence(ctx, "base.bin", EvidenceSpec{Label: "base", Acquisition: AcquisitionSpec{Method: "test"}}, strings.NewReader("base bytes searchable"))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "one hundred workers"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	const workers = 100
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 4 {
			case 0:
				_, err := c.ImportEvidence(ctx, fmt.Sprintf("occurrence-%03d.bin", i), EvidenceSpec{Label: "concurrent occurrence", Acquisition: AcquisitionSpec{Method: "stress"}}, strings.NewReader("shared concurrent bytes"))
				errs <- err
			case 1:
				result, err := c.Query(ctx, Or(KindIs(EntityObject), ValueEquals("tag", fmt.Sprint(i))))
				if err == nil && len(result.Entities) == 0 {
					err = fmt.Errorf("query returned no objects")
				}
				errs <- err
			case 2:
				run, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityAssertionRecord, Label: "tag object"})
				if err == nil {
					err = run.Use(ctx, base.RootObject, "target")
				}
				if err == nil {
					_, err = run.Relate(ctx, "tag", AssertionSpec{Type: "tag", Body: fmt.Sprintf("worker-%03d", i), Targets: []EntityRef{base.RootObject.EntityRef()}})
				}
				if run != nil {
					finishErr := run.Finish(ctx, func() Outcome {
						if err != nil {
							return OutcomeFailed(err)
						}
						return OutcomeSucceeded()
					}())
					if err == nil {
						err = finishErr
					}
				}
				errs <- err
			case 3:
				_, err := session.Freeze(ctx, FreezeSpec{Name: fmt.Sprintf("objects-%03d", i), Query: KindIs(EntityObject)})
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	report, err := c.Verify(ctx, VerifySpec{Mode: VerifyFull})
	if err != nil || !report.OK {
		t.Fatalf("mixed workload verification: %#v %v", report, err)
	}
}

func TestSnapshotRestoreAndSignedCheckpoint(t *testing.T) {
	ctx, base, _, c := openTestRepo(t)
	original, err := c.ImportEvidence(ctx, "original.bin", EvidenceSpec{Label: "original", Acquisition: AcquisitionSpec{Method: "test"}}, strings.NewReader("portable evidence"))
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint bytes.Buffer
	cp, err := c.CreateCheckpoint(ctx, CheckpointSpec{Signer: privateKey, Writer: &checkpoint})
	if err != nil {
		t.Fatal(err)
	}
	if cp.Inventory.Case != c.ID() || len(cp.Inventory.Blobs) != 1 || checkpoint.Len() == 0 {
		t.Fatalf("checkpoint inventory: %#v", cp)
	}
	if err = VerifyCheckpoint(cp); err != nil {
		t.Fatal(err)
	}
	cp.Signature.Value = "AAAA"
	if err = VerifyCheckpoint(cp); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered signature = %v", err)
	}
	snapshotPath := filepath.Join(base, "portable-case")
	delivery, err := c.Snapshot(ctx, SnapshotSpec{Destination: snapshotPath, Name: "portable copy"})
	if err != nil {
		t.Fatal(err)
	}
	if delivery.SHA256 == "" {
		t.Fatal("snapshot package has no digest")
	}
	restoredRepo, err := Open(ctx, Config{Root: filepath.Join(base, "restored-repository"), DefaultAgent: AgentSpec{Kind: AgentSoftware, Name: "restore-agent"}})
	if err != nil {
		t.Fatal(err)
	}
	defer restoredRepo.Close()
	restored, err := restoredRepo.RestoreCase(ctx, RestoreSpec{Source: snapshotPath})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.ID() != c.ID() {
		t.Fatalf("restored case ID=%s want %s", restored.ID(), c.ID())
	}
	obj, err := restored.Object(ctx, original.RootObject.ID)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := restored.OpenObject(ctx, obj.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.NewSectionReader(reader, 0, obj.Size))
	closeReader(reader)
	if err != nil || string(data) != "portable evidence" {
		t.Fatalf("restored bytes %q %v", data, err)
	}
	report, err := restored.Verify(ctx, VerifySpec{Mode: VerifyFull})
	if err != nil || !report.OK {
		t.Fatalf("restored verification: %#v %v", report, err)
	}
}

func TestStreamingByteSearchAcrossChunkBoundary(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	data := bytes.Repeat([]byte{'x'}, byteSearchChunk*2)
	copy(data[byteSearchChunk-3:], []byte("needle"))
	ev, err := c.ImportEvidence(ctx, "large.bin", EvidenceSpec{Label: "large", Acquisition: AcquisitionSpec{Method: "test"}}, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.StartSession(ctx, SessionSpec{Label: "search"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	selection, err := s.Freeze(ctx, FreezeSpec{Name: "large object", Query: IDIs(string(ev.RootObject.ID))})
	if err != nil {
		t.Fatal(err)
	}
	hits, err := c.SearchBytes(ctx, ByteSearchSpec{Selection: selection.ID, Literal: []byte("needle"), ContextBytes: 3, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Offset != byteSearchChunk-3 || string(hits[0].Context) != "xxxneedlexxx" {
		t.Fatalf("boundary hits: %#v", hits)
	}
}

func TestEvidenceIdempotencyConflictDoesNotPublishOrphanBytes(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	if _, err := c.ImportEvidence(ctx, "first", EvidenceSpec{Label: "first", IdempotencyKey: "one-accession"}, strings.NewReader("first bytes")); err != nil {
		t.Fatal(err)
	}
	before, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.ImportEvidence(ctx, "second", EvidenceSpec{Label: "second", IdempotencyKey: "one-accession"}, strings.NewReader("different bytes")); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed idempotent import = %v", err)
	}
	after, err := c.Info(ctx)
	if err != nil || after.Revision != before.Revision {
		t.Fatalf("conflict changed revision: %d -> %d: %v", before.Revision, after.Revision, err)
	}
	recovery, err := c.InspectRecovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovery.OrphanBlobs) != 0 || len(recovery.StagingFiles) != 0 {
		t.Fatalf("idempotency conflict left recovery debris: %#v", recovery)
	}
}
