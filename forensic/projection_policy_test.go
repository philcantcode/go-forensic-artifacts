package forensic

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProjectionFiltersExclusionsAndResourceLimits(t *testing.T) {
	ctx, base, _, c := openTestRepo(t)
	first, err := c.ImportEvidence(ctx, "first.txt", EvidenceSpec{Label: "first"}, bytes.NewReader([]byte("first")))
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.ImportEvidence(ctx, "second.txt", EvidenceSpec{Label: "second"}, bytes.NewReader([]byte("second")))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "projection policy"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	selection, err := session.Freeze(ctx, FreezeSpec{Name: "two files", Query: Or(IDIs(string(first.RootObject.ID)), IDIs(string(second.RootObject.ID)))})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := session.CreateProjection(ctx, ProjectionSpec{Selection: selection.ID, Closure: ClosureExact, Layout: LayoutByID, Include: IncludeBytes, Kinds: []EntityKind{EntityObject}, Exclusions: []ProjectionExclusion{{Entity: second.RootObject.EntityRef(), Reason: "agent-specific subset"}}, MaxFiles: 1, MaxBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.Members) != 1 || projection.Members[0].ID != string(first.RootObject.ID) || len(projection.Excluded) != 1 || projection.Excluded[0].Entity.ID != string(second.RootObject.ID) {
		t.Fatalf("projection policy not resolved: %#v", projection)
	}
	loaded, err := c.Projection(ctx, projection.ID)
	if err != nil || len(loaded.Excluded) != 1 || loaded.Excluded[0].Reason != "agent-specific subset" {
		t.Fatalf("projection policy round trip: %#v %v", loaded, err)
	}
	materialized, err := session.Materialize(ctx, projection.ID, DirectoryTarget{Path: filepath.Join(base, "filtered-projection"), Writable: true})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(materialized.Destination, "projection-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest ProjectionManifest
	if err = json.Unmarshal(body, &manifest); err != nil || len(manifest.Entries) != 1 || manifest.Entries[0].Entity.ID != string(first.RootObject.ID) {
		t.Fatalf("filtered projection manifest: %#v %v", manifest, err)
	}

	tiny, err := session.CreateProjection(ctx, ProjectionSpec{Selection: selection.ID, Closure: ClosureExact, Include: IncludeBytes, MaxFiles: 2, MaxBytes: 3})
	if err != nil {
		t.Fatal(err)
	}
	tinyDestination := filepath.Join(base, "too-small")
	if _, err = session.Materialize(ctx, tiny.ID, DirectoryTarget{Path: tinyDestination, Writable: true}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("byte-limited projection = %v, want invalid", err)
	}
	if _, statErr := os.Stat(tinyDestination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed projection published a destination: %v", statErr)
	}
	if _, err = session.CreateProjection(ctx, ProjectionSpec{Selection: selection.ID, Exclusions: []ProjectionExclusion{{Entity: EntityRef{ID: "obj_not_in_closure", Kind: EntityObject}, Reason: "invalid"}}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("out-of-closure exclusion = %v, want invalid", err)
	}
}

func TestProjectionEmitsTypedMetadataProvenanceAndFindings(t *testing.T) {
	ctx, base, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "input.bin", EvidenceSpec{Label: "projection source"}, bytes.NewReader([]byte("input")))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "rich projection"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	if _, err = session.AuthorFinding(ctx, FindingSpec{Title: "related finding", Body: "the selected object is relevant", Status: FindingDraft, Members: map[string][]EntityRef{"evidence": {evidence.RootObject.EntityRef()}}}); err != nil {
		t.Fatal(err)
	}
	selection, err := session.Freeze(ctx, FreezeSpec{Name: "one object", Query: IDIs(string(evidence.RootObject.ID))})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := session.CreateProjection(ctx, ProjectionSpec{Selection: selection.ID, Include: IncludeBytes | IncludeMetadata | IncludeProvenance | IncludeFindings})
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := session.Materialize(ctx, projection.ID, DirectoryTarget{Path: filepath.Join(base, "rich-projection")})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(materialized.Destination, "projection-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest ProjectionManifest
	if err = json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	roles := map[string]int{}
	for _, file := range manifest.Files {
		roles[file.Role]++
		if _, err = os.Stat(filepath.Join(materialized.Destination, filepath.FromSlash(file.Path))); err != nil {
			t.Fatalf("manifest support file %s: %v", file.Path, err)
		}
	}
	if roles["metadata"] != 1 || roles["provenance"] != 1 || roles["finding"] != 1 {
		t.Fatalf("projection representation roles = %#v", roles)
	}
	limited, err := session.CreateProjection(ctx, ProjectionSpec{Selection: selection.ID, Include: IncludeMetadata, MaxBytes: 1, MaxFiles: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = session.Materialize(ctx, limited.ID, DirectoryTarget{Path: filepath.Join(base, "support-too-large")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("support files ignored byte limit: %v", err)
	}
}
