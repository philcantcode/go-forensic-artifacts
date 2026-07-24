package forensic

import (
	"bytes"
	"testing"
)

func TestExtendedTypedQueries(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "firmware.bin", EvidenceSpec{Label: "firmware"}, bytes.NewReader([]byte("firmware")))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "extended query"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	extract, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityExtract, Label: "extract database", Tool: &ToolDescriptor{Name: "extractor", Version: "3"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = extract.Use(ctx, evidence.RootObject, "source"); err != nil {
		t.Fatal(err)
	}
	database, err := extract.Capture(ctx, ObjectSpec{Role: "extracted", DisplayName: "config.sqlite", MediaType: "application/vnd.sqlite3", Source: PathLocator{Display: "rootfs/etc/config.SQLITE", Separator: "/"}}, bytes.NewReader([]byte("sqlite")))
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := extract.Relate(ctx, "notable", AssertionSpec{Type: "urn:test:tag:notable/v1", Body: "notable database", Targets: []EntityRef{database.EntityRef()}})
	if err != nil {
		t.Fatal(err)
	}
	if err = extract.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}
	parse, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityParse, Label: "parse database", Tool: &ToolDescriptor{Name: "sqlite-parser", Version: "5"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = parse.Use(ctx, database, "source"); err != nil {
		t.Fatal(err)
	}
	artifact, err := parse.EmitArtifact(ctx, "row", ArtifactDraft{Type: "urn:test:artifact:config-row/v1", DisplayName: "config row", Source: database.ID, Values: []ArtifactValue{{Property: "key", Type: ValueString, Raw: "admin"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = parse.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}
	finding, err := session.AuthorFinding(ctx, FindingSpec{Title: "Configuration weakness", Body: "Weak setting", Status: FindingDraft, Members: map[string][]EntityRef{"evidence": {artifact.EntityRef()}}})
	if err != nil {
		t.Fatal(err)
	}

	checks := []struct {
		name  string
		query Query
		want  string
	}{
		{"media", MediaTypeIs("APPLICATION/VND.SQLITE3"), string(database.ID)},
		{"extension", ExtensionIs("sqlite"), string(database.ID)},
		{"size", SizeBetween(6, 6), string(database.ID)},
		{"schema", SchemaIs("urn:test:artifact:config-row/v1"), string(artifact.ID)},
		{"agent", ProducedByAgent(session.info.Agent.ID), string(database.ID)},
		{"tool", ProducedByTool("sqlite-parser", "5"), string(artifact.ID)},
		{"evidence", InEvidence(evidence.ID), string(artifact.ID)},
		{"finding", InFinding(finding.ID), string(artifact.ID)},
		{"descendant", DescendsFrom(string(evidence.RootObject.ID)), string(artifact.ID)},
		{"revision", CreatedAtRevision(artifact.CreatedRevision, artifact.CreatedRevision), string(artifact.ID)},
		{"assertion", AssertionTypeIs("urn:test:tag:notable/v1"), string(assertion.ID)},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			result, queryErr := c.Query(ctx, check.query)
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			if !queryContains(result, check.want) {
				t.Fatalf("query %#v did not contain %s: %#v", check.query, check.want, result.Entities)
			}
		})
	}
	if _, err = c.Query(ctx, SizeBetween(10, 1)); err == nil {
		t.Fatal("invalid size range was accepted")
	}
}

func queryContains(result QueryResult, id string) bool {
	for _, entity := range result.Entities {
		if entity.ID == id {
			return true
		}
	}
	return false
}
