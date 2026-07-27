package forensic

import (
	"bytes"
	"context"
	"testing"
)

const apkLocaleArtifactType = "urn:test:artifact:android.apk.locale/v1"

func TestRelationshipQueryFiltersDerivedObjectsBySiblingMetadata(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	session, err := c.StartSession(ctx, SessionSpec{Label: "APK target filtering"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)

	_, russianManifest := addAPKTarget(t, ctx, c, session, "russian.apk", "ru")
	_, englishManifest := addAPKTarget(t, ctx, c, session, "english.apk", "en")

	query := apkManifestLanguageQuery("ru")
	result, err := c.Query(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entities) != 1 || result.Entities[0] != russianManifest.EntityRef() {
		t.Fatalf("Russian manifest query = %#v, want only %s", result.Entities, russianManifest.ID)
	}
	if queryContains(result, string(englishManifest.ID)) {
		t.Fatalf("Russian manifest query included English manifest %s", englishManifest.ID)
	}
	firstPage, err := c.QueryPage(ctx, QueryPageSpec{Query: query, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Entities) != 1 || firstPage.Entities[0] != russianManifest.EntityRef() || firstPage.Next.ID == "" {
		t.Fatalf("first relationship query page = %#v", firstPage)
	}

	frozen, err := session.Freeze(ctx, FreezeSpec{
		Name:           "Manifests from APKs with Russian language support",
		Query:          query,
		IdempotencyKey: "russian-apk-manifests-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(frozen.Members) != 1 || frozen.Members[0] != russianManifest.EntityRef() {
		t.Fatalf("frozen members = %#v, want only %s", frozen.Members, russianManifest.ID)
	}

	_, laterManifest := addAPKTarget(t, ctx, c, session, "later-russian.apk", "ru")
	live, err := c.Query(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(live.Entities) != 2 || !queryContains(live, string(laterManifest.ID)) {
		t.Fatalf("live query after later import = %#v, want both Russian manifests", live.Entities)
	}
	pinnedPage, err := c.QueryPage(ctx, QueryPageSpec{
		Query:    query,
		Revision: firstPage.Revision,
		After:    firstPage.Next,
		Limit:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pinnedPage.Entities) != 0 {
		t.Fatalf("revision-pinned relationship query saw later entities: %#v", pinnedPage.Entities)
	}
	persisted, err := c.Selection(ctx, frozen.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted.Members) != 1 || persisted.Members[0] != russianManifest.EntityRef() {
		t.Fatalf("frozen selection changed after case growth: %#v", persisted.Members)
	}
}

func TestRelationshipQueriesAreStrictAndValidateOnePredicate(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "target.bin", EvidenceSpec{Label: "target"}, bytes.NewReader([]byte("target")))
	if err != nil {
		t.Fatal(err)
	}

	for name, query := range map[string]Query{
		"ancestor":   HasAncestor(IDIs(string(evidence.RootObject.ID))),
		"descendant": HasDescendant(IDIs(string(evidence.RootObject.ID))),
	} {
		t.Run(name+" excludes self", func(t *testing.T) {
			result, queryErr := c.Query(ctx, And(IDIs(string(evidence.RootObject.ID)), query))
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			if len(result.Entities) != 0 {
				t.Fatalf("strict relationship query matched candidate itself: %#v", result.Entities)
			}
		})
	}

	invalid := []Query{
		{Op: QueryHasAncestor},
		{Op: QueryHasDescendant, Children: []Query{All(), All()}},
	}
	for _, query := range invalid {
		if _, err = c.Query(ctx, query); err == nil {
			t.Fatalf("invalid relationship query was accepted: %#v", query)
		}
	}
}

func apkManifestLanguageQuery(language string) Query {
	return And(
		KindIs(EntityObject),
		PathGlob("**/AndroidManifest.xml"),
		HasAncestor(And(
			KindIs(EntityObject),
			HasDescendant(And(
				ArtifactTypeIs(apkLocaleArtifactType),
				ValueEquals("language", language),
			)),
		)),
	)
}

func addAPKTarget(t *testing.T, ctx context.Context, c *Case, session *Session, name, language string) (ObjectRef, ObjectRef) {
	t.Helper()
	evidence, err := c.ImportEvidence(ctx, name, EvidenceSpec{Label: name}, bytes.NewReader([]byte("APK:"+name)))
	if err != nil {
		t.Fatal(err)
	}

	extract, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityExtract, Label: "Extract " + name})
	if err != nil {
		t.Fatal(err)
	}
	if err = extract.Use(ctx, evidence.RootObject, "apk"); err != nil {
		t.Fatal(err)
	}
	manifest, err := extract.Capture(ctx, ObjectSpec{
		Role:        "android-manifest",
		DisplayName: name + "/AndroidManifest.xml",
		MediaType:   "application/xml",
		Source:      PathLocator{Display: name + "/AndroidManifest.xml", Separator: "/"},
	}, bytes.NewReader([]byte("<manifest/>")))
	if err != nil {
		t.Fatal(err)
	}
	if err = extract.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}

	parse, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityParse, Label: "Parse locales from " + name})
	if err != nil {
		t.Fatal(err)
	}
	if err = parse.Use(ctx, evidence.RootObject, "apk"); err != nil {
		t.Fatal(err)
	}
	if _, err = parse.EmitArtifact(ctx, ProducerKey("locale-"+language), ArtifactDraft{
		Type:        apkLocaleArtifactType,
		DisplayName: name + " locale " + language,
		Source:      evidence.RootObject.ID,
		Values: []ArtifactValue{{
			Property:   "language",
			Type:       ValueString,
			Raw:        language,
			Normalized: language,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err = parse.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}
	return evidence.RootObject, manifest
}
