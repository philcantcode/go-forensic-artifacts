package forensic

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestTypedLocatorsTemporalValuesAndMetadataSearch(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "history.sqlite", EvidenceSpec{Label: "browser history", Acquisition: AcquisitionSpec{Method: "test"}}, bytes.NewReader([]byte("SQLite bytes")))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "parse typed model"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	run, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityParse, Label: "parse browser visit", Tool: &ToolDescriptor{Name: "browser-parser", Version: "2.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = run.Use(ctx, evidence.RootObject, "source"); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 7, 23, 10, 11, 12, 123000000, time.FixedZone("source", 2*60*60))
	end := start.Add(2 * time.Second)
	rowID := int64(42)
	confidence := 0.85
	draft := ArtifactDraft{
		Type: "urn:test:artifact:browser.visit/v1", DisplayName: "Admin portal visit", Source: evidence.RootObject.ID,
		Values: []ArtifactValue{
			{Property: "visited_at", SchemaURI: "urn:test:property:visited-at/v1", Type: ValueTime, Raw: "133822734721230000", Interpretation: "WebKit microseconds interpreted using profile timezone", Source: SQLiteLocator{Object: evidence.RootObject.ID, Database: "History", Table: "visits", RowID: &rowID, Column: "visit_time"}, Temporal: &TemporalValue{RawType: "webkit-microseconds", UTCStart: &start, UTCEnd: &end, OriginalNumeric: "133822734721230000", EpochUnit: "microseconds", Timezone: "Europe/Paris", TimezoneBasis: TimezoneInferred, Precision: "microsecond", SemanticRole: "visited", Normalizer: &ToolDescriptor{Name: "browser-parser", Version: "2.1"}, SourceClock: "browser profile", Confidence: &confidence}},
			{Property: "account", Type: ValueString, Raw: "Admin.Account", Normalized: "admin.account", Source: JSONLocator{Object: evidence.RootObject.ID, Pointer: "/account"}},
			{Property: "xml", Type: ValueString, Raw: "node", Source: XMLLocator{Object: evidence.RootObject.ID, XPath: "/root/item[1]", Namespaces: map[string]string{"x": "urn:test"}}},
			{Property: "member", Type: ValueString, Raw: "etc/config", Source: ArchiveLocator{Container: evidence.RootObject.ID, RawName: []byte("etc/config"), DisplayName: "etc/config", MemberIndex: 7}},
			{Property: "registry", Type: ValueString, Raw: "enabled", Source: RegistryLocator{Hive: evidence.RootObject.ID, KeyPath: `HKLM\\Software\\Example`, ValueName: "Enabled"}},
			{Property: "api", Type: ValueURI, Raw: "cloud item", Source: APILocator{AcquisitionURI: "https://api.example.test/export", AccountID: "tenant-1", ResourceID: "item-9", RequestID: "request-3", PageReference: "next-2"}},
		},
	}
	artifact, err := run.EmitArtifact(ctx, "visit-42", draft)
	if err != nil {
		t.Fatal(err)
	}
	if err = run.Finish(ctx, OutcomeSucceeded()); err != nil {
		t.Fatal(err)
	}
	loaded, err := c.Artifact(ctx, artifact.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Values) != len(draft.Values) {
		t.Fatalf("loaded values=%d, want %d", len(loaded.Values), len(draft.Values))
	}
	if _, ok := loaded.Values[0].Source.(SQLiteLocator); !ok {
		t.Fatalf("SQLite locator did not round trip: %T", loaded.Values[0].Source)
	}
	if _, ok := loaded.Values[2].Source.(XMLLocator); !ok {
		t.Fatalf("XML locator did not round trip: %T", loaded.Values[2].Source)
	}
	if _, ok := loaded.Values[3].Source.(ArchiveLocator); !ok {
		t.Fatalf("archive locator did not round trip: %T", loaded.Values[3].Source)
	}
	if _, ok := loaded.Values[4].Source.(RegistryLocator); !ok {
		t.Fatalf("registry locator did not round trip: %T", loaded.Values[4].Source)
	}
	if _, ok := loaded.Values[5].Source.(APILocator); !ok {
		t.Fatalf("API locator did not round trip: %T", loaded.Values[5].Source)
	}
	if loaded.Values[0].Temporal == nil || loaded.Values[0].Temporal.UTCStart == nil || loaded.Values[0].Temporal.UTCStart.Location() != time.UTC || loaded.Values[0].Temporal.SemanticRole != "visited" {
		t.Fatalf("temporal interpretation did not round trip in UTC: %#v", loaded.Values[0].Temporal)
	}
	inside, err := c.Query(ctx, TimeOverlaps("visited_at", start.Add(time.Second), start.Add(3*time.Second), "visited"))
	if err != nil || len(inside.Entities) != 1 || inside.Entities[0].ID != string(artifact.ID) {
		t.Fatalf("time overlap query: %#v %v", inside, err)
	}
	outside, err := c.Query(ctx, TimeOverlaps("visited_at", start.Add(time.Hour), start.Add(2*time.Hour), "visited"))
	if err != nil || len(outside.Entities) != 0 {
		t.Fatalf("non-overlapping time query: %#v %v", outside, err)
	}
	if _, err = c.Query(ctx, Query{Op: QueryTimeRange, Property: "visited_at", Start: "invalid", End: "invalid"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid time query = %v", err)
	}

	metadata, err := c.SearchMetadata(ctx, MetadataSearchSpec{Regexp: `admin\.account`, Fields: []MetadataField{MetadataValueNorm}})
	if err != nil || len(metadata.Hits) != 1 || metadata.Hits[0].Entity.ID != string(artifact.ID) || metadata.Hits[0].Property != "account" {
		t.Fatalf("metadata regexp search: %#v %v", metadata, err)
	}
	pathSearch, err := c.SearchMetadata(ctx, MetadataSearchSpec{Literal: "HISTORY.SQLITE", Fields: []MetadataField{MetadataPath}})
	if err != nil || len(pathSearch.Hits) != 1 || pathSearch.Hits[0].Entity.ID != string(evidence.RootObject.ID) {
		t.Fatalf("case-insensitive path metadata search: %#v %v", pathSearch, err)
	}
	if _, err = c.SearchMetadata(ctx, MetadataSearchSpec{Literal: "x", Regexp: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ambiguous metadata search = %v", err)
	}
}

func TestTemporalValidation(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "input", EvidenceSpec{Label: "input"}, bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "temporal validation"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	run, err := session.BeginActivity(ctx, ActivitySpec{Type: ActivityParse, Label: "invalid time"})
	if err != nil {
		t.Fatal(err)
	}
	if err = run.Use(ctx, evidence.RootObject, "source"); err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC()
	_, err = run.EmitArtifact(ctx, "invalid", ArtifactDraft{Type: "urn:test/time", Source: evidence.RootObject.ID, Values: []ArtifactValue{{Property: "time", Type: ValueTime, Raw: "bad", Temporal: &TemporalValue{UTCEnd: &end}}}})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("end-only temporal interval = %v", err)
	}
	_ = run.Finish(ctx, OutcomeFailed(err))
}

func TestSavedByteSearchCreatesTraceableArtifactsAndSelection(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	evidence, err := c.ImportEvidence(ctx, "messages.txt", EvidenceSpec{Label: "messages"}, bytes.NewReader([]byte("token=alpha\nother\ntoken=alpha\n")))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "saved search"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	source, err := session.Freeze(ctx, FreezeSpec{Name: "message bytes", Query: IDIs(string(evidence.RootObject.ID))})
	if err != nil {
		t.Fatal(err)
	}
	spec := SavedByteSearchSpec{Name: "alpha tokens", Search: ByteSearchSpec{Selection: source.ID, Literal: []byte("token=alpha"), ContextBytes: 3, Limit: 10}, IdempotencyKey: "alpha-v1"}
	saved, err := session.SaveByteSearch(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Hits) != 2 || len(saved.Selection.Members) != 2 || saved.Selection.Revision == 0 {
		t.Fatalf("unexpected saved search: %#v", saved)
	}
	for _, hit := range saved.Hits {
		loaded, loadErr := c.Artifact(ctx, hit.ID)
		if loadErr != nil || loaded.Source != evidence.RootObject.ID || loaded.Type != "urn:forensic:artifact:byte-search-hit/v1" {
			t.Fatalf("saved hit round trip: %#v %v", loaded, loadErr)
		}
		trace, traceErr := c.Trace(ctx, loaded)
		if traceErr != nil {
			t.Fatal(traceErr)
		}
		foundSource := false
		for _, entity := range trace.Entities {
			foundSource = foundSource || entity.ID == string(evidence.RootObject.ID)
		}
		if !foundSource {
			t.Fatalf("saved search hit %s is not traceable to its bytes", hit.ID)
		}
	}
	beforeReplay, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := session.SaveByteSearch(ctx, spec)
	if err != nil || repeated.Selection.ID != saved.Selection.ID || repeated.Activity != saved.Activity || len(repeated.Hits) != len(saved.Hits) {
		t.Fatalf("saved-search idempotency mismatch: %#v %v", repeated, err)
	}
	afterReplay, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterReplay.Revision != beforeReplay.Revision {
		t.Fatalf("idempotent replay advanced case revision from %d to %d", beforeReplay.Revision, afterReplay.Revision)
	}
}
