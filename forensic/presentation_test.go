package forensic

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestListPresentationsEvidenceObjectTextAndHex(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)

	textBody := []byte("hello presentation world\nline two\n")
	ev, err := c.ImportEvidence(ctx, "notes.txt", EvidenceSpec{
		Label: "notes", Acquisition: AcquisitionSpec{Method: "test"},
	}, bytes.NewReader(textBody))
	if err != nil {
		t.Fatal(err)
	}

	cat, err := c.ListPresentations(ctx, EntityRef{ID: string(ev.ID), Kind: EntityEvidence})
	if err != nil {
		t.Fatal(err)
	}
	if cat.PreferredViewID != ViewMetadataV1 {
		t.Fatalf("evidence preferred = %q, want metadata", cat.PreferredViewID)
	}
	if cat.Entity.Kind != EntityEvidence || cat.Entity.ID != string(ev.ID) {
		t.Fatalf("catalog entity = %#v", cat.Entity)
	}
	views := viewMap(cat.Views)
	if !views[ViewMetadataV1].Available || !views[ViewHexV1].Available || !views[ViewTextV1].Available {
		t.Fatalf("expected metadata/hex/text available for text evidence: %#v", cat.Views)
	}

	objCat, err := c.ListPresentations(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject})
	if err != nil {
		t.Fatal(err)
	}
	if objCat.PreferredViewID != ViewTextV1 {
		t.Fatalf("text object preferred = %q, want text", objCat.PreferredViewID)
	}
}

func TestListPresentationsBinaryObjectPrefersHex(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)

	// High-entropy binary: many NULs and non-printables.
	bin := make([]byte, 512)
	for i := range bin {
		bin[i] = byte(i % 256)
	}
	ev, err := c.ImportEvidence(ctx, "blob.bin", EvidenceSpec{
		Label: "blob", Acquisition: AcquisitionSpec{Method: "test"},
	}, bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}

	cat, err := c.ListPresentations(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject})
	if err != nil {
		t.Fatal(err)
	}
	if cat.PreferredViewID != ViewHexV1 {
		t.Fatalf("binary preferred = %q, want hex", cat.PreferredViewID)
	}
	views := viewMap(cat.Views)
	if views[ViewTextV1].Available {
		t.Fatalf("text should be unavailable for binary: %#v", views[ViewTextV1])
	}
	if views[ViewTextV1].Reason == "" {
		t.Fatal("expected reason for unavailable text view")
	}
	if !views[ViewHexV1].Available || !views[ViewMetadataV1].Available {
		t.Fatalf("hex and metadata should be available: %#v", cat.Views)
	}
}

func TestPresentMetadataHexTextWindows(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)

	body := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	ev, err := c.ImportEvidence(ctx, "alpha.txt", EvidenceSpec{
		Label: "alpha", Acquisition: AcquisitionSpec{Method: "lab-copy", SourceURI: "file://alpha.txt", Custodian: "analyst"},
	}, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	// Evidence metadata includes root object id.
	meta, err := c.Present(ctx, EntityRef{ID: string(ev.ID), Kind: EntityEvidence}, ViewMetadataV1, PresentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Encoding != EncodingFields {
		t.Fatalf("encoding = %q", meta.Encoding)
	}
	fields := fieldMap(meta.Fields)
	if fields["root_object.id"] != string(ev.RootObject.ID) {
		t.Fatalf("root_object.id = %q", fields["root_object.id"])
	}
	if fields["label"] != "alpha" {
		t.Fatalf("label = %q", fields["label"])
	}
	if fields["acquisition.method"] != "lab-copy" {
		t.Fatalf("method = %q", fields["acquisition.method"])
	}

	// Object hex window with offset/length.
	hexPres, err := c.Present(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject}, ViewHexV1, PresentOptions{
		Offset: 4, Length: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if hexPres.HexWindow == nil {
		t.Fatal("expected hex_window")
	}
	hw := hexPres.HexWindow
	if hw.Offset != 4 || hw.Length != 8 {
		t.Fatalf("hex window offset/len = %d/%d", hw.Offset, hw.Length)
	}
	if hw.TotalSize != int64(len(body)) {
		t.Fatalf("total_size = %d", hw.TotalSize)
	}
	wantHex := hex.EncodeToString(body[4 : 4+8])
	if hw.Hex != wantHex {
		t.Fatalf("hex = %q, want %q", hw.Hex, wantHex)
	}
	if hw.ASCII != "EFGHIJKL" {
		t.Fatalf("ascii = %q", hw.ASCII)
	}
	if !hw.Truncated {
		t.Fatal("expected truncated when window is partial")
	}

	// Evidence hex delegates to root object.
	evHex, err := c.Present(ctx, EntityRef{ID: string(ev.ID), Kind: EntityEvidence}, ViewHexV1, PresentOptions{Length: 4})
	if err != nil {
		t.Fatal(err)
	}
	if evHex.HexWindow == nil || evHex.HexWindow.Hex != hex.EncodeToString(body[:4]) {
		t.Fatalf("evidence hex = %#v", evHex.HexWindow)
	}

	// Text view.
	textPres, err := c.Present(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject}, ViewTextV1, PresentOptions{Offset: 0, Length: 10})
	if err != nil {
		t.Fatal(err)
	}
	if textPres.Text == nil || textPres.Text.Text != "ABCDEFGHIJ" {
		t.Fatalf("text = %#v", textPres.Text)
	}
	if textPres.Text.Encoding != "utf-8" {
		t.Fatalf("text encoding = %q", textPres.Text.Encoding)
	}
}

func TestPresentClampsMaxLength(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)

	// Larger than MaxPresentLength.
	body := bytes.Repeat([]byte("a"), int(MaxPresentLength)+2048)
	ev, err := c.ImportEvidence(ctx, "large.txt", EvidenceSpec{
		Label: "large", Acquisition: AcquisitionSpec{Method: "test"},
	}, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	pres, err := c.Present(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject}, ViewHexV1, PresentOptions{
		Offset: 0, Length: MaxPresentLength * 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pres.HexWindow == nil {
		t.Fatal("expected hex window")
	}
	if int64(pres.HexWindow.Length) != MaxPresentLength {
		t.Fatalf("length = %d, want clamped to %d", pres.HexWindow.Length, MaxPresentLength)
	}
	if !pres.HexWindow.Truncated {
		t.Fatal("expected truncated for large object")
	}
	if pres.HexWindow.TotalSize != int64(len(body)) {
		t.Fatalf("total_size = %d", pres.HexWindow.TotalSize)
	}
}

func TestPresentDefaultLength(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)

	body := bytes.Repeat([]byte("x"), int(DefaultPresentLength)+100)
	ev, err := c.ImportEvidence(ctx, "def.txt", EvidenceSpec{
		Label: "def", Acquisition: AcquisitionSpec{Method: "test"},
	}, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	pres, err := c.Present(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject}, ViewHexV1, PresentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if int64(pres.HexWindow.Length) != DefaultPresentLength {
		t.Fatalf("default length = %d, want %d", pres.HexWindow.Length, DefaultPresentLength)
	}
}

func TestPresentArtifactAndSelectionMetadata(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)

	ev, err := c.ImportEvidence(ctx, "src.bin", EvidenceSpec{
		Label: "src", Acquisition: AcquisitionSpec{Method: "test"},
	}, bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	art, sel := createArtifactAndSelection(t, ctx, c, ev)

	artCat, err := c.ListPresentations(ctx, EntityRef{ID: string(art.ID), Kind: EntityArtifact})
	if err != nil {
		t.Fatal(err)
	}
	if artCat.PreferredViewID != ViewMetadataV1 || len(artCat.Views) != 1 {
		t.Fatalf("artifact catalog = %#v", artCat)
	}
	artPres, err := c.Present(ctx, EntityRef{ID: string(art.ID), Kind: EntityArtifact}, ViewMetadataV1, PresentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	af := fieldMap(artPres.Fields)
	if af["type"] == "" {
		t.Fatalf("artifact fields missing type: %#v", artPres.Fields)
	}
	if !strings.Contains(strings.Join(keys(artPres.Fields), ","), "value[") {
		t.Fatalf("expected value rows: %#v", artPres.Fields)
	}

	selCat, err := c.ListPresentations(ctx, EntityRef{ID: string(sel.ID), Kind: EntitySelection})
	if err != nil {
		t.Fatal(err)
	}
	if selCat.PreferredViewID != ViewMetadataV1 {
		t.Fatalf("selection preferred = %q", selCat.PreferredViewID)
	}
	selPres, err := c.Present(ctx, EntityRef{ID: string(sel.ID), Kind: EntitySelection}, ViewMetadataV1, PresentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sf := fieldMap(selPres.Fields)
	if sf["name"] == "" {
		t.Fatalf("selection name missing: %#v", selPres.Fields)
	}
	if sf["member_count"] == "0" {
		t.Fatalf("expected members: %#v", selPres.Fields)
	}
}

func createArtifactAndSelection(t *testing.T, ctx context.Context, c *Case, ev Evidence) (ArtifactRef, Selection) {
	t.Helper()
	s, err := c.StartSession(ctx, SessionSpec{Label: "artifact-session"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)

	parser := &presentationTestParser{}
	result, err := s.ParseObject(ctx, ev.RootObject, parser, ParseOptions{})
	if err != nil {
		t.Fatalf("ParseObject: %v", err)
	}
	var art ArtifactRef
	for _, out := range result.Outputs {
		if out.Kind == EntityArtifact {
			loaded, loadErr := c.Artifact(ctx, ArtifactID(out.ID))
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			art = loaded
			break
		}
	}
	if art.ID == "" {
		t.Fatalf("no artifact in parse outputs: %#v", result.Outputs)
	}

	sel, err := s.Freeze(ctx, FreezeSpec{
		Name:  "all-objects",
		Query: KindIs(EntityObject),
	})
	if err != nil {
		t.Fatal(err)
	}
	return art, sel
}

type presentationTestParser struct{}

func (p *presentationTestParser) Descriptor() ParserDescriptor {
	return ParserDescriptor{
		ID:            "test.presentation.parser",
		Version:       "1",
		Deterministic: true,
	}
}

func (p *presentationTestParser) Probe(ctx context.Context, r ObjectReader) (ProbeResult, error) {
	return ProbeResult{Supported: true, Confidence: 1}, nil
}

func (p *presentationTestParser) Parse(ctx context.Context, request ParseRequest, sink Sink) error {
	_, err := sink.EmitArtifact(ctx, "main", ArtifactDraft{
		Type:        "test.presentation/v1",
		DisplayName: "presentation-art",
		Source:      request.Input.ID,
		Values: []ArtifactValue{
			{Property: "greeting", Type: ValueString, Raw: "hi", Normalized: "hi"},
			{Property: "count", Type: ValueInteger, Raw: "3", Normalized: int64(3)},
		},
	})
	return err
}

func TestPresentErrors(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)

	ev, err := c.ImportEvidence(ctx, "x.bin", EvidenceSpec{
		Label: "x", Acquisition: AcquisitionSpec{Method: "test"},
	}, bytes.NewReader([]byte{0x00, 0x01, 0x02, 0xff}))
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.ListPresentations(ctx, EntityRef{ID: "missing", Kind: EntityEvidence})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing entity: %v", err)
	}

	_, err = c.ListPresentations(ctx, EntityRef{ID: string(ev.ID), Kind: EntityFindingRevision})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported kind: %v", err)
	}

	_, err = c.Present(ctx, EntityRef{ID: string(ev.ID), Kind: EntityEvidence}, "nope", PresentOptions{})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown view: %v", err)
	}

	_, err = c.Present(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject}, ViewTextV1, PresentOptions{})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("text on binary: %v", err)
	}

	_, err = c.Present(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject}, ViewHexV1, PresentOptions{Offset: -1})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative offset: %v", err)
	}

	_, err = c.Present(ctx, EntityRef{}, ViewMetadataV1, PresentOptions{})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty entity: %v", err)
	}

	// Offset beyond end.
	_, err = c.Present(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject}, ViewHexV1, PresentOptions{Offset: 1000})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("offset beyond: %v", err)
	}
}

func TestPresentReadOnlyNoMutation(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	ev, err := c.ImportEvidence(ctx, "ro.txt", EvidenceSpec{
		Label: "ro", Acquisition: AcquisitionSpec{Method: "test"},
	}, bytes.NewReader([]byte("readonly")))
	if err != nil {
		t.Fatal(err)
	}
	infoBefore, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListPresentations(ctx, EntityRef{ID: string(ev.ID), Kind: EntityEvidence})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Present(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject}, ViewHexV1, PresentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	infoAfter, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if infoAfter.Revision != infoBefore.Revision {
		t.Fatalf("presentation mutated revision %d -> %d", infoBefore.Revision, infoAfter.Revision)
	}
}

func TestIsMostlyText(t *testing.T) {
	if !isMostlyText([]byte("hello\nworld\t!")) {
		t.Fatal("plain text")
	}
	if !isMostlyText([]byte{}) {
		t.Fatal("empty")
	}
	if isMostlyText([]byte{0, 1, 2, 3, 4, 5, 0, 0, 0xff}) {
		t.Fatal("binary should fail")
	}
	// JSON-like
	if !isMostlyText([]byte(`{"a":1,"b":"x"}`)) {
		t.Fatal("json")
	}
	// Control-heavy valid UTF-8 must not count as text (regression for
	// denominator that ignored non-printable non-NUL runes).
	ctrl := make([]byte, 100)
	for i := 0; i < 90; i++ {
		ctrl[i] = 0x01
	}
	for i := 90; i < 100; i++ {
		ctrl[i] = 'A'
	}
	if isMostlyText(ctrl) {
		t.Fatal("control-heavy payload must not be mostly text")
	}
}

func TestListPresentationsControlHeavyPrefersHex(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	ctrl := make([]byte, 200)
	for i := 0; i < 180; i++ {
		ctrl[i] = 0x01
	}
	for i := 180; i < 200; i++ {
		ctrl[i] = 'x'
	}
	ev, err := c.ImportEvidence(ctx, "ctrl.bin", EvidenceSpec{
		Label: "ctrl", Acquisition: AcquisitionSpec{Method: "test"},
	}, bytes.NewReader(ctrl))
	if err != nil {
		t.Fatal(err)
	}
	cat, err := c.ListPresentations(ctx, EntityRef{ID: string(ev.RootObject.ID), Kind: EntityObject})
	if err != nil {
		t.Fatal(err)
	}
	if cat.PreferredViewID != ViewHexV1 {
		t.Fatalf("preferred = %q, want hex", cat.PreferredViewID)
	}
	views := viewMap(cat.Views)
	if views[ViewTextV1].Available {
		t.Fatalf("text should be unavailable: %#v", views[ViewTextV1])
	}
}

func TestPresentMetadataFieldAndMemberCaps(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)

	// Many small objects so freeze produces a large selection.
	session, err := c.StartSession(ctx, SessionSpec{Label: "bulk"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)

	n := MaxSelectionMembersListed + 20
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("m-%d.bin", i)
		_, err := c.ImportEvidence(ctx, name, EvidenceSpec{
			Label: name, Acquisition: AcquisitionSpec{Method: "test"},
		}, bytes.NewReader([]byte{byte(i)}))
		if err != nil {
			t.Fatal(err)
		}
	}
	sel, err := session.Freeze(ctx, FreezeSpec{
		Name:  "many-objects",
		Query: KindIs(EntityObject),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Members) <= MaxSelectionMembersListed {
		t.Fatalf("need more members than cap: %d", len(sel.Members))
	}
	pres, err := c.Present(ctx, EntityRef{ID: string(sel.ID), Kind: EntitySelection}, ViewMetadataV1, PresentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !pres.Truncated {
		t.Fatal("expected truncated selection metadata")
	}
	memberRows := 0
	for _, f := range pres.Fields {
		if strings.HasPrefix(f.Key, "member[") {
			memberRows++
		}
	}
	if memberRows > MaxSelectionMembersListed {
		t.Fatalf("member rows = %d, max %d", memberRows, MaxSelectionMembersListed)
	}
	if len(pres.Fields) > MaxMetadataFields {
		t.Fatalf("fields = %d, max %d", len(pres.Fields), MaxMetadataFields)
	}

	// Long field value truncation via artifact property.
	ev, err := c.ImportEvidence(ctx, "art-src.bin", EvidenceSpec{
		Label: "art-src", Acquisition: AcquisitionSpec{Method: "test"},
	}, bytes.NewReader([]byte("src")))
	if err != nil {
		t.Fatal(err)
	}
	parser := &presentationLongValueParser{}
	result, err := session.ParseObject(ctx, ev.RootObject, parser, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var artID string
	for _, out := range result.Outputs {
		if out.Kind == EntityArtifact {
			artID = out.ID
			break
		}
	}
	if artID == "" {
		t.Fatal("no artifact")
	}
	artPres, err := c.Present(ctx, EntityRef{ID: artID, Kind: EntityArtifact}, ViewMetadataV1, PresentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !artPres.Truncated {
		t.Fatal("expected truncated long value")
	}
	for _, f := range artPres.Fields {
		if strings.HasSuffix(f.Key, ".raw") && len(f.Value) > MaxFieldValueBytes {
			t.Fatalf("raw value length %d exceeds max", len(f.Value))
		}
	}
}

type presentationLongValueParser struct{}

func (p *presentationLongValueParser) Descriptor() ParserDescriptor {
	return ParserDescriptor{ID: "test.presentation.long", Version: "1", Deterministic: true}
}

func (p *presentationLongValueParser) Probe(ctx context.Context, r ObjectReader) (ProbeResult, error) {
	return ProbeResult{Supported: true, Confidence: 1}, nil
}

func (p *presentationLongValueParser) Parse(ctx context.Context, request ParseRequest, sink Sink) error {
	long := strings.Repeat("Z", MaxFieldValueBytes+512)
	_, err := sink.EmitArtifact(ctx, "main", ArtifactDraft{
		Type:        "test.presentation.long/v1",
		DisplayName: "long",
		Source:      request.Input.ID,
		Values: []ArtifactValue{
			{Property: "blob", Type: ValueString, Raw: long, Normalized: long},
		},
	})
	return err
}

func TestPresentAcquisitionHashOrderStable(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	// Use non-SHA-256 algorithm names so import does not integrity-check them.
	ev, err := c.ImportEvidence(ctx, "h.bin", EvidenceSpec{
		Label: "h",
		Acquisition: AcquisitionSpec{
			Method: "test",
			SuppliedHashes: map[string]string{
				"z-hash": "aaa",
				"a-hash": "bbb",
				"m-hash": "ccc",
			},
		},
	}, bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for i := 0; i < 5; i++ {
		pres, err := c.Present(ctx, EntityRef{ID: string(ev.ID), Kind: EntityEvidence}, ViewMetadataV1, PresentOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range pres.Fields {
			if strings.HasPrefix(f.Key, "acquisition.hash.") {
				got = append(got, f.Key)
			}
		}
		if i == 0 {
			keys = got
			continue
		}
		if strings.Join(got, ",") != strings.Join(keys, ",") {
			t.Fatalf("hash field order unstable: %v vs %v", keys, got)
		}
	}
	want := []string{"acquisition.hash.a-hash", "acquisition.hash.m-hash", "acquisition.hash.z-hash"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
}

func viewMap(views []PresentationViewInfo) map[string]PresentationViewInfo {
	m := make(map[string]PresentationViewInfo, len(views))
	for _, v := range views {
		m[v.ID] = v
	}
	return m
}

func fieldMap(fields []FieldRow) map[string]string {
	m := make(map[string]string, len(fields))
	for _, f := range fields {
		m[f.Key] = f.Value
	}
	return m
}

func keys(fields []FieldRow) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.Key
	}
	return out
}
