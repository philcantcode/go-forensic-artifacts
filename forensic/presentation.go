package forensic

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// Stable presentation view identifiers (versioned namespace).
const (
	ViewMetadataV1 = "forensic.metadata/v1"
	ViewHexV1      = "forensic.hex/v1"
	ViewTextV1     = "forensic.text/v1"
)

// Presentation window and metadata bounds. Present clamps byte windows and
// metadata field lists server-side so hosts cannot amplify memory via large
// selections or artifact value tables.
const (
	DefaultPresentLength int64 = 16 * 1024 // 16 KiB
	MaxPresentLength     int64 = 64 * 1024 // 64 KiB
	// textProbeBytes is how many leading bytes are sampled for text suitability.
	textProbeBytes = 4 * 1024
	// MaxMetadataFields caps fields encoding rows (including member samples).
	MaxMetadataFields = 256
	// MaxFieldValueBytes truncates individual field values (UTF-8 safe cut).
	MaxFieldValueBytes = 4 * 1024
	// MaxSelectionMembersListed caps member[...] rows in selection metadata.
	MaxSelectionMembersListed = 64
)

// PresentationEncoding identifies the payload shape of a Presentation.
type PresentationEncoding string

const (
	EncodingFields    PresentationEncoding = "fields"
	EncodingHexWindow PresentationEncoding = "hex_window"
	EncodingText      PresentationEncoding = "text"
)

// PresentationViewInfo describes one available or unavailable view for an entity.
type PresentationViewInfo struct {
	ID        string               `json:"id"`
	Title     string               `json:"title"`
	Encoding  PresentationEncoding `json:"encoding"`
	Available bool                 `json:"available"`
	Reason    string               `json:"reason,omitempty"`
}

// PresentationCatalog is the read-only view menu for an entity.
type PresentationCatalog struct {
	Entity          EntityRef              `json:"entity"`
	PreferredViewID string                 `json:"preferred_view_id"`
	Views           []PresentationViewInfo `json:"views"`
}

// PresentOptions controls windowed byte views. Zero Length means DefaultPresentLength.
type PresentOptions struct {
	Offset int64 `json:"offset,omitempty"`
	Length int64 `json:"length,omitempty"`
}

// FieldRow is one key/value metadata row.
type FieldRow struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// HexWindow is a bounded hex dump of object bytes.
type HexWindow struct {
	Offset    int64  `json:"offset"`
	Length    int    `json:"length"`
	TotalSize int64  `json:"total_size"`
	Truncated bool   `json:"truncated"`
	// Hex is lowercase continuous hex of the window (2 chars per byte).
	Hex string `json:"hex"`
	// ASCII is a printable-side rendering (non-printable as '.').
	ASCII string `json:"ascii,omitempty"`
}

// TextWindow is a bounded decoded text window.
type TextWindow struct {
	Offset    int64  `json:"offset"`
	Length    int    `json:"length"`
	TotalSize int64  `json:"total_size"`
	Truncated bool   `json:"truncated"`
	// Encoding names the decode used (currently "utf-8").
	Encoding string `json:"encoding"`
	Text     string `json:"text"`
}

// Presentation is one view payload. Exactly one of Fields, HexWindow, or Text
// is populated according to Encoding.
//
// Truncated is true when fields were capped (metadata) or when a byte window
// does not cover the full object (also mirrored on HexWindow/Text).
type Presentation struct {
	ViewID    string               `json:"view_id"`
	Encoding  PresentationEncoding `json:"encoding"`
	// Truncated is set when metadata fields or listed members were capped.
	Truncated bool `json:"truncated,omitempty"`
	// TruncationReason explains a Truncated metadata presentation.
	TruncationReason string      `json:"truncation_reason,omitempty"`
	Fields           []FieldRow  `json:"fields,omitempty"`
	HexWindow        *HexWindow  `json:"hex_window,omitempty"`
	Text             *TextWindow `json:"text,omitempty"`
}

// ListPresentations returns which presentation views exist for entity and which
// is preferred. Read-only; does not mutate the case.
func (c *Case) ListPresentations(ctx context.Context, entity EntityRef) (PresentationCatalog, error) {
	if err := c.checkOpen(); err != nil {
		return PresentationCatalog{}, err
	}
	if err := ctx.Err(); err != nil {
		return PresentationCatalog{}, err
	}
	if strings.TrimSpace(entity.ID) == "" || entity.Kind == "" {
		return PresentationCatalog{}, fmt.Errorf("%w: entity id and kind are required", ErrInvalid)
	}

	switch entity.Kind {
	case EntityEvidence:
		return c.catalogEvidence(ctx, entity)
	case EntityObject:
		return c.catalogObject(ctx, entity)
	case EntityArtifact:
		return c.catalogArtifact(ctx, entity)
	case EntitySelection:
		return c.catalogSelection(ctx, entity)
	default:
		return PresentationCatalog{}, fmt.Errorf("%w: presentation for kind %q", ErrUnsupported, entity.Kind)
	}
}

// Present returns a single view payload for entity. Read-only; byte windows
// are clamped to MaxPresentLength.
func (c *Case) Present(ctx context.Context, entity EntityRef, viewID string, opts PresentOptions) (Presentation, error) {
	if err := c.checkOpen(); err != nil {
		return Presentation{}, err
	}
	if err := ctx.Err(); err != nil {
		return Presentation{}, err
	}
	if strings.TrimSpace(entity.ID) == "" || entity.Kind == "" {
		return Presentation{}, fmt.Errorf("%w: entity id and kind are required", ErrInvalid)
	}
	viewID = strings.TrimSpace(viewID)
	if viewID == "" {
		return Presentation{}, fmt.Errorf("%w: view id is required", ErrInvalid)
	}
	if opts.Offset < 0 {
		return Presentation{}, fmt.Errorf("%w: offset must be non-negative", ErrInvalid)
	}
	if opts.Length < 0 {
		return Presentation{}, fmt.Errorf("%w: length must be non-negative", ErrInvalid)
	}

	switch entity.Kind {
	case EntityEvidence:
		return c.presentEvidence(ctx, entity, viewID, opts)
	case EntityObject:
		return c.presentObject(ctx, entity, viewID, opts)
	case EntityArtifact:
		return c.presentArtifact(ctx, entity, viewID, opts)
	case EntitySelection:
		return c.presentSelection(ctx, entity, viewID, opts)
	default:
		return Presentation{}, fmt.Errorf("%w: presentation for kind %q", ErrUnsupported, entity.Kind)
	}
}

func (c *Case) catalogEvidence(ctx context.Context, entity EntityRef) (PresentationCatalog, error) {
	ev, err := c.Evidence(ctx, EvidenceID(entity.ID))
	if err != nil {
		return PresentationCatalog{}, err
	}
	textAvail, textReason := c.objectTextAvailability(ctx, ev.RootObject.ID)
	return PresentationCatalog{
		Entity:          EntityRef{ID: string(ev.ID), Kind: EntityEvidence},
		PreferredViewID: ViewMetadataV1,
		Views: []PresentationViewInfo{
			{ID: ViewMetadataV1, Title: "Metadata", Encoding: EncodingFields, Available: true},
			{ID: ViewHexV1, Title: "Hex", Encoding: EncodingHexWindow, Available: true},
			{ID: ViewTextV1, Title: "Text", Encoding: EncodingText, Available: textAvail, Reason: textReason},
		},
	}, nil
}

func (c *Case) catalogObject(ctx context.Context, entity EntityRef) (PresentationCatalog, error) {
	obj, err := c.Object(ctx, ObjectID(entity.ID))
	if err != nil {
		return PresentationCatalog{}, err
	}
	textAvail, textReason := c.objectTextAvailability(ctx, obj.ID)
	preferred := ViewHexV1
	if textAvail {
		preferred = ViewTextV1
	}
	return PresentationCatalog{
		Entity:          EntityRef{ID: string(obj.ID), Kind: EntityObject},
		PreferredViewID: preferred,
		Views: []PresentationViewInfo{
			{ID: ViewMetadataV1, Title: "Metadata", Encoding: EncodingFields, Available: true},
			{ID: ViewHexV1, Title: "Hex", Encoding: EncodingHexWindow, Available: true},
			{ID: ViewTextV1, Title: "Text", Encoding: EncodingText, Available: textAvail, Reason: textReason},
		},
	}, nil
}

func (c *Case) catalogArtifact(ctx context.Context, entity EntityRef) (PresentationCatalog, error) {
	art, err := c.Artifact(ctx, ArtifactID(entity.ID))
	if err != nil {
		return PresentationCatalog{}, err
	}
	return PresentationCatalog{
		Entity:          EntityRef{ID: string(art.ID), Kind: EntityArtifact},
		PreferredViewID: ViewMetadataV1,
		Views: []PresentationViewInfo{
			{ID: ViewMetadataV1, Title: "Metadata", Encoding: EncodingFields, Available: true},
		},
	}, nil
}

func (c *Case) catalogSelection(ctx context.Context, entity EntityRef) (PresentationCatalog, error) {
	sel, err := c.Selection(ctx, SelectionID(entity.ID))
	if err != nil {
		return PresentationCatalog{}, err
	}
	return PresentationCatalog{
		Entity:          EntityRef{ID: string(sel.ID), Kind: EntitySelection},
		PreferredViewID: ViewMetadataV1,
		Views: []PresentationViewInfo{
			{ID: ViewMetadataV1, Title: "Metadata", Encoding: EncodingFields, Available: true},
		},
	}, nil
}

func (c *Case) presentEvidence(ctx context.Context, entity EntityRef, viewID string, opts PresentOptions) (Presentation, error) {
	ev, err := c.Evidence(ctx, EvidenceID(entity.ID))
	if err != nil {
		return Presentation{}, err
	}
	switch viewID {
	case ViewMetadataV1:
		fields := []FieldRow{
			{Key: "id", Value: string(ev.ID)},
			{Key: "kind", Value: string(EntityEvidence)},
			{Key: "label", Value: ev.Label},
			{Key: "acquisition.method", Value: ev.Acquisition.Method},
			{Key: "acquisition.source_uri", Value: ev.Acquisition.SourceURI},
			{Key: "acquisition.custodian", Value: ev.Acquisition.Custodian},
			{Key: "root_object.id", Value: string(ev.RootObject.ID)},
			{Key: "root_object.display_name", Value: ev.RootObject.DisplayName},
			{Key: "root_object.path", Value: ev.RootObject.Path},
			{Key: "root_object.media_type", Value: ev.RootObject.MediaType},
			{Key: "root_object.size", Value: fmt.Sprintf("%d", ev.RootObject.Size)},
			{Key: "root_object.blob", Value: string(ev.RootObject.Blob)},
			{Key: "created_revision", Value: fmt.Sprintf("%d", ev.CreatedRevision)},
		}
		if len(ev.Acquisition.SuppliedHashes) > 0 {
			algos := make([]string, 0, len(ev.Acquisition.SuppliedHashes))
			for algo := range ev.Acquisition.SuppliedHashes {
				algos = append(algos, algo)
			}
			sort.Strings(algos)
			for _, algo := range algos {
				fields = append(fields, FieldRow{
					Key:   "acquisition.hash." + algo,
					Value: ev.Acquisition.SuppliedHashes[algo],
				})
			}
		}
		return finishFieldsPresentation(viewID, fields), nil
	case ViewHexV1, ViewTextV1:
		return c.presentObjectBytes(ctx, ev.RootObject.ID, viewID, opts)
	default:
		return Presentation{}, fmt.Errorf("%w: unknown view %q for evidence", ErrInvalid, viewID)
	}
}

func (c *Case) presentObject(ctx context.Context, entity EntityRef, viewID string, opts PresentOptions) (Presentation, error) {
	obj, err := c.Object(ctx, ObjectID(entity.ID))
	if err != nil {
		return Presentation{}, err
	}
	switch viewID {
	case ViewMetadataV1:
		return finishFieldsPresentation(viewID, []FieldRow{
			{Key: "id", Value: string(obj.ID)},
			{Key: "kind", Value: string(EntityObject)},
			{Key: "display_name", Value: obj.DisplayName},
			{Key: "path", Value: obj.Path},
			{Key: "media_type", Value: obj.MediaType},
			{Key: "size", Value: fmt.Sprintf("%d", obj.Size)},
			{Key: "blob", Value: string(obj.Blob)},
			{Key: "generating_activity", Value: string(obj.GeneratingActivity)},
			{Key: "created_revision", Value: fmt.Sprintf("%d", obj.CreatedRevision)},
		}), nil
	case ViewHexV1, ViewTextV1:
		return c.presentObjectBytes(ctx, obj.ID, viewID, opts)
	default:
		return Presentation{}, fmt.Errorf("%w: unknown view %q for object", ErrInvalid, viewID)
	}
}

func (c *Case) presentArtifact(ctx context.Context, entity EntityRef, viewID string, opts PresentOptions) (Presentation, error) {
	_ = opts
	if viewID != ViewMetadataV1 {
		return Presentation{}, fmt.Errorf("%w: unknown view %q for artifact", ErrInvalid, viewID)
	}
	art, err := c.Artifact(ctx, ArtifactID(entity.ID))
	if err != nil {
		return Presentation{}, err
	}
	fields := []FieldRow{
		{Key: "id", Value: string(art.ID)},
		{Key: "kind", Value: string(EntityArtifact)},
		{Key: "type", Value: art.Type},
		{Key: "display_name", Value: art.DisplayName},
		{Key: "source", Value: string(art.Source)},
		{Key: "generating_activity", Value: string(art.GeneratingActivity)},
		{Key: "created_revision", Value: fmt.Sprintf("%d", art.CreatedRevision)},
		{Key: "value_count", Value: fmt.Sprintf("%d", len(art.Values))},
	}
	for i, v := range art.Values {
		prefix := fmt.Sprintf("value[%d]", i)
		fields = append(fields,
			FieldRow{Key: prefix + ".property", Value: v.Property},
			FieldRow{Key: prefix + ".type", Value: string(v.Type)},
			FieldRow{Key: prefix + ".raw", Value: v.Raw},
			FieldRow{Key: prefix + ".normalized", Value: formatNormalized(v.Normalized)},
		)
		if v.Unit != "" {
			fields = append(fields, FieldRow{Key: prefix + ".unit", Value: v.Unit})
		}
		if v.Interpretation != "" {
			fields = append(fields, FieldRow{Key: prefix + ".interpretation", Value: v.Interpretation})
		}
	}
	return finishFieldsPresentation(viewID, fields), nil
}

func (c *Case) presentSelection(ctx context.Context, entity EntityRef, viewID string, opts PresentOptions) (Presentation, error) {
	_ = opts
	if viewID != ViewMetadataV1 {
		return Presentation{}, fmt.Errorf("%w: unknown view %q for selection", ErrInvalid, viewID)
	}
	sel, err := c.Selection(ctx, SelectionID(entity.ID))
	if err != nil {
		return Presentation{}, err
	}
	fields := []FieldRow{
		{Key: "id", Value: string(sel.ID)},
		{Key: "kind", Value: string(EntitySelection)},
		{Key: "name", Value: sel.Name},
		{Key: "observed_revision", Value: fmt.Sprintf("%d", sel.Revision)},
		{Key: "created_revision", Value: fmt.Sprintf("%d", sel.CreatedRevision)},
		{Key: "member_count", Value: fmt.Sprintf("%d", len(sel.Members))},
		{Key: "query.op", Value: string(sel.Query.Op)},
	}
	listed := len(sel.Members)
	if listed > MaxSelectionMembersListed {
		listed = MaxSelectionMembersListed
	}
	for i := 0; i < listed; i++ {
		m := sel.Members[i]
		fields = append(fields, FieldRow{
			Key:   fmt.Sprintf("member[%d]", i),
			Value: string(m.Kind) + ":" + m.ID,
		})
	}
	pres := finishFieldsPresentation(viewID, fields)
	if len(sel.Members) > MaxSelectionMembersListed {
		pres.Truncated = true
		if pres.TruncationReason == "" {
			pres.TruncationReason = fmt.Sprintf(
				"listed %d of %d members (max %d)",
				MaxSelectionMembersListed, len(sel.Members), MaxSelectionMembersListed,
			)
		} else {
			pres.TruncationReason += fmt.Sprintf(
				"; listed %d of %d members",
				MaxSelectionMembersListed, len(sel.Members),
			)
		}
	}
	return pres, nil
}

func (c *Case) presentObjectBytes(ctx context.Context, id ObjectID, viewID string, opts PresentOptions) (Presentation, error) {
	if viewID == ViewTextV1 {
		avail, reason := c.objectTextAvailability(ctx, id)
		if !avail {
			if reason == "" {
				reason = "content is not mostly text"
			}
			return Presentation{}, fmt.Errorf("%w: text view unavailable: %s", ErrInvalid, reason)
		}
	}

	window, total, err := c.readObjectWindow(ctx, id, opts)
	if err != nil {
		return Presentation{}, err
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}
	truncated := offset+int64(len(window)) < total

	switch viewID {
	case ViewHexV1:
		return Presentation{
			ViewID:   viewID,
			Encoding: EncodingHexWindow,
			HexWindow: &HexWindow{
				Offset:    offset,
				Length:    len(window),
				TotalSize: total,
				Truncated: truncated,
				Hex:       hex.EncodeToString(window),
				ASCII:     asciiSide(window),
			},
		}, nil
	case ViewTextV1:
		// Replace invalid UTF-8 sequences so the window is always valid text.
		text := string(window)
		if !utf8.Valid(window) {
			text = strings.ToValidUTF8(text, "\uFFFD")
		}
		return Presentation{
			ViewID:   viewID,
			Encoding: EncodingText,
			Text: &TextWindow{
				Offset:    offset,
				Length:    len(window),
				TotalSize: total,
				Truncated: truncated,
				Encoding:  "utf-8",
				Text:      text,
			},
		}, nil
	default:
		return Presentation{}, fmt.Errorf("%w: unknown byte view %q", ErrInvalid, viewID)
	}
}

func (c *Case) readObjectWindow(ctx context.Context, id ObjectID, opts PresentOptions) ([]byte, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	reader, err := c.OpenObject(ctx, id)
	if err != nil {
		return nil, 0, err
	}
	defer closeReader(reader)

	total := reader.Size()
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		return nil, total, fmt.Errorf("%w: offset %d beyond object size %d", ErrInvalid, offset, total)
	}

	length := opts.Length
	if length <= 0 {
		length = DefaultPresentLength
	}
	if length > MaxPresentLength {
		length = MaxPresentLength
	}
	remain := total - offset
	if length > remain {
		length = remain
	}
	if length == 0 {
		return []byte{}, total, nil
	}

	buf := make([]byte, int(length))
	n, err := reader.ReadAt(buf, offset)
	buf = buf[:n]
	if err != nil && err != io.EOF {
		return nil, total, fmt.Errorf("%w: read object window: %v", ErrIntegrity, err)
	}
	return buf, total, nil
}

// objectTextAvailability samples the start of the object and reports whether
// forensic.text/v1 should be offered. Media types are not trusted alone —
// content is always probed so mislabeled binary cannot advertise text.
func (c *Case) objectTextAvailability(ctx context.Context, id ObjectID) (bool, string) {
	obj, err := c.Object(ctx, id)
	if err != nil {
		return false, "object not readable"
	}
	if obj.Size == 0 {
		return true, ""
	}
	probeLen := int64(textProbeBytes)
	if probeLen > obj.Size {
		probeLen = obj.Size
	}
	window, _, err := c.readObjectWindow(ctx, id, PresentOptions{Offset: 0, Length: probeLen})
	if err != nil {
		return false, "object not readable"
	}
	if isMostlyText(window) {
		return true, ""
	}
	return false, "high binary entropy"
}

func isMostlyText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	// Reject if not mostly valid UTF-8.
	if !utf8.Valid(b) {
		// Allow a small fraction of invalid sequences at the trailing edge of a
		// truncated multi-byte character by checking a slightly shorter slice.
		if len(b) > 4 && utf8.Valid(b[:len(b)-3]) {
			b = b[:len(b)-3]
		} else {
			return false
		}
	}
	printable := 0
	nonPrintable := 0
	nulls := 0
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if size <= 0 {
			return false
		}
		i += size
		if r == 0 {
			nulls++
			continue
		}
		if r == '\t' || r == '\n' || r == '\r' || (r >= 32 && r != 0x7f) {
			printable++
		} else {
			nonPrintable++
		}
	}
	// Too many NULs ⇒ binary.
	if float64(nulls)/float64(len(b)) > 0.01 {
		return false
	}
	// Printable ratio over all non-NUL runes (control bytes lower the ratio).
	content := printable + nonPrintable
	if content == 0 {
		return false
	}
	return float64(printable)/float64(content) >= 0.85
}

// finishFieldsPresentation applies value-length and field-count caps.
func finishFieldsPresentation(viewID string, fields []FieldRow) Presentation {
	out := make([]FieldRow, 0, len(fields))
	valueTruncated := false
	for _, f := range fields {
		v, cut := clampFieldValue(f.Value)
		if cut {
			valueTruncated = true
		}
		out = append(out, FieldRow{Key: f.Key, Value: v})
	}
	fieldTruncated := false
	if len(out) > MaxMetadataFields {
		out = out[:MaxMetadataFields]
		fieldTruncated = true
	}
	pres := Presentation{
		ViewID:   viewID,
		Encoding: EncodingFields,
		Fields:   out,
	}
	if fieldTruncated || valueTruncated {
		pres.Truncated = true
		parts := make([]string, 0, 2)
		if fieldTruncated {
			parts = append(parts, fmt.Sprintf("field rows capped at %d", MaxMetadataFields))
		}
		if valueTruncated {
			parts = append(parts, fmt.Sprintf("values capped at %d bytes", MaxFieldValueBytes))
		}
		pres.TruncationReason = strings.Join(parts, "; ")
	}
	return pres
}

func clampFieldValue(s string) (string, bool) {
	if len(s) <= MaxFieldValueBytes {
		return s, false
	}
	// Cut on a UTF-8 boundary at or before MaxFieldValueBytes.
	cut := MaxFieldValueBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if cut == 0 {
		cut = MaxFieldValueBytes
	}
	return s[:cut], true
}

func asciiSide(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		if c >= 32 && c < 127 {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

func formatNormalized(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
