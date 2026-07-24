package forensic

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentExportsEscapeMarkdownAndRetainLosslessJSONL(t *testing.T) {
	ctx, base, _, c := openTestRepo(t)
	name := "payload ](javascript:alert(1)) | <script>\n# injected"
	evidence, err := c.ImportEvidence(ctx, name, EvidenceSpec{Label: "export source"}, strings.NewReader("bytes"))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.StartSession(ctx, SessionSpec{Label: "exports"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(ctx)
	selection, err := session.Freeze(ctx, FreezeSpec{Name: "agent export", Query: IDIs(string(evidence.RootObject.ID))})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := session.CreateProjection(ctx, ProjectionSpec{Selection: selection.ID, Include: IncludeBytes})
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := session.Materialize(ctx, projection.ID, DirectoryTarget{Path: filepath.Join(base, "export-view")})
	if err != nil {
		t.Fatal(err)
	}
	var markdown bytes.Buffer
	if err = c.ExportMarkdown(ctx, MarkdownSpec{Selection: selection.ID, Writer: &markdown, IncludeHashes: true, IncludeProvenanceSummary: true, Materialization: materialized.ID}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(markdown.String(), "<script>") || !strings.Contains(markdown.String(), "&lt;script&gt;") || !strings.Contains(markdown.String(), "\\|") || !strings.Contains(markdown.String(), "Projected file:") {
		t.Fatalf("unsafe or incomplete Markdown:\n%s", markdown.String())
	}
	var jsonl bytes.Buffer
	if err = c.ExportJSONL(ctx, JSONLSpec{Selection: selection.ID, Writer: &jsonl}); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err = json.Unmarshal(bytes.TrimSpace(jsonl.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record["display_name"] != name || record["object"] == nil || record["activity"] == nil {
		t.Fatalf("JSONL lost typed/raw data: %#v", record)
	}
}
