package forensic

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzSanitizeComponent(f *testing.F) {
	for _, seed := range []string{"../escape", "CON", "a/b\\c", "normal.txt", "\x00bad", "évidence"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		out := sanitizeComponent(input)
		if out == "" || out == "." || out == ".." || strings.ContainsAny(out, `/:\\`) {
			t.Fatalf("unsafe result %q for %q", out, input)
		}
	})
}

func FuzzProjectionManifestRoundTrip(f *testing.F) {
	f.Add("obj_0190123456787abc8def0123456789ab", "safe/file.bin", int64(12))
	f.Fuzz(func(t *testing.T, id, path string, size int64) {
		if len(id) > 256 || len(path) > 1024 {
			return
		}
		m := ProjectionManifest{Format: 1, Case: CaseID("case_0190123456787abc8def0123456789ab"), Projection: ProjectionID("prj_0190123456787abc8def0123456789ab"), Selection: SelectionID("sel_0190123456787abc8def0123456789ab"), Entries: []ManifestEntry{{Entity: EntityRef{ID: id, Kind: EntityObject}, Path: path, Size: size}}}
		b, err := canonicalJSON(m)
		if err != nil {
			t.Fatal(err)
		}
		var got ProjectionManifest
		if err = json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Entries) != 1 || got.Entries[0].Entity.ID != id || got.Entries[0].Path != path || got.Entries[0].Size != size {
			t.Fatalf("round trip mismatch: %#v", got)
		}
	})
}
