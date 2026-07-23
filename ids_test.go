package forensic

import (
	"strings"
	"testing"
)

func TestTypedIDsAndCanonicalJSON(t *testing.T) {
	id1, err := newObjectID()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := newObjectID()
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 || !validID(string(id1), "obj_") {
		t.Fatalf("invalid IDs: %q %q", id1, id2)
	}
	if !strings.HasPrefix(string(id1), "obj_") {
		t.Fatalf("missing type prefix: %s", id1)
	}
	a, err := canonicalJSON(map[string]any{"z": 1, "a": map[string]any{"y": 2, "x": 1}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalJSON(map[string]any{"a": map[string]any{"x": 1, "y": 2}, "z": 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) || string(a) != `{"a":{"x":1,"y":2},"z":1}` {
		t.Fatalf("non-canonical JSON: %s / %s", a, b)
	}
}

func TestGlobAndPathSanitization(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"**/*.sqlite", "root/db.sqlite", true},
		{"**/*.sqlite", "db.sqlite", true},
		{"*.json", "a/b.json", false},
		{"config?.json", "config1.json", true},
	} {
		got, err := globMatch(tc.pattern, tc.path)
		if err != nil || got != tc.want {
			t.Fatalf("globMatch(%q,%q)=%v,%v", tc.pattern, tc.path, got, err)
		}
	}
	for _, hostile := range []string{"..", "CON", "a/b", "x:y", " . "} {
		got := sanitizeComponent(hostile)
		if got == "" || got == "." || got == ".." || strings.ContainsAny(got, `/:`) {
			t.Fatalf("unsafe sanitized component %q -> %q", hostile, got)
		}
	}
}
