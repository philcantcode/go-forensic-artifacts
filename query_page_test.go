package forensic

import (
	"bytes"
	"testing"
)

func TestRevisionPinnedQueryPages(t *testing.T) {
	ctx, _, _, c := openTestRepo(t)
	want := map[string]bool{}
	for i := 0; i < 5; i++ {
		evidence, err := c.ImportEvidence(ctx, "page.txt", EvidenceSpec{Label: "page"}, bytes.NewReader([]byte{byte(i)}))
		if err != nil {
			t.Fatal(err)
		}
		want[string(evidence.RootObject.ID)] = true
	}
	first, err := c.QueryPage(ctx, QueryPageSpec{Query: KindIs(EntityObject), Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Entities) != 2 || first.Next.ID == "" || first.Revision == 0 {
		t.Fatalf("unexpected first page: %#v", first)
	}
	late, err := c.ImportEvidence(ctx, "late.txt", EvidenceSpec{Label: "late"}, bytes.NewReader([]byte("late")))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entity := range first.Entities {
		seen[entity.ID] = true
	}
	next := first.Next
	for next.ID != "" {
		page, pageErr := c.QueryPage(ctx, QueryPageSpec{Query: KindIs(EntityObject), Revision: first.Revision, After: next, Limit: 2})
		if pageErr != nil {
			t.Fatal(pageErr)
		}
		for _, entity := range page.Entities {
			seen[entity.ID] = true
		}
		next = page.Next
	}
	if len(seen) != len(want) || seen[string(late.RootObject.ID)] {
		t.Fatalf("revision-pinned traversal changed: seen=%#v want=%#v", seen, want)
	}
	for id := range want {
		if !seen[id] {
			t.Fatalf("paged traversal missed %s", id)
		}
	}
}
