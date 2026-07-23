package forensic

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
)

func TestProjectionFaultBoundariesLeaveAuthoritativeCaseValid(t *testing.T) {
	for _, point := range []string{"after-projection-create", "after-projection-copy", "after-projection-manifest", "after-projection-publish", "before-catalog-commit", "after-catalog-commit"} {
		t.Run(point, func(t *testing.T) {
			ctx, base, _, c := openTestRepo(t)
			ev, err := c.ImportEvidence(ctx, "input.bin", EvidenceSpec{Label: "input", Acquisition: AcquisitionSpec{Method: "test"}}, bytes.NewReader([]byte("projection bytes")))
			if err != nil {
				t.Fatal(err)
			}
			s, err := c.StartSession(ctx, SessionSpec{Label: "projection fault"})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close(ctx)
			selection, err := s.Freeze(ctx, FreezeSpec{Name: "input", Query: IDIs(string(ev.RootObject.ID))})
			if err != nil {
				t.Fatal(err)
			}
			projection, err := s.CreateProjection(ctx, ProjectionSpec{Selection: selection.ID, Closure: ClosureExact, Layout: LayoutByID, Include: IncludeBytes | IncludeMetadata})
			if err != nil {
				t.Fatal(err)
			}
			triggered := false
			c.faultMu.Lock()
			c.fault = func(got string) error {
				if got == point && !triggered {
					triggered = true
					return fmt.Errorf("injected %s", point)
				}
				return nil
			}
			c.faultMu.Unlock()
			_, materializeErr := s.Materialize(ctx, projection.ID, DirectoryTarget{Path: filepath.Join(base, "fault-workspace"), Writable: true})
			c.faultMu.Lock()
			c.fault = nil
			c.faultMu.Unlock()
			if materializeErr == nil || !triggered {
				t.Fatalf("fault %s was not returned: %v", point, materializeErr)
			}
			report, err := c.Verify(ctx, VerifySpec{Mode: VerifyQuick})
			if err != nil || !report.OK {
				t.Fatalf("case after %s: %#v %v", point, report, err)
			}
		})
	}
}
