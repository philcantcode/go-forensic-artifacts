package forensic_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	forensic "github.com/philcantcode/go-forensic-artifacts"
)

func ExampleCase_ImportSourceTree() {
	ctx := context.Background()
	base, _ := os.MkdirTemp("", "forensic-example-")
	defer os.RemoveAll(base)
	source := filepath.Join(base, "source")
	_ = os.Mkdir(source, 0700)
	_ = os.WriteFile(filepath.Join(source, "main.go"), []byte("package main\n"), 0600)

	repository, _ := forensic.Open(ctx, forensic.Config{Root: filepath.Join(base, "repository")})
	defer repository.Close()
	caseFile, _ := repository.CreateCase(ctx, forensic.CaseSpec{Name: "source review"})
	defer caseFile.Close()

	tree, _ := caseFile.ImportSourceTree(ctx, source, forensic.SourceTreeSpec{
		Label:          "reviewed source",
		Acquisition:    forensic.AcquisitionSpec{Method: "working-tree copy"},
		IdempotencyKey: "reviewed-source-v1",
	})
	fmt.Println(tree.FileCount, tree.Entries[0].Path)

	// Output: 1 main.go
}
