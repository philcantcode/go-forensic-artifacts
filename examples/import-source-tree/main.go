// Example: import a source directory into a forensic case repository, then
// query .go files from the imported tree.
//
//	go run ./examples/import-source-tree
//
// Optional flags:
//
//	-repo DIR     repository root (default: temporary directory, cleaned up)
//	-source DIR   source tree to import (default: a tiny synthetic tree)
//	-case NAME    case name (default: source-review)
//	-keep         keep the temporary repository when using the default -repo
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	forensic "github.com/philcantcode/go-forensic-artifacts/forensic"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	repoRoot := flag.String("repo", "", "repository root (default: temporary directory)")
	sourceDir := flag.String("source", "", "source tree to import (default: synthetic sample)")
	caseName := flag.String("case", "source-review", "case name")
	keep := flag.Bool("keep", false, "keep temporary repository (only with default -repo)")
	flag.Parse()

	ctx := context.Background()

	cleanup := func() {}
	root := *repoRoot
	if root == "" {
		tmp, err := os.MkdirTemp("", "forensic-example-")
		if err != nil {
			return err
		}
		root = filepath.Join(tmp, "repository")
		if !*keep {
			cleanup = func() { _ = os.RemoveAll(tmp) }
		} else {
			fmt.Printf("repository kept at %s\n", root)
		}
	}
	defer cleanup()

	source := *sourceDir
	if source == "" {
		tmpSource, err := os.MkdirTemp("", "forensic-source-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpSource)
		source = tmpSource
		if err := os.WriteFile(filepath.Join(source, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("# sample\n"), 0o600); err != nil {
			return err
		}
	}

	repo, err := forensic.Open(ctx, forensic.Config{
		Root: root,
		DefaultAgent: forensic.AgentSpec{
			Kind: forensic.AgentSoftware,
			Name: "import-source-tree-example",
		},
	})
	if err != nil {
		return fmt.Errorf("open repository: %w", err)
	}
	defer repo.Close()

	// Create or reopen the case so the example is re-runnable against a fixed -repo.
	var caseFile *forensic.Case
	caseFile, err = repo.CreateCase(ctx, forensic.CaseSpec{
		Name:        *caseName,
		Description: "example source-tree import",
	})
	if err != nil {
		// Reopen if the case already exists (idempotent demo against a kept repo).
		caseFile, err = repo.OpenCase(ctx, forensic.ByName(*caseName))
		if err != nil {
			return fmt.Errorf("create/open case: %w", err)
		}
	}
	defer caseFile.Close()

	info, err := caseFile.Info(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("case %s (%s) at revision %d\n", info.Name, info.ID, info.Revision)

	tree, err := caseFile.ImportSourceTree(ctx, source, forensic.SourceTreeSpec{
		Label: "reviewed source",
		Acquisition: forensic.AcquisitionSpec{
			Method: "working-tree copy",
		},
		IdempotencyKey: "example-import-source-tree-v1",
	})
	if err != nil {
		return fmt.Errorf("import source tree: %w", err)
	}
	fmt.Printf("imported tree %s: %d files, %d bytes, digest %s\n",
		tree.ID, tree.FileCount, tree.TotalBytes, tree.TreeDigest)

	files, err := caseFile.Query(ctx, forensic.And(
		forensic.InTree(tree.ID),
		forensic.ExtensionIs(".go"),
	))
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	fmt.Printf("go files in tree: %d (case revision %d)\n", len(files.Entities), files.Revision)
	for _, e := range files.Entities {
		obj, err := caseFile.Object(ctx, forensic.ObjectID(e.ID))
		if err != nil {
			return err
		}
		fmt.Printf("  %s  %s  %d bytes  %s\n", obj.ID, obj.DisplayName, obj.Size, obj.Blob)
	}

	report, err := caseFile.Verify(ctx, forensic.VerifySpec{Mode: forensic.VerifyQuick})
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if !report.OK {
		return fmt.Errorf("verify failed: %+v", report.Issues)
	}
	fmt.Printf("verify ok (mode=%s, checked_blobs=%d)\n", report.Mode, report.CheckedBlobs)
	return nil
}
