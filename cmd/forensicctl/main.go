// Command forensicctl is a small CLI for the forensic case repository library.
//
// It is intentionally thin: durable case state lives in the library, and this
// tool only exposes common operator workflows (create/list cases, import
// evidence, verify integrity, query entities, and text search).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	forensic "github.com/philcantcode/go-forensic-artifacts/forensic"
)

const version = "0.2.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return 2
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return 0
	case "version", "-version", "--version":
		fmt.Printf("forensicctl %s\n", version)
		return 0
	}

	// Global flags appear before the subcommand: forensicctl -repo PATH <cmd> ...
	fs := flag.NewFlagSet("forensicctl", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	repoRoot := fs.String("repo", envOr("FORENSIC_REPO", ""), "repository root directory (or FORENSIC_REPO)")
	agentName := fs.String("agent", envOr("FORENSIC_AGENT", "forensicctl"), "default software agent name")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON where applicable")
	fs.Usage = func() { printUsage(os.Stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		printUsage(os.Stderr)
		return 2
	}
	cmd, rest := rest[0], rest[1:]

	ctx := context.Background()
	switch cmd {
	case "case":
		return cmdCase(ctx, *repoRoot, *agentName, *jsonOut, rest)
	case "import":
		return cmdImport(ctx, *repoRoot, *agentName, *jsonOut, rest)
	case "verify":
		return cmdVerify(ctx, *repoRoot, *agentName, *jsonOut, rest)
	case "query":
		return cmdQuery(ctx, *repoRoot, *agentName, *jsonOut, rest)
	case "search":
		return cmdSearch(ctx, *repoRoot, *agentName, *jsonOut, rest)
	case "recover":
		return cmdRecover(ctx, *repoRoot, *agentName, *jsonOut, rest)
	case "help":
		printUsage(os.Stdout)
		return 0
	case "version":
		fmt.Printf("forensicctl %s\n", version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		printUsage(os.Stderr)
		return 2
	}
}

func printUsage(w *os.File) {
	fmt.Fprintf(w, `forensicctl — operator CLI for go-forensic-artifacts

Usage:
  forensicctl [global flags] <command> [command flags] [args]

Global flags:
  -repo PATH     repository root (required for most commands; or FORENSIC_REPO)
  -agent NAME    default software agent name (default: forensicctl)
  -json          emit JSON for structured commands

Commands:
  version                         print CLI version
  case create <name>              create a case
  case list                       list active cases
  case info <name-or-id>          show case metadata
  import file <path>              import a regular file as evidence
  import tree <path>              import a directory as a source tree
  verify                          verify case integrity
  query                           list entities matching simple filters
  search <text>                   FTS5 / literal text search over catalog text
  recover inspect                 report recovery issues without mutating data

Examples:
  forensicctl -repo /srv/forensics case create router-firmware
  forensicctl -repo /srv/forensics import tree ./src --case router-firmware
  forensicctl -repo /srv/forensics verify --case router-firmware --mode full
  forensicctl -repo /srv/forensics query --case router-firmware --kind object --ext .go
`)
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// parseFlexible allows flags before or after positional arguments so callers can
// write either `import tree --case x ./src` or `import tree ./src --case x`.
func parseFlexible(fs *flag.FlagSet, args []string) error {
	return fs.Parse(reorderFlagArgs(fs, args))
}

func reorderFlagArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			positionals = append(positionals, a)
			continue
		}
		name, hasValue := splitFlagToken(a)
		flags = append(flags, a)
		if hasValue {
			continue
		}
		if isBoolFlag(fs, name) {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}

func splitFlagToken(a string) (name string, hasInlineValue bool) {
	a = strings.TrimLeft(a, "-")
	if i := strings.IndexByte(a, '='); i >= 0 {
		return a[:i], true
	}
	return a, false
}

func isBoolFlag(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
		return bf.IsBoolFlag()
	}
	return false
}

func openRepo(ctx context.Context, root, agent string) (*forensic.Repository, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("%w: -repo is required (or set FORENSIC_REPO)", forensic.ErrInvalid)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return forensic.Open(ctx, forensic.Config{
		Root: abs,
		DefaultAgent: forensic.AgentSpec{
			Kind: forensic.AgentSoftware,
			Name: agent,
		},
	})
}

func openCase(ctx context.Context, repo *forensic.Repository, selector string) (*forensic.Case, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, fmt.Errorf("%w: --case is required", forensic.ErrInvalid)
	}
	if strings.HasPrefix(selector, "case_") {
		return repo.OpenCase(ctx, forensic.ByID(forensic.CaseID(selector)))
	}
	return repo.OpenCase(ctx, forensic.ByName(selector))
}

func writeJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
		return 1
	}
	return 0
}

func fail(err error) int {
	if err == nil {
		return 0
	}
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	switch {
	case errors.Is(err, forensic.ErrNotFound):
		return 3
	case errors.Is(err, forensic.ErrIntegrity):
		return 4
	case errors.Is(err, forensic.ErrInvalid):
		return 2
	default:
		return 1
	}
}

// --- case -------------------------------------------------------------------

func cmdCase(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: forensicctl case <create|list|info> ...")
		return 2
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "create":
		return caseCreate(ctx, repoRoot, agent, jsonOut, args)
	case "list":
		return caseList(ctx, repoRoot, agent, jsonOut, args)
	case "info":
		return caseInfo(ctx, repoRoot, agent, jsonOut, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown case subcommand %q\n", sub)
		return 2
	}
}

func caseCreate(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("case create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	desc := fs.String("description", "", "optional case description")
	if err := parseFlexible(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: forensicctl case create <name> [--description TEXT]")
		return 2
	}
	name := fs.Arg(0)

	repo, err := openRepo(ctx, repoRoot, agent)
	if err != nil {
		return fail(err)
	}
	defer repo.Close()

	c, err := repo.CreateCase(ctx, forensic.CaseSpec{Name: name, Description: *desc})
	if err != nil {
		return fail(err)
	}
	defer c.Close()

	info, err := c.Info(ctx)
	if err != nil {
		return fail(err)
	}
	if jsonOut {
		return writeJSON(info)
	}
	fmt.Printf("created case %s (%s) revision %d\n", info.Name, info.ID, info.Revision)
	return 0
}

func caseList(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("case list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := parseFlexible(fs, args); err != nil {
		return 2
	}
	repo, err := openRepo(ctx, repoRoot, agent)
	if err != nil {
		return fail(err)
	}
	defer repo.Close()

	cases, err := repo.ListCases(ctx)
	if err != nil {
		return fail(err)
	}
	if jsonOut {
		return writeJSON(cases)
	}
	if len(cases) == 0 {
		fmt.Println("no cases")
		return 0
	}
	for _, c := range cases {
		fmt.Printf("%s\t%s\trev=%d\t%s\n", c.ID, c.Name, c.Revision, c.CreatedAt.UTC().Format(time.RFC3339))
	}
	return 0
}

func caseInfo(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("case info", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := parseFlexible(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: forensicctl case info <name-or-id>")
		return 2
	}
	repo, err := openRepo(ctx, repoRoot, agent)
	if err != nil {
		return fail(err)
	}
	defer repo.Close()

	c, err := openCase(ctx, repo, fs.Arg(0))
	if err != nil {
		return fail(err)
	}
	defer c.Close()

	info, err := c.Info(ctx)
	if err != nil {
		return fail(err)
	}
	if jsonOut {
		return writeJSON(info)
	}
	fmt.Printf("id:          %s\n", info.ID)
	fmt.Printf("name:        %s\n", info.Name)
	fmt.Printf("description: %s\n", info.Description)
	fmt.Printf("created:     %s\n", info.CreatedAt.UTC().Format(time.RFC3339Nano))
	fmt.Printf("revision:    %d\n", info.Revision)
	fmt.Printf("root:        %s\n", c.Root())
	return 0
}

// --- import -----------------------------------------------------------------

func cmdImport(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: forensicctl import <file|tree> <path> --case NAME")
		return 2
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "file":
		return importFile(ctx, repoRoot, agent, jsonOut, args)
	case "tree":
		return importTree(ctx, repoRoot, agent, jsonOut, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown import subcommand %q\n", sub)
		return 2
	}
}

func importFile(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("import file", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	caseSel := fs.String("case", "", "case name or id")
	label := fs.String("label", "", "evidence label (default: base name)")
	method := fs.String("method", "cli-import", "acquisition method")
	sourceURI := fs.String("source-uri", "", "optional source URI")
	idem := fs.String("idempotency-key", "", "optional idempotency key")
	if err := parseFlexible(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: forensicctl import file <path> --case NAME [--label L] [--method M]")
		return 2
	}
	path := fs.Arg(0)
	if *label == "" {
		*label = filepath.Base(path)
	}

	repo, err := openRepo(ctx, repoRoot, agent)
	if err != nil {
		return fail(err)
	}
	defer repo.Close()
	c, err := openCase(ctx, repo, *caseSel)
	if err != nil {
		return fail(err)
	}
	defer c.Close()

	ev, err := c.ImportEvidenceFile(ctx, path, forensic.EvidenceSpec{
		Label: *label,
		Acquisition: forensic.AcquisitionSpec{
			Method:    *method,
			SourceURI: *sourceURI,
		},
		IdempotencyKey: *idem,
	})
	if err != nil {
		return fail(err)
	}
	if jsonOut {
		return writeJSON(ev)
	}
	fmt.Printf("imported evidence %s\n", ev.ID)
	fmt.Printf("  label:   %s\n", ev.Label)
	fmt.Printf("  object:  %s\n", ev.RootObject.ID)
	fmt.Printf("  blob:    %s\n", ev.RootObject.Blob)
	fmt.Printf("  size:    %d\n", ev.RootObject.Size)
	fmt.Printf("  rev:     %d\n", ev.CreatedRevision)
	return 0
}

func importTree(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("import tree", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	caseSel := fs.String("case", "", "case name or id")
	label := fs.String("label", "", "source-tree label (default: base name)")
	method := fs.String("method", "cli-import", "acquisition method")
	sourceURI := fs.String("source-uri", "", "optional source URI")
	includeGit := fs.Bool("include-git", false, "include .git directory contents")
	idem := fs.String("idempotency-key", "", "optional idempotency key")
	if err := parseFlexible(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: forensicctl import tree <path> --case NAME [--label L] [--include-git]")
		return 2
	}
	path := fs.Arg(0)
	if *label == "" {
		*label = filepath.Base(path)
	}

	repo, err := openRepo(ctx, repoRoot, agent)
	if err != nil {
		return fail(err)
	}
	defer repo.Close()
	c, err := openCase(ctx, repo, *caseSel)
	if err != nil {
		return fail(err)
	}
	defer c.Close()

	tree, err := c.ImportSourceTree(ctx, path, forensic.SourceTreeSpec{
		Label: *label,
		Acquisition: forensic.AcquisitionSpec{
			Method:    *method,
			SourceURI: *sourceURI,
		},
		IncludeGitDir:  *includeGit,
		IdempotencyKey: *idem,
	})
	if err != nil {
		return fail(err)
	}
	if jsonOut {
		// Omit full entry list in JSON by default for large trees; include summary fields.
		type treeOut struct {
			ID              forensic.TreeID     `json:"id"`
			Evidence        forensic.EvidenceID `json:"evidence"`
			Label           string              `json:"label"`
			TreeDigest      string              `json:"tree_digest"`
			Manifest        forensic.ObjectRef  `json:"manifest"`
			FileCount       int                 `json:"file_count"`
			TotalBytes      int64               `json:"total_bytes"`
			CreatedRevision int64               `json:"created_revision"`
		}
		return writeJSON(treeOut{
			ID:              tree.ID,
			Evidence:        tree.Evidence,
			Label:           tree.Label,
			TreeDigest:      tree.TreeDigest,
			Manifest:        tree.Manifest,
			FileCount:       tree.FileCount,
			TotalBytes:      tree.TotalBytes,
			CreatedRevision: tree.CreatedRevision,
		})
	}
	fmt.Printf("imported source tree %s\n", tree.ID)
	fmt.Printf("  label:    %s\n", tree.Label)
	fmt.Printf("  evidence: %s\n", tree.Evidence)
	fmt.Printf("  files:    %d\n", tree.FileCount)
	fmt.Printf("  bytes:    %d\n", tree.TotalBytes)
	fmt.Printf("  digest:   %s\n", tree.TreeDigest)
	fmt.Printf("  rev:      %d\n", tree.CreatedRevision)
	return 0
}

// --- verify -----------------------------------------------------------------

func cmdVerify(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	caseSel := fs.String("case", "", "case name or id")
	mode := fs.String("mode", string(forensic.VerifyQuick), "quick|originals|full")
	if err := parseFlexible(fs, args); err != nil {
		return 2
	}

	repo, err := openRepo(ctx, repoRoot, agent)
	if err != nil {
		return fail(err)
	}
	defer repo.Close()
	c, err := openCase(ctx, repo, *caseSel)
	if err != nil {
		return fail(err)
	}
	defer c.Close()

	report, err := c.Verify(ctx, forensic.VerifySpec{Mode: forensic.VerifyMode(*mode)})
	if err != nil {
		return fail(err)
	}
	if jsonOut {
		code := writeJSON(report)
		if !report.OK {
			return 4
		}
		return code
	}
	if report.OK {
		fmt.Printf("ok mode=%s case=%s revision=%d checked_blobs=%d\n",
			report.Mode, report.Case, report.Revision, report.CheckedBlobs)
		return 0
	}
	fmt.Printf("FAILED mode=%s case=%s revision=%d issues=%d\n",
		report.Mode, report.Case, report.Revision, len(report.Issues))
	for _, issue := range report.Issues {
		entity := ""
		if issue.Entity.ID != "" {
			entity = fmt.Sprintf(" entity=%s(%s)", issue.Entity.ID, issue.Entity.Kind)
		}
		path := ""
		if issue.Path != "" {
			path = " path=" + issue.Path
		}
		fmt.Printf("  [%s]%s%s %s\n", issue.Code, entity, path, issue.Detail)
	}
	return 4
}

// --- query ------------------------------------------------------------------

func cmdQuery(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	caseSel := fs.String("case", "", "case name or id")
	kind := fs.String("kind", "", "entity kind filter (object, evidence, source_tree, artifact, ...)")
	ext := fs.String("ext", "", "file extension filter (e.g. .go)")
	pathGlob := fs.String("path-glob", "", "path glob filter")
	treeID := fs.String("tree", "", "restrict to source-tree id")
	if err := parseFlexible(fs, args); err != nil {
		return 2
	}

	repo, err := openRepo(ctx, repoRoot, agent)
	if err != nil {
		return fail(err)
	}
	defer repo.Close()
	c, err := openCase(ctx, repo, *caseSel)
	if err != nil {
		return fail(err)
	}
	defer c.Close()

	var parts []forensic.Query
	if *kind != "" {
		parts = append(parts, forensic.KindIs(forensic.EntityKind(*kind)))
	}
	if *ext != "" {
		parts = append(parts, forensic.ExtensionIs(*ext))
	}
	if *pathGlob != "" {
		parts = append(parts, forensic.PathGlob(*pathGlob))
	}
	if *treeID != "" {
		parts = append(parts, forensic.InTree(forensic.TreeID(*treeID)))
	}
	q := forensic.All()
	if len(parts) == 1 {
		q = parts[0]
	} else if len(parts) > 1 {
		q = forensic.And(parts...)
	}

	result, err := c.Query(ctx, q)
	if err != nil {
		return fail(err)
	}
	if jsonOut {
		return writeJSON(result)
	}
	fmt.Printf("revision=%d count=%d\n", result.Revision, len(result.Entities))
	for _, e := range result.Entities {
		fmt.Printf("%s\t%s\n", e.Kind, e.ID)
	}
	return 0
}

// --- search -----------------------------------------------------------------

func cmdSearch(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	caseSel := fs.String("case", "", "case name or id")
	limit := fs.Int("limit", 50, "maximum hits")
	if err := parseFlexible(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: forensicctl search <text> --case NAME [--limit N]")
		return 2
	}
	text := fs.Arg(0)

	repo, err := openRepo(ctx, repoRoot, agent)
	if err != nil {
		return fail(err)
	}
	defer repo.Close()
	c, err := openCase(ctx, repo, *caseSel)
	if err != nil {
		return fail(err)
	}
	defer c.Close()

	hits, err := c.SearchText(ctx, text, *limit)
	if err != nil {
		return fail(err)
	}
	if jsonOut {
		return writeJSON(hits)
	}
	if len(hits) == 0 {
		fmt.Println("no hits")
		return 0
	}
	for _, h := range hits {
		fmt.Printf("%s\t%s\t%s\n", h.Artifact, h.Property, h.Text)
	}
	return 0
}

// --- recover ----------------------------------------------------------------

func cmdRecover(ctx context.Context, repoRoot, agent string, jsonOut bool, args []string) int {
	if len(args) == 0 || args[0] != "inspect" {
		fmt.Fprintln(os.Stderr, "usage: forensicctl recover inspect")
		return 2
	}
	fs := flag.NewFlagSet("recover inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := parseFlexible(fs, args[1:]); err != nil {
		return 2
	}

	repo, err := openRepo(ctx, repoRoot, agent)
	if err != nil {
		return fail(err)
	}
	defer repo.Close()

	report, err := repo.InspectRecovery(ctx)
	if err != nil {
		return fail(err)
	}
	if jsonOut {
		return writeJSON(report)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fail(err)
	}
	return 0
}
