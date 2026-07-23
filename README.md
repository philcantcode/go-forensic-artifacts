# Go forensic artifact store

[![CI](https://github.com/philcantcode/go-forensic-artifacts/actions/workflows/ci.yml/badge.svg)](https://github.com/philcantcode/go-forensic-artifacts/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/philcantcode/go-forensic-artifacts.svg)](https://pkg.go.dev/github.com/philcantcode/go-forensic-artifacts)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`forensic` is a local-first Go library for immutable forensic evidence and
vulnerability-research artifacts. One repository configuration manages durable,
self-contained cases. Each case combines a SHA-256 content store with a
transactional SQLite provenance catalog.

The implementation covers the design's version 1 baseline and complete first
vertical slice:

- repository and case create, discover, reopen, and concurrent access;
- staged, atomic file and source-tree imports with distinct evidence/object
  occurrence IDs and inert symlink metadata;
- agents, sessions, immutable attributed activities, external-execution
  metadata, custody transfers, sealed inputs, outputs, and audit chain;
- typed artifacts, rich source locators, uncertainty-aware temporal values,
  assertions, and versioned vulnerability findings with identifiers,
  references, affected targets, confidence, and analyst attribution;
- probed single-object and bounded-concurrency parser orchestration with
  per-input isolation, durable partial results, and explicit deterministic
  parser-output reuse;
- wrapped external experiments with protected projection inputs, allowlisted
  environments, bounded logs, declared outputs, and captured exit status;
- typed structured queries across schema, media, size, provenance, evidence,
  findings, assertions, revisions, and descendants; exact frozen selections;
  and provenance tracing;
- deterministic copy-only directory projections with safe paths, explicit
  policy exclusions, typed metadata, provenance/finding sidecars, and
  manifests;
- FTS5 and bounded metadata search, streaming literal/regular-expression byte
  search, and traceable saved-search artifacts;
- deterministic Markdown and JSONL exports plus versioned, policy-auditable
  BagIt deliverables with membership and exclusion lineage; and
- quick, original, full, and projection integrity verification, including
  semantic catalog and source-tree invariants;
- signed external checkpoints; and
- live SQLite snapshots that can be verified and restored with stable IDs.

## What a source folder becomes

`ImportSourceTree` treats a source-code folder as one logical accession, not as
one indivisible parsed artifact. It creates one `Evidence` record and one
`SourceTree` aggregate. The aggregate has a canonical manifest, while every
regular file is a separate immutable `Object` occurrence with its own hash and
path locator. Directories and symlinks are inert manifest entries; symlinks are
never followed. This gives an agent one stable handle for “the repository” and
addressable member objects for parsing, searching, tracing, and projecting.

```go
tree, err := c.ImportSourceTree(ctx, "./source", forensic.SourceTreeSpec{
    Label: "service source at reviewed commit",
    Acquisition: forensic.AcquisitionSpec{Method: "working-tree copy"},
    IdempotencyKey: "service-source-v1",
})

files, err := c.Query(ctx, forensic.And(
    forensic.InTree(tree.ID),
    forensic.ExtensionIs(".go"),
))
```

The default import excludes `.git`; set `IncludeGitDir` when repository history
itself is evidence. Configurable entry, file, and byte limits bound agent-driven
imports. Raw filesystem path bytes, display paths, file modes, hashes, and
symlink targets are retained in the tree manifest.

## Quick start

```go
repo, err := forensic.Open(ctx, forensic.Config{
    Root: "/srv/forensics",
    DefaultAgent: forensic.AgentSpec{
        Kind: forensic.AgentSoftware,
        Name: "research-agent-7",
    },
})
if err != nil { return err }
defer repo.Close()

c, err := repo.CreateCase(ctx, forensic.CaseSpec{Name: "router-firmware"})
if err != nil { return err }
defer c.Close()

evidence, err := c.ImportEvidenceFile(ctx, "firmware.bin", forensic.EvidenceSpec{
    Label: "Vendor firmware 3.2.1",
    Acquisition: forensic.AcquisitionSpec{Method: "vendor-download"},
})
if err != nil { return err }

session, err := c.StartSession(ctx, forensic.SessionSpec{Label: "config review"})
if err != nil { return err }
defer session.Close(ctx)

run, err := session.BeginActivity(ctx, forensic.ActivitySpec{
    Type: forensic.ActivityExtract,
    Label: "Extract configuration",
})
if err != nil { return err }
if err := run.Use(ctx, evidence.RootObject, "firmware-image"); err != nil { return err }

config, err := run.CaptureFile(ctx, "config.json", forensic.ObjectSpec{
    Role: "extracted-file",
    Source: forensic.PathLocator{Display: "etc/config.json", Separator: "/"},
})
if err != nil { return err }
if err := run.Finish(ctx, forensic.OutcomeSucceeded()); err != nil { return err }

selection, err := session.Freeze(ctx, forensic.FreezeSpec{
    Name: "JSON configuration",
    Query: forensic.And(
        forensic.KindIs(forensic.EntityObject),
        forensic.PathGlob("**/*.json"),
    ),
})
```

Every selected entity can be followed through its generating activity and
named inputs back to original managed bytes with `Case.Trace`. `Case.Verify`
checks the catalog, foreign keys, audit chain, blob references, digests, or a
materialized projection without modifying the case.

Large result sets can use `Case.QueryPage`. Reuse the returned `Revision` and
`Next` cursor so traversal remains stable while other agents add data. A
deterministic parser can opt into `ParseOptions.UseCache`; a hit creates a
separate reuse activity and returns the original immutable output IDs.

## Storage and safety

The live layout is documented in [the design](docs/design.md). Managed blobs are
published before catalog references commit. Materializations always copy bytes;
they never hardlink to the content store. Imports reject symlinks, emitted path
components are sanitized, and projection/package destinations must be outside
the authoritative case directory.

Concurrency is supported across goroutines and cooperating processes on one
host. Opening a case over NFS/SMB, distributed writes, live acquisition,
physically deleting committed evidence, and sandboxing hostile parsers are
outside the core library's scope.

Recovery inspection reports abandoned staging files, orphaned blobs, running
activities, and unregistered self-describing cases without silently mutating
evidence. Explicit APIs complete safe case registration and mark interrupted
activities when an operator decides recovery is appropriate.

Schema upgrades are explicit maintenance operations. They acquire a repository
lease, make and verify an online SQLite backup, apply versioned migrations in a
transaction, and preserve the backup for rollback and audit.
Portable old-schema cases require `RestoreSpec{Migrate: true}`; restore performs
all compatibility checks before publishing anything into the repository.

`Session.RunExperiment` is the optional wrapped-process boundary. It invokes a
program directly without a shell, protects projected inputs, exposes a writable
`output/`, captures bounded logs and only caller-declared outputs, and records
the exit outcome. It deliberately does not claim to sandbox hostile code; use
an OS or container sandbox where that trust boundary is required.

## Architecture decisions

The short decision records are in [`docs/adr`](docs/adr):

1. local filesystem and SQLite;
2. per-case SHA-256 content store;
3. immutable activity provenance;
4. typed UUIDv7 identifiers and canonical audit events;
5. freeze-before-projection; and
6. Go/SQLite implementation baseline.

## Development

Go 1.25.8 or newer is required. This floor includes standard-library security
fixes used by the repository, checkpoint, and export paths.

```text
go test ./...
go test -race ./...
go vet ./...
```

The tests exercise 100 concurrent mixed workers under the race detector,
multi-process import/query/tag/freeze, forced process termination at persistence
boundaries, export fault injection, deterministic projections, portable restore,
path/manifest fuzz seeds, and deliberate blob/catalog/package corruption.

The acceptance evidence is mapped in
[docs/implementation-status.md](docs/implementation-status.md).

## Releases and security

Releases use semantic versioning and are published from signed or annotated
`v*` tags after the full test suite passes. See [RELEASING.md](RELEASING.md)
and [CHANGELOG.md](CHANGELOG.md). Until version 1.0, minor releases may contain
breaking API changes.

Please report suspected vulnerabilities privately using GitHub's security
advisory form, as described in [SECURITY.md](SECURITY.md).

## License

This project is available under the [MIT License](LICENSE).
