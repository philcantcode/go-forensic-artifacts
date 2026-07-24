# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-24

- Moved the public library package from the module root into `forensic/`.
  Import path is now `github.com/philcantcode/go-forensic-artifacts/forensic`.
  This is a breaking change for importers of the 0.1.0 path.
- Documented the module layout (`forensic/`, `cmd/`, `examples/`, `docs/`) in
  README, design §15.5 / §22, ADR 0006, RELEASING, and implementation-status.
- Added `cmd/forensicctl`, a thin operator CLI for case create/list/info,
  file and source-tree import, integrity verify, simple queries, text search,
  and recovery inspection.
- Added `examples/import-source-tree`, a runnable library example that imports
  a directory, queries `.go` members, and verifies the case.

## [0.1.0] - 2026-07-23

Initial public release.

- Added the local-first forensic artifact repository and per-case SQLite catalog.
- Added immutable SHA-256 storage, regular-file and source-tree imports,
  provenance, typed queries, frozen selections, deterministic projections,
  exports, snapshots, and integrity verification.
- Added typed SQLite, JSON, XML, archive, registry, and API locators;
  uncertainty-aware temporal values; bounded metadata queries; and traceable
  saved byte-search results.
- Added multi-agent activity attribution, external-execution metadata, parent
  activities, append-only custody transfers, and revision-stable idempotent
  replays.
- Added parser probing, isolated per-input parser factories, bounded concurrent
  parsing, ordered results, durable partial outputs on parser failure, and
  explicit deterministic parser-output reuse.
- Added read-only recovery inspection, explicit case re-registration and
  interruption handling, plus versioned BagIt deliverables with closure,
  exclusions, policy metadata, membership manifests, and predecessor lineage.
- Added projection exclusion records and semantic verification for entity
  invariants, acquisition hashes, and source-tree manifests.
- Added extended typed query predicates and richer vulnerability-finding
  metadata, including identifiers, references, affected targets, confidence,
  and analyst attribution.
- Added explicit leased schema migration with verified online backups,
  transactional version steps, and retained rollback artifacts.
- Added wrapped experiment execution with protected inputs, safe working paths,
  allowlisted environments, bounded stdout/stderr capture, declared output
  ingestion, cancellation, and durable outcomes.
- Added revision-pinned query pages, rich projection metadata/provenance/finding
  sidecars, source-tree resource limits and raw path retention, and preflighted
  old-schema portable restore with stable IDs.
- Added concurrent, multi-process, crash-boundary, corruption, fuzz, and race tests.
- Added architecture decision records, CI, release automation, and security policy.

[0.2.0]: https://github.com/philcantcode/go-forensic-artifacts/releases/tag/v0.2.0
[0.1.0]: https://github.com/philcantcode/go-forensic-artifacts/releases/tag/v0.1.0
