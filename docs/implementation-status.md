# Version 1 acceptance evidence

Status: implemented and verified, July 2026.

This matrix maps the ten acceptance criteria in
[section 20.2 of the design](design.md#202-version-1-acceptance-criteria) to
executable evidence.

| Criterion | Evidence |
| --- | --- |
| 100 concurrent workers | `TestHundredGoroutineMixedWorkload` imports, queries, asserts/tags, and freezes through shared handles; the suite passes under `go test -race`. |
| Cooperating local processes | `TestMultiProcessImports` has three processes import, query, tag, and freeze the same case. |
| Crash-safe publication | `TestProcessTerminationAtPersistenceBoundaries` kills a writer at every instrumented ingest boundary; deterministic injection covers the same boundaries and projection publication. |
| Idempotent retries | The end-to-end test repeats imports and parser producer keys; `TestAuditTamperAndProducerConflict` proves changed producer payloads conflict. |
| Deterministic projections | `TestEndToEndVerticalSlice` materializes one projection twice and compares the canonical manifests byte-for-byte. |
| Workspace isolation | The end-to-end test mutates projected bytes, detects the change, and proves the managed blob is unchanged. |
| Corruption detection | Tests inject blob, audit-chain, projection, BagIt tag, checkpoint-signature, portable-catalog, and portable-blob corruption. |
| Traceable artifacts/deliverables | `Case.Trace` is checked from an artifact and a BagIt deliverable back to original evidence. |
| Stable-ID portable restore | Snapshot/restore tests restore an online SQLite snapshot into a new repository and verify stable case, entity, and blob IDs. |
| Format compatibility | Schema and format versions are independent, forward schemas fail closed, and version 1 snapshot/restore compatibility is exercised on every test run. |

Additional coverage includes hostile path sanitization, regular-file and
source-tree imports, inert symlink handling, package payloads, bounded
cross-chunk byte search, FTS5 startup, multi-occurrence blob deduplication,
context cancellation, and full reopen verification.
