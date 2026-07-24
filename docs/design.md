# Forensic artifact store for Go: proposed design

Status: version 1 baseline implemented, July 2026. See
[implementation-status.md](implementation-status.md) for acceptance evidence.

The repository implements the recommended vertical slice in section 23 and the
version 1 acceptance criteria in section 20.2. Later ecosystem adapters in phase
5 remain optional extension modules rather than core storage requirements.

This document defines a reusable Go library for managing forensic evidence and
vulnerability-research outputs. The public package is `forensic` at
`github.com/philcantcode/go-forensic-artifacts/forensic`. The module root holds
`forensic/` (library), `cmd/` (operator CLI), `examples/` (runnable samples), and
`docs/` (this design and ADRs).

## 1. Executive decision

Build a local-first case repository with two coordinated stores per case:

- an immutable, content-addressed blob store for bytes; and
- a transactional SQLite catalog for identity, provenance, parsed data, findings, selections, projections, and audit history.

Model research as a provenance graph:

```text
Agent --associated with--> Activity --used-------> Entity
                               |
                               +--generated-----> Entity

Entity kinds:
Evidence, Object, Artifact, Assertion, FindingRevision,
Selection, Projection, Manifest, Deliverable
```

An `Object` is an occurrence of some bytes with a particular meaning and history. A `Blob` is only the immutable byte sequence. Multiple objects may intentionally refer to one blob, so byte-level deduplication never erases distinct provenance.

The relational catalog is an efficient internal representation, not the public model. The public API exposes typed domain operations and query expressions, never raw SQL. Standards-compatible graph and package formats are export adapters.

### Why this shape

- Files remain directly usable, hashable, grep-able, and exportable.
- SQLite gives atomic metadata changes and same-host multi-process locking without requiring a service.
- Content addressing makes derived representations cheap to identify and safe to share.
- Entity/activity provenance expresses experiments much better than a flat vulnerability-ticket model.
- Frozen selections and projections allow two agents to derive different views from the same case revision.
- A self-contained case can be verified, backed up, or packaged without access to a central server.

### Important limits

The first storage engine supports concurrent goroutines and concurrent processes on one host. It does not support multiple hosts opening one case over NFS or SMB. SQLite WAL permits concurrent readers and a writer, but its shared-memory design requires processes to be on the same host and still permits only one writer at a time. Writes therefore have to be short and batched.

The library preserves and describes evidence; it does not by itself prove lawful acquisition, make a computer a write blocker, sandbox malicious parsers, or make a hash stored beside a file resistant to an administrator rewriting both. External signed checkpoints and organizational controls remain necessary for stronger custody claims.

## 2. Goals and non-goals

### Goals

1. A caller configures a repository root once, creates or opens a case, and immediately has a durable store.
2. All ordinary handles and operations are safe for concurrent goroutine use.
3. Multiple cooperating processes on the same machine can open and write the same case.
4. Original bytes and derived bytes are immutable after publication.
5. Every material transformation has an actor, activity, tool/configuration, inputs, outputs, time, and outcome.
6. Parsed values retain both their source spelling and normalized interpretation.
7. Queries can be frozen into repeatable result sets and projected into safe folder trees, archives, container inputs, JSONL, or Markdown.
8. An agent can retry an operation without silently duplicating results.
9. Cases can be verified, snapshotted, and exported with checksum manifests.
10. The core stays small; disk-image readers, file-system parsers, application parsers, runners, and interchange formats are modules.

### Non-goals for the core library

- Acquiring a live disk, memory, phone, or cloud account.
- Reimplementing E01, AFF4, disk file systems, registry parsing, or every application parser.
- A desktop review UI or multi-user web service.
- Distributed writes from different hosts.
- Running untrusted tools safely in-process.
- Deciding that evidence is legally admissible or that a workflow meets a particular jurisdiction's rules.
- Physically deleting committed evidence in the first release.
- Treating a materialized workspace as authoritative case data.

## 3. Design principles

### 3.1 Originals never change

Import creates a managed copy by default. Extraction, normalization, carving, redaction, conversion, minimization, and report generation create new entities. Corrections supersede prior assertions; they do not rewrite them.

### 3.2 Provenance is structural, not a note field

The core lineage is expressed by immutable activity input and output edges. Free-form notes supplement that structure but cannot replace it.

### 3.3 Bytes and meaning have separate identity

`Blob(sha256:...)` identifies bytes. `Object(obj_...)` identifies those bytes as, for example, the E01 received from a custodian, the copy extracted from a ZIP, or the minimized test case generated by an agent. Equal hashes do not imply equal evidential roles.

### 3.4 Parsed facts and investigative interpretation are separate

A parser result is immutable and attributable to the parser run. Tags, comments, relevance, confidence, vulnerability severity, and review status are assertions or finding revisions made later by a human or agent.

### 3.5 Queries are not snapshots

A saved query can change as a case grows. A frozen selection records an exact case revision and exact member IDs. Projections and deliverables always consume a frozen selection.

### 3.6 External work is explicit

The library can observe a command when an optional runner owns the execution. It can also record an operation reported after the fact. These have different `capture_mode` values, so an assertion is not presented as direct observation.

### 3.7 Ordering and time are different

The audit sequence is the authoritative order in which facts were committed. Activity start/end times, source timestamps, filesystem timestamps, and the time an assertion was recorded are all separate fields. Wall clocks can be wrong.

### 3.8 Safe defaults beat implicit convenience

Writable projections copy or reflink data; materializations never hardlink managed blobs. Imports reject symlinks by default. Paths are sanitized and recorded. Raw SQL, implicit external references, and mutable global actors are not exposed.

## 4. Ideas adopted from existing systems and standards

| Source | Useful idea | Adaptation here |
| --- | --- | --- |
| The Sleuth Kit / Autopsy | A shared case database and “blackboard” through which modules post typed artifacts and attributes | Typed artifacts and a parser sink, but with immutable parser outputs and explicit activity provenance |
| Autopsy ingest modules | Pluggable analysis stages, progress, events, keyword indexing, and common services | Small parser contracts, deterministic descriptors/configuration, batching, cancellation, and optional schedulers |
| EnCase / FTK | Evidence-oriented cases, indexing, bookmarks/review, and report/export workflows | Preserve the source/derived/review/deliverable separation without depending on proprietary formats or a monolithic UI |
| W3C PROV | `Entity`, `Activity`, and `Agent`, with usage, generation, derivation, and association | The conceptual provenance core and export mapping |
| CASE/UCO | A machine-readable cyber-investigation graph and traceability from results back to sources and tools | Namespaced schemas plus an optional versioned JSON-LD exporter; not an RDF database in the hot path |
| OCFL | Separate logical paths from physical content paths; inventory hashes; immutable versions; rebuildability and storage transparency | Content-addressed storage, exact logical path manifests, versioned projections, and self-describing case packages; no claim of OCFL conformance |
| BagIt | A simple payload directory and checksum manifests for reliable transfer | The first portable-case/deliverable package adapter |
| AFF4 and forensic image formats | Package bytes and related forensic metadata in established acquisition formats | Import as opaque original objects and add format-specific adapters; do not replace these formats |
| Unix tools | Transparent files and composable grep/regex workflows | Safe folder materialization plus streaming byte search and Markdown/JSONL output |

The TSK blackboard is particularly relevant: it lets modules publish typed analysis results to a common case database. This design keeps that extensibility while making the producing activity, parser build, configuration, source locator, and raw value mandatory parts of the model.

## 5. Vocabulary and identity

All public IDs are opaque, typed, 128-bit random/time-ordered identifiers rendered with prefixes. UUIDv7 is the preferred encoding if the implementation spike confirms a small, stable dependency.

```text
case_...   evd_...    obj_...    art_...    act_...
agt_...    asn_...    fnd_...    sel_...    prj_...
mat_...    dlv_...    ses_...    tool_...
```

IDs are stable and never contain names or paths. Blob references are algorithm-qualified lowercase digests such as `sha256:0123...`.

### 5.1 Core records

| Record | Meaning | Mutation policy |
| --- | --- | --- |
| `Case` | Administrative boundary and storage unit | Display metadata is revisioned; ID and creation facts are immutable |
| `Agent` | Human, autonomous agent, service, organization, or unknown actor | Immutable identity record; aliases are assertions |
| `Session` | A bounded body of work by an agent | Append/close only; groups activities |
| `Tool` | Software identity: name, version, build digest, URI | Immutable descriptor |
| `Activity` | Acquisition, import, parse, search, experiment, review, projection, export, etc. | Inputs are added while running; terminal outcome is append-only |
| `Blob` | Immutable managed bytes | Never modified; deduplicated per case |
| `Evidence` | Accessioned source/custodian/device/account and its original objects | Core facts immutable; later corrections are assertions |
| `Object` | A byte-bearing occurrence with original or derived role | Immutable and generated by exactly one activity |
| `Artifact` | Structured parser output tied to precise sources | Immutable and generated by exactly one activity |
| `Assertion` | Tag, comment, relationship, correction, classification, or review decision | Immutable; can be superseded or retracted by another assertion |
| `FindingRevision` | A version of an investigative claim | Immutable revision; a stable finding ID points to its current revision |
| `Selection` | Exact entity IDs frozen at a case revision | Immutable |
| `Projection` | Selection plus closure, layout, and representation recipe | Immutable; changes create a new version |
| `Materialization` | One realization of a projection at a destination | Append-only status and manifest; external files are not authoritative |
| `Deliverable` | Immutable package/report and its selection, policies, recipient, and hash | Immutable; corrections create a new version |

### 5.2 Evidence layer mapping

| Evidence layer | Primary records | Required lineage |
| --- | --- | --- |
| Original evidence | `Evidence` plus one or more original `Object`s | Accession/acquisition activity, source/custodian/device, acquisition method/log, supplied and computed hashes |
| Extracted object | Derived `Object` | Parent inputs, extraction/carving activity, original path or offset, tool/configuration, derived hash |
| Parsed artifact | `Artifact` and typed values | Source objects/locators, parser activity and version, raw and normalized values |
| Investigative finding | Stable finding plus immutable `FindingRevision`s | Authoring/review activities, member entities and roles, status/confidence/comments/significance |
| Deliverable | `Deliverable` plus package/report objects | Frozen selection, closure, exclusions/redactions, exporter version, recipient, package hash |

### 5.3 Blob versus object example

Two agents independently extract an identical `config.json`. The case stores one blob because the SHA-256 values match, but it stores two objects:

```text
obj_A --generated by--> extract activity A --used--> firmware image A
  |
  +--has bytes--> sha256:1234

obj_B --generated by--> extract activity B --used--> container layer B
  |
  +--has bytes--> sha256:1234
```

This is intentional. Deduplicating the objects would destroy the fact that the same content appeared in two sources.

## 6. Provenance model

### 6.1 Core invariants

1. Every evidence, object, artifact, assertion, finding revision, selection, projection, manifest, and deliverable is generated by exactly one activity.
2. An activity may use zero or more existing entities in named roles and generate zero or more new entities in named roles.
3. Inputs must be declared before outputs. The first output atomically seals the input set; an explicit `SealInputs` operation is also available.
4. An activity's type, agents, session, tool, and configuration are fixed when it starts. Later records can correct them only by assertion; they cannot rewrite the historical activity.
5. An output cannot later acquire a different generating activity.
6. An activity cannot add inputs or outputs after reaching a terminal state.
7. Sharing a blob never implies a provenance edge.
8. Derivation is a directed acyclic graph because a sealed activity can only use already committed entities and can only generate new IDs.
9. Semantic relationships are assertions with their own producer, confidence, and source; they are not silently inferred as lineage.
10. Every write transaction receives a monotonically increasing case revision and audit sequence.

### 6.2 Activity types

Core types use stable namespaced identifiers. Extensions can add their own.

```text
case.create             evidence.accession       evidence.acquire
object.import           object.extract           object.carve
artifact.parse          artifact.normalize       entity.search
entity.correlate        finding.author           finding.review
selection.freeze        projection.materialize   experiment.execute
object.redact           deliverable.package      integrity.verify
custody.transfer        assertion.record
```

An activity contains:

- type and human label;
- associated agents and their roles;
- session and optional parent activity;
- tool descriptor and executable/container digest where known;
- canonical configuration and its digest;
- capture mode: `library`, `wrapped`, `reported`, or `imported`;
- start, end, and recorded times with clock/source details;
- state: `running`, `succeeded`, `failed`, `cancelled`, or `interrupted`;
- the input-sealed revision/time;
- command, arguments, working directory hint, and an allowlisted/redacted environment where relevant;
- outcome summary, exit status, warnings, and log object IDs;
- idempotency key and request fingerprint where supplied.

Activity failure does not invalidate captured outputs. Crash files and logs from a failed experiment are often the important result. Their provenance retains the failed or interrupted outcome.

### 6.3 Source locators

Artifacts and object derivations use typed locators rather than a single path string:

```text
path       volume/filesystem ID, raw path bytes, display path, case rules
extent     parent object, byte offset, byte length, sector/cluster when known
sqlite     object, database name, table, rowid/primary key, column
json       object, JSON Pointer
xml        object, XPath plus namespace map
archive    container object, raw member name, member index
registry   hive object, key path, value name
api        acquisition URI, account/resource ID, request/page reference
custom     namespaced type plus canonical JSON
```

Paths retain raw bytes, declared/detected encoding, separator, normalized display form, and case-sensitivity context. Display normalization never replaces raw source data.

### 6.4 Timestamp values

A temporal value retains:

- raw value and raw type;
- normalized UTC instant or uncertainty interval;
- original numeric epoch/unit where applicable;
- timezone/offset and whether it was explicit, assumed, or inferred;
- precision;
- semantic role such as created, modified, sent, visited, observed, or executed;
- parser/normalizer and source clock;
- optional confidence and clock-skew interpretation.

Timeline analysis is a query/projection over these values. It does not overwrite the source artifact or collapse several timestamps into one “best” timestamp.

### 6.5 Recording work performed outside the library

There are three supported patterns.

**Wrapped execution:** an optional runner creates a projection, starts the process/container, captures the exact command/tool/environment plus stdout/stderr, imports declared outputs, and closes the activity. `capture_mode=wrapped`.

**Client-managed execution:** the caller starts an activity, declares inputs, performs work itself, imports outputs through the activity handle, and finishes it. `capture_mode=library` for the recording, while execution details are supplied by the caller.

**After-the-fact assertion:** the caller records what it believes happened with explicit original times and notes. Existing bytes can be represented as a new object occurrence referring to the same blob. `capture_mode=reported` prevents this from being mistaken for direct observation.

The library never infers that a file appearing in a directory was produced by a particular command without an explicit capture operation.

## 7. Transformation chronology

The normal chronology is:

| Stage | Activity | Uses | Generates |
| --- | --- | --- | --- |
| Accession/acquisition | `evidence.accession` / `evidence.acquire` | External source reference, optional acquisition log | Evidence record, original objects, acquisition-log objects |
| Extraction/carving | `object.extract` / `object.carve` | Original or derived objects | New derived objects with paths/extents and hashes |
| Parsing | `artifact.parse` | Objects | Immutable artifacts with raw and normalized values |
| Re-normalization | `artifact.normalize` | Existing artifacts | New artifact versions; old parser output remains |
| Search | `entity.search` | Query, objects, artifacts, or a selection | Optional saved hit artifacts and a frozen selection |
| Correlation | `entity.correlate` | Artifacts, objects, assertions | Relationship assertions or correlation artifacts |
| Finding | `finding.author` | Relevant entities | First finding revision |
| Review | `finding.review` / `assertion.record` | Finding revision or entities | New revision, tag, comment, relevance, confidence, status |
| Selection | `selection.freeze` | Query evaluated at revision R | Exact member set plus query and revision |
| Projection | `projection.materialize` | Selection and projection spec | Manifest entity and an external/managed folder, archive, or stream |
| Experiment | `experiment.execute` | Projection/entities, tool, environment, seed/config | Logs, traces, crashes, minimized cases, patches, parsed results |
| Redaction | `object.redact` | Source object and redaction policy | New redacted object and transformation log |
| Delivery | `deliverable.package` | Frozen selection, closure policy, redacted objects | Report/package objects, manifest, deliverable record |

### Vulnerability-research example

```text
firmware.bin (original object)
    |
    v  unpack activity
rootfs/usr/bin/service (derived object)
    |
    +--> symbol parser ----------> function artifacts
    |
    +--> projection P1 ----------> agent A workspace
    |                                  |
    |                                  v fuzz activity
    |                              crash input + trace
    |                                  |
    |                                  v minimize activity
    |                              minimized PoC
    |
    +--> projection P2 ----------> agent B workspace
                                       |
                                       v static-analysis activity
                                   call-path artifacts

minimized PoC + trace + call path
    |
    v correlate/author activity
finding revision 1
    |
    v review/redact/package activities
finding revision 2 + external deliverable
```

Agent A and agent B can work concurrently. Their outputs are distinguishable by session, actor, activity, and projection even when they ultimately share blobs.

## 8. Repository and on-disk layout

```text
<repository>/
├── repository.json                 # format marker; no secrets
├── repository.sqlite3              # case registry; rebuildable from case.json files
├── cases/
│   └── <case-id>/
│       ├── case.json               # stable ID and format marker
│       ├── catalog.sqlite3         # metadata, graph, audit, indexes
│       ├── blobs/
│       │   └── sha256/ab/cd/<full-lowercase-digest>
│       ├── checkpoints/
│       │   └── <revision>.json[.sig]
│       └── staging/
│           ├── ingest/
│           └── package/
└── workspaces/
    └── <case-id>/<materialization-id>/
        ├── projection-manifest.json
        ├── data/...
        └── output/...              # optional writable output boundary
```

The case directory is self-identifying and can be re-registered if the repository registry is lost. Each case owns its CAS. Cross-case deduplication is deliberately rejected initially because it complicates isolation, deletion, portability, and information leakage.

Workspaces sit outside the authoritative case directory so ordinary verification and backup never confuse mutated experiment files with managed evidence. A projection to a caller-supplied external directory follows the same manifest protocol.

`staging` must be on the same filesystem as its case CAS so final publication can use an atomic same-volume operation. Temporary names are random and opened with exclusive creation.

### 8.1 Case creation and discovery

Case names are human-facing; the stable ID owns the directory. The repository registry enforces a unique normalized lookup key while retaining the exact display name.

Concurrent case creation uses this recoverable protocol:

1. Reserve the case ID and lookup key as `creating` in a repository SQLite transaction.
2. Create `cases/.creating-<case-id>` exclusively and initialize its marker/catalog.
3. Flush the marker/catalog and rename the directory atomically to `cases/<case-id>`.
4. Mark the registry row `active`.

Opening ignores `creating` rows and partial directories. Recovery can finish or report an interrupted creation by comparing the registry with `case.json`; it never guesses by directory name. Case registration is rebuildable by scanning and validating those markers.

### 8.2 Import modes

`Copy` is the default and the only mode that creates a fully self-contained case.

- `Copy`: open and stream the source into managed staging while hashing.
- `Move`: future explicit ownership-transfer operation; never implicit.
- `ExternalReference`: future opt-in record for data too large or inaccessible to copy. It is visibly non-durable and must store a URI, identity metadata, size, hash, and last verification. Projections cannot claim self-containment unless referenced data is included.

Path import opens the source first and records pre/post identity metadata where the operating system provides it, reducing path-replacement and concurrent-mutation ambiguity. The managed hash is always over the bytes actually read.

## 9. Catalog model

The exact SQL schema is an implementation detail, but these logical groups are required:

```text
case_info, schema_migrations, revisions, audit_events
agents, sessions, tools, activities, activity_agents
entities, activity_inputs, activity_outputs
blobs, objects, evidence, evidence_objects, source_locators
artifacts, artifact_values, temporal_values
assertions, assertion_targets, relationships
findings, finding_revisions, finding_members
queries, selections, selection_members
projections, projection_members, materializations
deliverables, deliverable_members
idempotency_keys, maintenance_leases
artifact_fts, object_path_fts
```

### 9.1 Common entity header

Every entity row has:

```text
id, kind, schema_uri, schema_version
generating_activity_id, created_revision, created_at
state, media_type, display_name
```

Kind-specific tables carry the remaining fields. The public API never returns partially populated “universal” structs; it returns a common reference plus typed records.

### 9.2 Artifact values

An artifact has a namespaced type such as `urn:example:artifact:browser.visit/v1`. Its ordered values use a controlled set of physical types:

```text
string, integer, unsigned, real, boolean, bytes, time,
duration, uri, json, object_ref, artifact_ref, null
```

Each value can carry:

- property name and optional schema URI;
- raw representation;
- normalized typed representation;
- unit/encoding/language;
- source locator;
- confidence and interpretation notes;
- array ordinal.

Complex parser-specific data can be retained as canonical JSON, but important searchable values should also be expressed as typed properties. Schema validators are pluggable. Unknown namespaced types remain storable so one parser cannot force a core release.

### 9.3 Findings for vulnerability research

The generic finding model contains title, Markdown body, status, confidence, significance/severity, author, assignees, review state, and member entities with roles. A `vuln` extension schema should add:

```text
affected component/version/commit/build
weakness identifiers (for example CWE)
preconditions and attack surface
reachability and affected code locations
reproduction steps and environment
impact and severity vector
proof-of-concept/test-case objects
crash, trace, log, and sanitizer artifacts
fix/patch objects and verification activities
disclosure state and external identifiers
```

These fields belong to a versioned finding, not to the underlying parser artifacts.

## 10. Concurrency and durability

### 10.1 Contract

- `Repository`, `Case`, `Session`, service objects, `Activity`, and parser sinks are safe for concurrent goroutine use.
- Returned readers have independent cursors. A query iterator is intentionally single-consumer and must be closed.
- Input slices, maps, and byte buffers are copied or consumed before a method returns; the library does not retain caller-mutable data.
- An activity waits for in-flight captures before it becomes terminal and rejects new captures once terminal.
- All activity inputs must be declared before capture begins; the first output seals the input set, including under concurrent use.
- `Close` methods are idempotent and concurrency-safe. Once close begins, new work returns `ErrClosed`; accepted work either completes or fails without leaving broken references.
- Multiple processes on one host are supported for ordinary reads and writes.
- Multiple hosts, network filesystems, direct catalog editing, and copying a live SQLite file without its WAL are unsupported.

### 10.2 SQLite configuration

Every connection is initialized consistently:

```text
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
PRAGMA trusted_schema=OFF;
PRAGMA busy_timeout=<bounded configurable value>;
```

Write transactions are short. Large parser result sets are committed in bounded batches. Busy handling uses context-aware bounded retry with jitter and returns a typed `ErrBusy` rather than hanging indefinitely. Read iterators avoid holding transactions open because long WAL readers can prevent checkpoint progress.

No public transaction escape hatch is provided. Batch APIs preserve the invariants and prevent callers from retaining a writer lock across tool execution or file I/O.

### 10.3 Publishing a blob and object

The publication protocol is ordered so the database never references missing managed bytes:

1. Create a random `staging/ingest/*.partial` file exclusively.
2. Stream the input once while computing SHA-256, byte count, and any requested compatibility hashes.
3. Flush and sync the completed staging file; close it.
4. Compute the final CAS path from the lowercase digest.
5. Publish atomically without replacing an existing path. If another writer won the race, verify the existing size/digest and discard the temporary copy.
6. Sync the containing directory where the platform supports a meaningful directory sync.
7. Start a short SQLite write transaction.
8. Insert-or-confirm the blob, create the logical object and provenance edges, increment the case revision, append the audit event, and commit.

A crash before step 8 can leave an unreferenced CAS blob. It cannot leave a catalog object pointing to an absent blob. Maintenance reports such blobs as orphans and may remove them only after a grace period and an exclusive maintenance operation. Committed blobs are not garbage-collected in version 1.

### 10.4 Metadata writes and revisions

Each logical operation is one SQLite transaction where feasible. The transaction:

1. validates expected versions and idempotency;
2. applies domain rows and indexes;
3. increments a monotonically increasing case revision;
4. appends one canonical audit event containing the operation digest;
5. commits atomically.

Optimistic expected-revision fields detect conflicting finding edits. Append-only parser outputs normally do not conflict.

### 10.5 Idempotency

Every agent-facing create/run API accepts an optional idempotency key. The stored key is scoped to case, session, operation kind, and actor and is paired with a canonical request fingerprint.

- Repeating the same key and fingerprint returns the original result IDs.
- Reusing the key with a different fingerprint returns `ErrConflict`.
- Parser sinks accept stable producer keys for individual outputs, allowing safe batch retries.

Idempotency is not content deduplication. Two intentionally distinct imports without the same key create two object occurrences even if they share a blob.

### 10.6 Consistent snapshots

Queries execute in a SQLite read snapshot and report the case revision they observed. Freezing a query stores:

- the canonical query expression;
- the evaluated revision;
- exact ordered member IDs;
- query engine/schema version;
- actor/session/activity.

Versioned records use created/superseded revision bounds so a query evaluated “at revision R” cannot see a later review or finding revision. The membership write can occur after the read transaction because every selected ID and version is immutable and revision-bounded.

## 11. Audit, integrity, and custody

### 11.1 Audit log

Audit rows are append-only and hash chained:

```text
event_hash = SHA-256(domain || sequence || previous_hash || canonical_event)
```

The canonical event records actor, session, operation, affected IDs, case revision, request/config digest, and recorded time. Domain changes and their audit event commit in the same database transaction.

The chain detects accidental edits and incomplete history, but an administrator who can rewrite the whole case could recompute it. A checkpoint API therefore emits a canonical inventory containing the case ID, revision, audit head, catalog snapshot digest, and referenced blob digests. Callers may sign it using a supplied `crypto.Signer` and store or publish the checkpoint somewhere outside the case. NIST guidance specifically recommends storing evidence hashes separately from the evidence in a secure location; the API supports that workflow without pretending the local chain alone supplies it.

### 11.2 Verification modes

`Case.Verify` is read-only by default and returns a structured report.

- `Quick`: SQLite integrity/foreign keys, schema invariants, audit chain, object-to-blob references, checkpoint syntax.
- `Originals`: rehash original evidence blobs and verify supplied acquisition hashes where algorithms remain available.
- `Full`: rehash every referenced blob, validate sizes, enumerate missing/unreferenced files, and verify external signatures supplied by the caller.
- `Projection`: validate a materialization against its manifest and report modified, missing, or unexpected files.

Verification operates against a catalog snapshot. Final CAS files are immutable; files still being ingested remain under `staging` and are outside the snapshot.

### 11.3 Custody

Custody is not derivation. A `custody.transfer` activity records evidence/item, from/to agents or locations, purpose, reference number, occurred and recorded times, and acknowledgement/signature metadata. It can use the same evidence entity without generating replacement bytes.

## 12. Search and indexing

Search has four layers.

### 12.1 Structured catalog query

A typed expression AST supports:

- entity kind/type/schema;
- ID, blob hash, media type, size;
- raw/display/original path, glob, extension;
- acquisition/evidence/custodian/device;
- producing actor, session, activity, tool, parser, and version;
- artifact typed values and time ranges;
- tags/review/finding membership;
- graph ancestry/descendency and relationship type;
- created or observed case revision;
- set union, intersection, and difference over saved selections.

The compiler uses parameters and an allowlisted AST. No public API accepts SQL fragments.

### 12.2 Full text

SQLite FTS5 indexes selected textual artifact values, object display/original paths, finding revisions, comments, and optionally parser-extracted text. Each hit retains the exact entity/property/source locator. FTS is a rebuildable index, never the authoritative artifact store.

The SQLite-driver spike must prove FTS5 availability on supported build targets. If unavailable, the initial release keeps structured query and streaming scan while reporting the capability explicitly.

### 12.3 Regex and grep over metadata

Go's RE2-style `regexp` engine filters bounded SQL candidates, avoiding a driver-specific `REGEXP` function and catastrophic backtracking. Limits apply to candidate count and result bytes. Literal matching is separately optimized.

### 12.4 Streaming byte search

Byte search streams selected object blobs in bounded chunks and supports literals and Go regular expressions. Results contain object ID, byte offset/length, surrounding context digest/bytes under a configured cap, and the search definition.

Searching a disk-image blob does not magically understand its filesystem. A filesystem module must first expose files as derived objects or virtual records. Initial object extraction copies derived bytes into the CAS; extent-backed virtual objects can be a later optimization.

Search hits are ephemeral unless saved. Saving creates an `entity.search` activity, hit artifacts, and/or a frozen selection so results remain reproducible.

## 13. Projections, workspaces, and experiments

### 13.1 Three distinct concepts

1. **Selection:** exact entity membership at a case revision.
2. **Projection:** immutable recipe for closure, representation, layout, and policies.
3. **Materialization:** one concrete directory/archive/stream produced from the projection.

This avoids the common ambiguity where “saved search,” “export,” and “working folder” all mean the same mutable thing.

### 13.2 Projection specification

A projection records:

- frozen selection ID;
- closure policy;
- included entity kinds and representations;
- path layout and collision policy;
- whether raw bytes, metadata sidecars, parsed values, findings, and provenance are included;
- exclusion/redaction rules;
- target type and exporter version;
- resource limits and deterministic ordering;
- a canonical spec digest.

Closure policies include:

- `exact`: only selected entities;
- `sources`: selected entities plus provenance metadata for ancestors, without necessarily copying ancestor bytes;
- `input-bytes`: include immediate byte-bearing inputs needed to reproduce work;
- `full-provenance`: recursively include all ancestors and metadata;
- `finding-context`: include finding members and their immediate sources.

Every closure-added member records why it was included.

### 13.3 Layouts

Built-in layouts are deterministic:

```text
by-id/<kind>/<entity-id>/<sanitized-name>
by-evidence/<evidence-id>/<sanitized-original-path>
flat/<sanitized-name>~<short-entity-id>
custom/<safe-template-over-allowlisted-fields>
```

The manifest records the exact map from entity/blob/source path to emitted path, including sanitization and collisions. Logical paths always use `/` in manifests even on Windows.

### 13.4 Safe materialization protocol

1. Require a new destination or an empty library-owned partial directory.
2. Resolve the frozen selection and closure.
3. Sanitize every component; reject absolute paths, `..`, empty components, device names, and path conflicts.
4. Copy or create a copy-on-write reflink for writable data. Never hardlink any materialization to the CAS.
5. Write metadata sidecars and a provisional manifest.
6. Sync data, write the final manifest last, and atomically rename a managed partial directory where possible.
7. Hash/import the manifest and record materialization status and destination hint.

Symlinks in evidence are represented as metadata by default, not followed or emitted as active links. Projection file count, total bytes, individual size, and path length are limited before writing.

### 13.5 Container use

The first container target is a deterministic build/mount directory, not an opaque container engine integration. A runner mounts `data/` read-only and `output/` writable, records the image digest and runtime configuration, then imports declared outputs. OCI-image or engine-specific adapters can build on the same projection manifest later.

### 13.6 Workspace mutations

A workspace is disposable and may be changed freely. Those changes do not affect the case. To retain them, the caller or runner captures selected files as new derived objects under an activity. A directory-diff helper may report candidate changes but never bulk-imports them without an explicit policy.

## 14. Parser and automation model

### 14.1 Parser contract

Conceptually:

```go
type Parser interface {
    Descriptor() ParserDescriptor
    Probe(context.Context, ObjectReader) (ProbeResult, error)
    Parse(context.Context, ParseRequest, Sink) error
}

type Sink interface {
    EmitArtifact(context.Context, ProducerKey, ArtifactDraft) (ArtifactRef, error)
    EmitObject(context.Context, ProducerKey, ObjectDraft, io.Reader) (ObjectRef, error)
    Relate(context.Context, ProducerKey, RelationshipDraft) (AssertionRef, error)
    Flush(context.Context) error
}
```

`ParserDescriptor` includes a stable ID, version, build/source digest, supported media/types, emitted schema versions, and determinism declaration. `ParseRequest` includes an immutable input reader, activity/session, canonical configuration, limits, and context.

The sink is concurrency-safe and batches catalog writes. Parser implementations are not assumed thread-safe; the scheduler either creates an instance per task through a factory or serializes that parser.

### 14.2 Repeatability and caching

A parser-run fingerprint covers parser ID/version/build, input object/blob, configuration, relevant schemas, and declared environment. A cache may offer a prior result set, but reuse is explicit and itself recorded. The library never silently treats a parser as deterministic merely because inputs match.

### 14.3 Failure and partial results

Artifacts emitted before a parser fails remain attributed to the failed activity. Batched writes are individually atomic. The activity records the failure, progress, and logs. A caller can exclude incomplete runs in queries or deliberately inspect them.

### 14.4 Isolation

In-process parsers have the authority of the host process and are appropriate only for trusted code. An external parser adapter should use a projection plus JSONL/RPC sink protocol and let the host choose an OS sandbox or container. The core library records the sandbox/environment but cannot certify it.

## 15. Proposed Go API

The simple path should remain small. Import the library as:

```go
import forensic "github.com/philcantcode/go-forensic-artifacts/forensic"
```

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

c, err := repo.CreateCase(ctx, forensic.CaseSpec{
    Name: "router-firmware-2026-07",
})
if err != nil { return err }

evidence, err := c.ImportEvidenceFile(ctx, "firmware.bin", forensic.EvidenceSpec{
    Label: "Vendor firmware 3.2.1",
    Acquisition: forensic.AcquisitionSpec{
        Method: "vendor-download",
        SourceURI: "https://vendor.invalid/firmware/3.2.1",
    },
})
```

Opening is by stable ID or unique case name:

```go
c, err := repo.OpenCase(ctx, forensic.ByName("router-firmware-2026-07"))
```

Agent-specific work uses an immutable session-bound view rather than changing a global actor:

```go
s, err := c.StartSession(ctx, forensic.SessionSpec{
    Agent: agentRef,
    Label: "HTTP parser investigation",
})
defer s.Close(ctx)
```

### 15.1 Explicit transformation

```go
run, err := s.BeginActivity(ctx, forensic.ActivitySpec{
    Type:  forensic.ActivityExtract,
    Label: "Unpack SquashFS",
    Tool:  unsquashfsDescriptor,
    Config: map[string]any{"no_xattrs": false},
})
if err != nil { return err }

if err := run.Use(ctx, evidence.RootObject, "filesystem-image"); err != nil {
    _ = run.Finish(ctx, forensic.OutcomeFailed(err))
    return err
}

_, err = run.CaptureFile(ctx, outputPath, forensic.ObjectSpec{
    Role: "extracted-file",
    Source: forensic.PathLocator{/* raw and display path */},
})
if err != nil {
    _ = run.Finish(ctx, forensic.OutcomeFailed(err))
    return err
}

return run.Finish(ctx, forensic.OutcomeSucceeded())
```

High-level helpers use the same activity machinery internally. A `Run` handle may be shared by worker goroutines.

### 15.2 Query, freeze, and project

```go
q := forensic.And(
    forensic.KindIs(forensic.EntityObject),
    forensic.PathGlob("**/*.sqlite"),
    forensic.ProducedBySession(s.ID()),
)

selection, err := s.Freeze(ctx, forensic.FreezeSpec{
    Name:  "SQLite databases found by agent 7",
    Query: q,
})
if err != nil { return err }

projection, err := s.CreateProjection(ctx, forensic.ProjectionSpec{
    Selection: selection.ID,
    Closure:   forensic.ClosureInputBytes,
    Layout:    forensic.LayoutByEvidencePath,
    Include:   forensic.IncludeBytes | forensic.IncludeMetadata | forensic.IncludeProvenance,
})
if err != nil { return err }

materialized, err := s.Materialize(ctx, projection.ID, forensic.DirectoryTarget{
    Path: "/work/agent-7/sqlite",
    Writable: true,
})
```

### 15.3 Agent-friendly exports

```go
err = c.ExportMarkdown(ctx, forensic.MarkdownSpec{
    Selection: selection.ID,
    Writer:    w,
    IncludeHashes: true,
    IncludeProvenanceSummary: true,
})
```

Markdown output has deterministic ordering, stable ID anchors, YAML/JSON front matter containing case/revision/selection/exporter details, escaped untrusted text, and relative links to projected files. JSONL is the loss-minimizing automation format; Markdown is a human/agent view.

### 15.4 API rules

- Every blocking or I/O operation accepts `context.Context`.
- No method logs, exits, or panics for operational errors.
- Errors support `errors.Is` for not found, conflict, busy, integrity, invalid input, unsupported storage, closed handle, and cancellation.
- Iteration is streaming with deterministic default order and explicit limits.
- Public structs use typed IDs, not interchangeable strings.
- `io.Reader`, `io.ReaderAt`, and `fs.FS` integration is preferred over path-only APIs.
- Storage and SQLite types remain internal so a future service backend does not break callers.

### 15.5 Package layout

The version 1 implementation keeps one public library package and colocates
operator tooling beside it:

```text
github.com/philcantcode/go-forensic-artifacts
├── forensic/              public library (repository, case, session, CAS,
│                          catalog, query, parser, projection, export, verify)
├── cmd/forensicctl/       thin operator CLI over the library
├── examples/              runnable samples (not part of the public API surface)
└── docs/                  design document and architecture decision records
```

Import path:

```go
import forensic "github.com/philcantcode/go-forensic-artifacts/forensic"
```

Later splits remain optional and should not break the public import path without
a major release. Candidates if the package grows:

```text
forensic                 public API surface (stable import)
internal/catalog/sqlite  schema, migrations, transactions, indexes
internal/cas             staging, hashing, publication, readers, verification
```

Additional public packages (`query`, `parser`, `projection`, `export/bagit`,
`schema/vuln`) should only be introduced when two real implementations or
consumers demonstrate the boundary. Storage-engine types stay non-exported.

## 16. Deliverables and interchange

### 16.1 Deliverable record

A deliverable records:

- frozen selection and resolved closure;
- included and excluded entity IDs with reasons;
- redaction/transformation policies and generated replacements;
- exporter/tool/configuration version;
- report/package version and predecessor;
- recipient and purpose where supplied;
- manifest object and all output object hashes;
- generation activity and verification result.

Report edits or different recipients create new deliverables. They do not update a package in place.

### 16.2 Formats

Initial formats:

- directory projection with `projection-manifest.json`;
- JSONL entities/activities/values;
- Markdown summary plus file tree;
- BagIt 1.0 package with SHA-256 payload and tag manifests;
- catalog snapshot package for full portable cases.

Later adapters:

- CASE/UCO JSON-LD;
- W3C PROV JSON/JSON-LD;
- SARIF or vulnerability-report schemas;
- OCI layout/build contexts;
- AFF4 metadata/image integration;
- HTML/PDF generated from an immutable report source.

BagIt is a transfer format, not the live case layout. A package is built from a frozen revision using a consistent SQLite backup/snapshot, copies only referenced immutable blobs, writes manifests last, verifies them, and then records the resulting package hash as a deliverable. The package cannot contain its own later deliverable record without recursion; the enclosing case records that fact.

## 17. Security and safety

### 17.1 Threats in scope

- hostile file and archive names;
- path traversal and Windows device names;
- symlink/hardlink escape;
- huge files, decompression bombs, and excessive artifact output;
- concurrent replacement/mutation of import sources;
- malformed parser values and manifests;
- SQL/FTS query injection;
- regex denial of service;
- tool commands or environments leaking secrets into provenance;
- a process crashing at any storage step;
- accidental modification or bit rot of managed bytes.

### 17.2 Controls

- Canonical, component-by-component path validation; never concatenate an untrusted path with a destination.
- Reject active symlinks by default and never hardlink materializations to blobs.
- Stage and atomically publish files; use exclusive creation and same-volume paths.
- Bound total bytes, file count, artifact count, text size, nesting, and concurrency.
- Use Go regular expressions and parameterized query compilation.
- Treat extracted evidence databases as evidence inputs, never attach them to the catalog connection.
- Record only allowlisted environment variables; support secret-value redaction and value digests.
- Escape Markdown/HTML and neutralize spreadsheet formula cells in tabular exports.
- Validate imported manifests before following any path or URL.
- Make network fetching an explicit adapter with URL, size, redirect, protocol, and authentication policies.
- Keep repository configuration free of secrets and support caller-managed file permissions/encryption.

### 17.3 Trust boundaries

Hash verification detects changed bytes relative to the recorded digest. It does not establish who acquired the data. Audit chaining detects inconsistent local history but is not independently tamper-proof. Running a parser in the same process trusts that parser completely. These distinctions must remain visible in API documentation and reports.

## 18. Backup, recovery, migration, and lifecycle

### 18.1 Backup

Never copy only a live `catalog.sqlite3`; committed transactions may still be in its WAL. `Case.Snapshot` uses the SQLite backup API or an equivalent consistent read, records revision and audit head, and packages the catalog snapshot with exactly the blobs referenced at that revision.

### 18.2 Startup recovery

On open, the library:

- validates format and supported schema versions;
- lets SQLite recover its WAL;
- marks stale running activities as `interrupted` only through an explicit recovery transaction;
- reports stale staging files and unreferenced final blobs without deleting them;
- reconciles repository registry entries with self-describing case directories;
- refuses automatic destructive repair.

The process cannot know whether another live process owns a running activity merely from age. Activity ownership includes process instance/heartbeat metadata; recovery uses an expiring lease plus host/process checks where reliable, and otherwise leaves the state for explicit repair.

### 18.3 Schema migration

The on-disk format has its own version independent of the Go module version. Migrations require an exclusive maintenance lease, create and verify a catalog backup, apply in one transaction where SQLite allows it, append a migration audit event, and fail closed on unsupported forward versions. Blob layout changes use resumable manifest-driven migrations rather than bulk renames hidden inside `Open`.

### 18.4 Retention and deletion

Version 1 can supersede/retract logical assertions and exclude data from views, but it does not physically delete committed blobs or audit history. A future disposition feature must be explicit, policy-driven, auditable, aware of shared blob references, and honest that removing bytes necessarily prevents later full verification.

## 19. Performance shape

Optimize for many concurrent readers, moderate batched writers, millions of metadata values, and a smaller number of very large blobs.

- One catalog per case keeps unrelated cases independent.
- CAS writes and hashing happen outside SQLite transactions.
- Parser sinks batch hundreds/thousands of values per short transaction.
- FTS and derived indexes are rebuildable.
- Large values/logs are stored as objects rather than database BLOBs.
- Queries require explicit pagination/streaming and stable ordering.
- Hash and projection workers use bounded pools and weighted byte limits.
- Case revisions make cache invalidation explicit.

SQLite's single-writer behavior is acceptable for the first local-agent use case if batching is effective. Do not add a public storage abstraction prematurely. Keep catalog implementation internal and define benchmarks that reveal when a daemon/PostgreSQL backend is actually justified.

## 20. Testing and acceptance criteria

### 20.1 Required test classes

- Unit tests for IDs, canonicalization, path rules, locators, values, and query compilation.
- Property tests for provenance DAG invariants, selection set algebra, deterministic layouts, and manifest round trips.
- Go fuzz tests for artifact values, manifests, paths, package readers, and query AST decoding.
- `go test -race` stress tests with many goroutines sharing repository/case/activity/sink handles.
- Multi-process helpers racing identical and distinct imports, finding revisions, selections, and case creation.
- Fault injection after every ingest publication step and every export step, followed by reopen/verify.
- Forced process termination during WAL writes, blob publish, parser batches, projection build, and migration.
- Cross-platform tests on supported Windows, Linux, and macOS filesystems.
- Golden compatibility fixtures for every on-disk schema version.
- Full verification tests that deliberately corrupt, omit, duplicate, and orphan content.
- Security tests for `..`, absolute/UNC paths, Unicode normalization, case collisions, device names, symlinks, archive bombs, and formula/Markdown injection.

### 20.2 Version 1 acceptance criteria

1. One hundred goroutines can import/search/tag/freeze against one case under the race detector without data races or broken invariants.
2. At least several independent local processes can do the same with bounded busy errors and successful retries.
3. Killing a writer at every instrumented persistence boundary never creates a committed object that points at missing bytes.
4. Repeating an idempotent request returns the same IDs; changing its payload produces a conflict.
5. A projection of the same selection/spec produces the same logical manifest on all supported platforms; only documented destination metadata may differ.
6. Mutating a writable workspace never changes a managed blob.
7. Full verification detects every injected blob/catalog/manifest corruption in the test corpus.
8. Every artifact and deliverable can be traced through activities to original objects or an explicit external/reported source.
9. A portable package can be restored as a new repository registration with stable case/entity IDs.
10. Old compatibility fixtures remain readable after every supported migration.

## 21. Delivery plan

### Phase 0: feasibility and ADRs

- Choose the public project/package name and Go support window.
- Compare CGO-free and CGO SQLite drivers behind `database/sql` for WAL, backup API, FTS5, busy cancellation, connection pragmas, and supported OS/architectures.
- Prove atomic no-replace publication and sync semantics on Windows/Linux/macOS.
- Prove live snapshot/backup behavior with concurrent writers.
- Decide UUIDv7 dependency and canonical event encoding.
- Record explicit ADRs for SQLite/local filesystem, SHA-256 CAS, per-case stores, and immutable provenance.

Exit: runnable spikes and selected dependencies, not production scaffolding.

### Phase 1: durable core

- Repository/case create, discover, open, close, and recovery.
- IDs, agents, sessions, activities, revisions, audit chain.
- Staged SHA-256 CAS import, object/evidence records, independent readers.
- Quick/full verification and external checkpoint generation/signing.
- Concurrency, crash, and compatibility harnesses.

Exit: safely import evidence, record a manual transformation, reopen, trace, and verify it.

### Phase 2: artifacts and search

- Namespaced artifact schemas and typed/raw values.
- Source locators and timestamp model.
- Parser factory/sink, batching, idempotency, failure handling.
- Typed query AST, path/hash/provenance filters, FTS capability, metadata regex.
- Streaming literal/regex byte search and saved hits.

Exit: parse concurrently and trace every search result to bytes and parser activity.

### Phase 3: selections and projections

- Revision-aware query freezing and set algebra.
- Projection specs, closure reasoning, safe path mapper, directory target.
- Copy/reflink workspaces, manifests, mutation verification, output capture.
- Deterministic JSONL and Markdown exporters.
- Runner boundary protocol for read-only input/writable output.

Exit: two agents independently project subsets, experiment, and import outputs without changing case sources.

### Phase 4: findings and delivery

- Assertions, tags, comments, review and stable finding/revision model.
- Vulnerability-research extension schema.
- Redaction-as-derivation.
- Deliverable records, portable case snapshots, BagIt export/verify/restore.
- Recipient/exclusion/redaction provenance.

Exit: produce a repeatable vulnerability deliverable whose included data and transformations are independently verifiable.

### Phase 5: ecosystem adapters

- CASE/UCO and W3C PROV export.
- External parser protocol and selected sandbox/runner integrations.
- E01/AFF4/TSK adapters without coupling them into core storage.
- Filesystem/timeline modules and optional SARIF/OCI/HTML integrations.
- Benchmark-driven evaluation of a service/distributed backend.

## 22. Implementation decisions

The feasibility work resolved the previously open choices:

1. The module is `github.com/philcantcode/go-forensic-artifacts`. The public package is `forensic` at `github.com/philcantcode/go-forensic-artifacts/forensic` (source under `forensic/`). Operator CLI and samples live in `cmd/forensicctl` and `examples/`.
2. SQLite uses the CGO-free `modernc.org/sqlite` driver. Startup and integration tests exercise WAL, FTS5, busy handling, and online backup.
3. The minimum language/toolchain version is Go 1.25.8. The implementation uses portable Go and filesystem APIs for Windows, Linux, and macOS.
4. Audit events and manifests use constrained canonical JSON.
5. SHA-256 is the version 1 CAS and fixity algorithm. Supplied SHA-256 acquisition hashes are checked during import.
6. Version 1 projections copy only. Reflinks can be added later without changing manifests or provenance.
7. The default busy timeout is five seconds. Byte-search context is capped at 4 KiB, result limits are explicit, and projections cap file count and total bytes.
8. The first vertical slice validates binary evidence, extracted JSON configuration, typed values, findings, experiments, and delivery. Format-specific parsers remain modules over the implemented parser/sink contract.

The corresponding durable choices are recorded in [the ADR series](adr/README.md).

## 23. Recommended first vertical slice

Implement one end-to-end vulnerability-research story before broad parser work:

1. create/open a case;
2. import a firmware file as original evidence;
3. manually record an extraction that produces one executable and one config file;
4. emit a handful of typed artifacts with path and byte/JSON locators;
5. query by path, parser, actor, and literal content;
6. freeze the config/executable subset;
7. materialize a writable directory projection;
8. record a wrapped or client-managed experiment producing a crash/log object;
9. create and revise a finding;
10. export Markdown plus a BagIt package and fully verify it;
11. repeat the workflow under goroutine/process races and injected crashes.

This slice tests the difficult seams—bytes versus identity, atomic publication, provenance, raw/normalized data, projections, outside execution, and delivery—before investing in a large artifact catalog.

## 24. Research references

- [The Sleuth Kit framework: The Blackboard](https://www.sleuthkit.org/sleuthkit/docs/framework-docs/mod_bbpage.html) describes the shared artifact/attribute service used by analysis modules.
- [The Sleuth Kit / Autopsy database schema](https://sleuthkit.org/sleuthkit/docs/jni-docs/4.12.1/db_schema_9_4_page.html) is useful prior art for content, artifacts, attributes, review status, ingest jobs, and reports.
- [Autopsy ingest module guide](https://www.sleuthkit.org/autopsy/docs/api-docs/4.22.1/mod_ingest_page.html) shows the operational parser/module lifecycle and posting/indexing model.
- [CASE ontology design and specification](https://caseontology.org/resources/case_design_document.html) and [CASE instance-data guidance](https://caseontology.org/resources/instance_data.html) define a cyber-investigation interchange model and JSON-LD serialization.
- [CASE ontology 1.4 documentation](https://ontology.caseontology.org/documentation/index.html) is the current ontology reference surveyed for this design.
- [W3C PROV primer](https://www.w3.org/TR/prov-primer/) introduces the entity/activity/agent and usage/generation model.
- [NIST IR 8387, Digital Evidence Preservation](https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8387.pdf) discusses preservation, chain of custody, source documentation, hashes, and separate secure storage of hash values.
- [Oxford Common File Layout 1.1](https://ocfl.io/1.1/spec/) provides useful ideas for transparent layouts, inventories, logical paths, immutable versions, content addressing, and fixity.
- [RFC 8493, BagIt 1.0](https://www.rfc-editor.org/info/rfc8493/) defines a simple payload/tag layout with checksum manifests and path-safety considerations.
- [SQLite WAL documentation](https://www.sqlite.org/wal.html), [SQLite isolation](https://www.sqlite.org/isolation.html), and [SQLite FTS5](https://www.sqlite.org/fts5.html) define the relevant concurrency, snapshot, durability, and indexing behavior.
- [AFF4 Standard repository](https://github.com/aff4/Standard) documents the Advanced Forensic Format v4 reference-image standard considered for adapters.

The proprietary EnCase and FTK product families are valuable workflow references, but this architecture does not depend on undocumented internal behavior or proprietary storage formats.
