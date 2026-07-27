# ADR 0007: Compose queries across provenance relationships

Status: accepted

## Context

Cases grow from original evidence into extracted objects, parser artifacts,
assertions, findings, and experimental outputs. A fixed-root descendant query
can answer "what came from this entity?" but cannot select candidates according
to properties elsewhere in their provenance graph. For example, a caller needs
to express "manifest objects whose ancestor APK also produced a locale artifact
with normalized language `ru`" as one revision-stable query.

Requiring hosts to query, trace, join, and refreeze entities themselves would
duplicate provenance semantics, create unbounded N+1 traversal, and permit the
case to change between query stages.

## Decision

The typed query AST includes two unary relationship predicates:

- `HasAncestor(q)` matches a candidate when at least one strict transitive
  provenance ancestor matches `q`; and
- `HasDescendant(q)` matches a candidate when at least one strict transitive
  provenance descendant matches `q`.

An ancestor/descendant edge follows immutable activity usage and generation:
an activity input is an ancestor of each of that activity's outputs. The
candidate itself is excluded. Relationship predicates may nest and compose
with all other typed predicates, including artifact types and normalized
values. Existing query depth and node limits apply to the complete expression.

Evaluation occurs in the same SQLite read snapshot and at the same case
revision as the outer query. Related entity sets and loaded entity views are
cached for the evaluation. `QueryPage` preserves its explicit revision across
relationship traversal. The public API accepts no relationship SQL or graph
callbacks.

A live query remains a view over the observed case revision. `Session.Freeze`
continues to be the sole way to turn it into immutable ordered membership for a
projection, targetset, experiment, or deliverable.

The first implementation uses bounded typed queries over the existing
provenance DAG. A transitive-closure index may replace recursive traversal only
after benchmarks demonstrate a need; it must remain rebuildable from activity
input/output edges and cannot become another provenance authority.

## Consequences

- Hosts can filter original and derived entities using facts anywhere in their
  provenance neighborhood without rebuilding graph semantics.
- Parser artifacts and extracted byte-bearing objects remain independently
  typed while still supporting correlated selection.
- Nested relationship queries are more expensive than scalar predicates and
  must retain query-size limits, revision bounds, and evaluation caches.
- Relationship predicates describe structural provenance only. Semantic links
  that are not activity derivation remain assertions and require separately
  typed predicates.
