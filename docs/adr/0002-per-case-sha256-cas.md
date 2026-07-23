# ADR 0002: Per-case SHA-256 content store

Status: accepted

Managed bytes live in a SHA-256 content-addressed store owned by one case. An
object identifies an occurrence and its provenance; a blob identifies bytes, so
equal content may back several objects.

Imports stream through same-volume staging and publish bytes before committing
catalog references. Cross-case deduplication is rejected to keep cases portable
and isolated.
