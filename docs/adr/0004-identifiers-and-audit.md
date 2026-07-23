# ADR 0004: Typed UUIDv7 identifiers and JSON audit chain

Status: accepted

Public identifiers are typed, prefixed, UUIDv7-compatible 128-bit values rendered
as lowercase hexadecimal. IDs contain no names or paths.

Each catalog mutation increments the case revision and appends a canonical JSON
audit event chained with SHA-256. The chain detects local inconsistency; external
checkpoints are still required for independently anchored custody claims.
