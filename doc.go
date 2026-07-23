// Package forensic manages immutable forensic evidence and derived research
// artifacts in durable, local-first case repositories.
//
// Managed bytes are stored in a per-case SHA-256 content store while SQLite
// records occurrence identity, activity provenance, artifacts, findings,
// selections, projections, audit history, and deliverables. Repository, Case,
// Session, and Activity handles are safe for concurrent goroutine use. Separate
// processes may cooperate on one local machine.
package forensic
