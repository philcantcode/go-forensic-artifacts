// Package forensic manages immutable forensic evidence and derived research
// artifacts in durable, local-first case repositories.
//
// Import:
//
//	import forensic "github.com/philcantcode/go-forensic-artifacts/forensic"
//
// Managed bytes are stored in a per-case SHA-256 content store while SQLite
// records occurrence identity, activity provenance, artifacts, findings,
// selections, projections, audit history, and deliverables. Repository, Case,
// Session, and Activity handles are safe for concurrent goroutine use. Separate
// processes may cooperate on one local machine.
//
// Operator tooling and samples live outside this package, under cmd/ and
// examples/ in the module root.
package forensic
