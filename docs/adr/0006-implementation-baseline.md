# ADR 0006: Go and SQLite implementation baseline

Status: accepted

The module supports Go 1.23 and uses `database/sql` with the CGO-free
`modernc.org/sqlite` driver. This keeps builds uniform across the initial Windows,
Linux, and macOS targets while retaining WAL and FTS5 capability.

The first release uses copy-only projections and implements the recommended
end-to-end vertical slice. Format and schema versions are independent of the Go
module version.
