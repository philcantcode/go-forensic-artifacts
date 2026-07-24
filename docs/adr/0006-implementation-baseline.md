# ADR 0006: Go and SQLite implementation baseline

Status: accepted

The module is `github.com/philcantcode/go-forensic-artifacts`. The public library
package is `forensic` at
`github.com/philcantcode/go-forensic-artifacts/forensic` (source tree under
`forensic/`). Operator tooling lives in `cmd/forensicctl`; runnable samples live
in `examples/`.

The toolchain floor is Go 1.25.8. Persistence uses `database/sql` with the
CGO-free `modernc.org/sqlite` driver so builds stay uniform across the initial
Windows, Linux, and macOS targets while retaining WAL and FTS5 capability.

The first release uses copy-only projections and implements the recommended
end-to-end vertical slice. Format and schema versions are independent of the Go
module version.
