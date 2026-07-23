# Releasing

Releases follow semantic versioning. Version 0.x minor releases may contain
breaking API changes; patch releases should remain compatible.

1. Update `CHANGELOG.md` with the release version and date.
2. Run `go mod verify`, `go vet ./...`, `go test ./... -count=1`, and
   `go test -race ./... -count=1`.
3. Commit the release preparation to `main` and wait for CI to pass.
4. Create and push an annotated tag:

   ```text
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

The release workflow reruns the tests and creates the GitHub release with
generated notes. If it fails before creating the release, fix the problem and
rerun the workflow; do not move a published tag.
