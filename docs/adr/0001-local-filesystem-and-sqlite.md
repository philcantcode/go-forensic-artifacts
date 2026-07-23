# ADR 0001: Local filesystem and SQLite

Status: accepted

Each repository is a local directory. Every case has a SQLite catalog beside its
managed files. SQLite runs in WAL mode with foreign keys, full synchronization,
and a bounded busy timeout.

This gives durable transactions and same-host process concurrency without a
service. Network filesystems and distributed writers are unsupported.
