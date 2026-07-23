# ADR 0005: Freeze before projection

Status: accepted

Queries are typed expression trees rather than SQL. A selection freezes their
ordered results and observed case revision. A projection consumes a frozen
selection and records closure, layout, and included representations.

Materializations always copy bytes and write their manifest last. They never
hardlink managed evidence, so writable workspaces cannot mutate the case.
