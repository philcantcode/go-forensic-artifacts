# ADR 0003: Immutable activity provenance

Status: accepted

Activities have fixed actors, tools, configuration, and named inputs. The first
output seals the inputs. Objects, artifacts, findings, selections, projections,
and manifests are immutable outputs of exactly one activity.

Corrections create new assertions or finding revisions. Failed activities retain
their already captured outputs because those outputs may be the evidence sought.
