# ADR 0008: Entity presentation views

Status: accepted

## Context

Hosts such as Campaign need to show selected forensic entities (evidence,
objects, artifacts, selections) in a right-hand inspector. Presentation must
answer which views exist, which view is preferred, and return bounded payloads
suitable for fields tables, hex dumps, and text windows.

If each host invents its own hex/text/metadata logic, view availability and
encoding semantics diverge, byte windows become unbounded, and Campaign would
own forensic presentation data it should only transport and render.

## Decision

The forensic package owns read-only entity presentation:

- `Case.ListPresentations(ctx, entity)` returns a `PresentationCatalog`: the
  entity ref, preferred view id, and ordered `PresentationViewInfo` entries
  (`id`, `title`, `encoding`, `available`, optional `reason`).
- `Case.Present(ctx, entity, viewID, opts)` returns a `Presentation` for one
  view with an encoding-specific payload (`fields`, `hex_window`, or `text`).

Stable view ids use a versioned namespace:

| View id | Encoding | Typical entity kinds |
|---------|----------|----------------------|
| `forensic.metadata/v1` | `fields` | evidence, object, artifact, selection |
| `forensic.hex/v1` | `hex_window` | object; evidence via root object |
| `forensic.text/v1` | `text` | object (and evidence root) when mostly text |

**Evidence happy path:** metadata is preferred; hex and text of the root
object are listed on the evidence catalog so callers do not need a second
entity selection. Presenting hex/text on evidence reads the root object
window; metadata includes the root object id as a field.

**Object preferred view:** `forensic.text/v1` when content is classified as
mostly text; otherwise `forensic.hex/v1`.

**Artifact / selection preferred view:** `forensic.metadata/v1`. Artifact
metadata includes a property values table; selection metadata includes member
kind/id rows.

Presentation is strictly read-only: no new entities, activities, blobs, or
case mutations. Payloads are bounded server-side:

- default byte window length: 16 KiB (`DefaultPresentLength`)
- maximum byte window length: 64 KiB (`MaxPresentLength`)
- offset must be non-negative; length is clamped to remaining bytes and max
- metadata field rows: at most `MaxMetadataFields` (256); individual values
  capped at `MaxFieldValueBytes` (4 KiB)
- selection member samples: at most `MaxSelectionMembersListed` (64); full
  `member_count` is always present

Truncation sets `Presentation.Truncated` and `TruncationReason` (and window
`truncated` flags for hex/text). Text availability always probes content;
media types are not trusted alone.

Views are registry-style inside the package so new encodings or view ids can
be added without changing host presentation models. Unavailable views remain
listed with `available: false` and a `reason` (for example high binary
entropy for text).

## Consequences

- Campaign and other hosts only transport and render catalog/presentation
  JSON; they do not invent hex, text classification, or metadata field sets.
- Hosts can switch views by re-calling `Present` with the chosen view id and
  optional window options.
- Large objects are inspected through repeated offset windows rather than full
  materialization into the API response.
- Unsupported entity kinds return `ErrUnsupported` (or `ErrNotFound` when the
  entity does not exist).
