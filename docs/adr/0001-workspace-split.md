# 1. Three-crate workspace split

- Status: Accepted
- Date: 2026-05

## Context

The tool needs to parse manifests, match advisories, fetch data, cache it, and
render output. Bundling all of this into one crate would entangle pure logic
with network and filesystem I/O, making the logic hard to test deterministically.

## Decision

Split into `depaudit-core` (pure logic, no I/O), `depaudit-db` (advisory I/O),
and `depaudit-cli` (binary + orchestration). Dependencies flow inward toward
`core`.

## Consequences

- The analytical core is fully unit-testable without external dependencies.
- A clear seam exists for future surfaces (e.g. a library API or web service)
  to reuse `core` and `db` without the CLI.
- Slightly more boilerplate (three manifests) than a single crate.
