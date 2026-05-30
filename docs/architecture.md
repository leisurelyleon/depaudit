# Architecture

`depaudit` is a Cargo workspace of three crates with a strict dependency
direction: the binary depends on the library crates, never the reverse.

## Crate responsibilities

- **`depaudit-core`** — Pure analysis logic with zero I/O. Manifest parsing,
  advisory matching, license policy, typosquat heuristics, and report
  aggregation. Every function is deterministic and unit-testable in isolation.
- **`depaudit-db`** — All advisory I/O: fetching from OSV (network) and
  reading/writing the local cache (filesystem). Depends on `depaudit-core` for
  the shared `Advisory` and `AdvisoryDb` types.
- **`depaudit-cli`** — The binary. Argument parsing, filesystem traversal,
  orchestration of the scan pipeline, and output rendering.

## Data flow

```text
discover manifests (walkdir)  ──►  parse (core::manifest)
│                │
▼                ▼
cache (db::cache)  ──►  AdvisoryDb  ──►  analyze (match + license + typosquat)
│
▼
Report  ──►  render (human | json | sarif)
```

## Why this split

Keeping `depaudit-core` I/O-free is the central design choice. It means the
entire analytical surface — the part where correctness actually matters — is
testable without touching a network or filesystem, which is why the core crate
carries the majority of the test suite.
