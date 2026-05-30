# 3. SARIF output format

- Status: Accepted
- Date: 2026-05

## Context

To be useful in real workflows, findings should surface where developers
already work rather than only in a terminal.

## Decision

Emit SARIF 2.1.0 as a first-class output format so results integrate natively
with GitHub code scanning and other SARIF-aware tooling.

## Consequences

- Findings can appear in a repository's Security tab via CI upload.
- We commit to a minimal but spec-valid SARIF shape (one run, rules, results).
- Severity is mapped onto SARIF's `error`/`warning`/`note` levels.
