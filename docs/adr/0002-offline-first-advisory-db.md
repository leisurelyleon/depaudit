# 2. Offline-first advisory database

- Status: Accepted
- Date: 2026-05

## Context

Dependency scanners are frequently run in CI and air-gapped environments where
outbound network access is restricted or forbidden. A tool that requires live
API calls on every scan is unusable in those settings.

## Decision

Separate fetching (`update-db`, online) from scanning (`scan`/`check`, offline).
Advisories are fetched once into a local JSON cache; scans read only the cache.

## Consequences

- Scans are fast, deterministic, and network-free.
- Advisory freshness becomes an explicit, user-controlled step (`update-db`).
- The cache format is a stable serialization of `AdvisoryDb`.
