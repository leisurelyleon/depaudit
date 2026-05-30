# depaudit

> A fast, offline-capable polyglot dependency & supply-chain auditor.

`depaudit` scans every dependency manifest in a repository — across npm, PyPI,
Cargo, and Go modules — in a single pass, and reports known vulnerabilities,
license-policy violations, and typosquat/dependency-confusion risks. It runs
fully offline against a cached advisory database, making it safe for
air-gapped and CI environments.

## The Problem

Modern projects are polyglot. A single repo may carry a `package.json`, a
`pyproject.toml`, and a `Cargo.toml`, each with its own ecosystem of risk.
Existing tools are usually single-ecosystem, network-dependent, and awkward to
wire into CI. `depaudit` unifies the scan, runs offline, and speaks SARIF so
results surface natively in GitHub code-scanning.

## Architecture

```
depaudit-core   pure logic, zero I/O  — parsers, matching, scoring (fully unit-tested)
depaudit-db     advisory fetch + local cache (offline-first)
depaudit-cli    arg parsing, orchestration, output rendering (the binary)
```

See [`docs/architecture.md`](docs/architecture.md) and the decision records in
[`docs/adr/`](docs/adr/) for rationale.

## Install

```bash
# From source
cargo install --path crates/depaudit-cli

# Homebrew (after first release)
brew install josephleoned/tap/depaudit
```

## Usage

```bash
depaudit scan ./my-project          # human-readable report
depaudit scan ./my-project --json   # machine-readable
depaudit check                      # CI mode: non-zero exit on findings
depaudit update-db                  # refresh the local advisory cache
```

## Results

Benchmarks (see [`benches/`](benches/)) and example output are documented in
[`docs/usage.md`](docs/usage.md).

## License

MIT — see [LICENSE](LICENSE).
