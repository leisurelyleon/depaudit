# Usage

## Commands

```bash
depaudit scan [PATH]            # scan and print a report (default PATH: ".")
depaudit check [PATH]           # CI mode: non-zero exit on findings
depaudit update-db [PATH]       # refresh the local advisory cache from OSV
```

## Options

- `--format <human|json|sarif>` — output format (default: `human`)
- `--fail-on <info|low|medium|high|critical>` — `check` failure threshold
  (default: `high`)
- `--config <PATH>` — path to `.depaudit.toml` (default: `.depaudit.toml`)

## Configuration (`.depaudit.toml`)

```toml
allowed_licenses = ["MIT", "Apache-2.0", "BSD-3-Clause"]
denied_licenses  = ["AGPL-3.0"]
popular_packages = ["requests", "lodash", "react"]
ignore_dirs      = [".git", "target", "node_modules"]
```

## Typical CI usage

```bash
depaudit update-db        # once, to populate the cache
depaudit check --fail-on high --format sarif > results.sarif
```
