//! Parsers for Go module files (`go.mod`, `go.sum`).

use std::collections::BTreeSet;

use crate::Result;
use crate::model::{Dependency, Ecosystem};

/// Parse a `go.mod`'s `require` directives (block and single-line forms).
/// Module requirements are exact, so they are marked locked.
pub fn parse_go_mod(content: &str) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    let mut in_require_block = false;

    for raw in content.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        if in_require_block {
            if line == ")" {
                in_require_block = false;
            } else if let Some(dep) = parse_require_line(line) {
                deps.push(dep);
            }
            continue;
        }

        if line == "require (" {
            in_require_block = true;
        } else if let Some(rest) = line.strip_prefix("require ") {
            if let Some(dep) = parse_require_line(rest.trim()) {
                deps.push(dep);
            }
        }
    }

    Ok(deps)
}

/// Parse a `go.sum`. Each module/version pair appears twice (zip hash and
/// `/go.mod` hash); duplicates are collapsed.
pub fn parse_go_sum(content: &str) -> Result<Vec<Dependency>> {
    let mut seen = BTreeSet::new();
    let mut deps = Vec::new();

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(name), Some(version_field)) = (parts.next(), parts.next()) else {
            continue;
        };
        let version = version_field.trim_end_matches("/go.mod");
        if seen.insert((name.to_owned(), version.to_owned())) {
            deps.push(Dependency::new(name, version, Ecosystem::Go, true));
        }
    }

    Ok(deps)
}

/// Parse a single `require` entry of the form `module/path v1.2.3`.
fn parse_require_line(line: &str) -> Option<Dependency> {
    let mut parts = line.split_whitespace();
    let name = parts.next()?;
    let version = parts.next()?;
    Some(Dependency::new(name, version, Ecosystem::Go, true))
}

/// Remove a trailing `// comment` (Go uses `//`, including `// indirect`).
fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(idx) => &line[..idx],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_block_and_single_requires() {
        let content = "module example.com/app\n\ngo 1.22\n\nrequire (\n    github.com/pkg/errors v0.9.1\n    golang.org/x/sync v0.6.0 // indirect\n)\n\nrequire github.com/spf13/cobra v1.8.0\n";
        let deps = parse_go_mod(content).unwrap();
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.name == "github.com/spf13/cobra"));
    }

    #[test]
    fn collapses_go_sum_duplicates() {
        let content =
            "github.com/pkg/errors v0.9.1 h1:abc=\ngithub.com/pkg/errors v0.9.1/go.mod h1:def=\n";
        let deps = parse_go_sum(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, "v0.9.1");
    }
}
