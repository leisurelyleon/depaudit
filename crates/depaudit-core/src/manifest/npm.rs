//! Parsers for npm manifests (`package.json`) and lockfiles (`package-lock.json`).

use serde_json::Value;

use crate::model::{Dependency, Ecosystem};
use crate::{CoreError, Result};

fn parse_err(reason: impl Into<String>) -> CoreError {
    CoreError::Parse {
        ecosystem: Ecosystem::Npm,
        reason: reason.into(),
    }
}

/// Parse a `package.json`. Declared versions are ranges (`is_locked = false`).
pub fn parse_package_json(content: &str) -> Result<Vec<Dependency>> {
    let value: Value = serde_json::from_str(content).map_err(|e| parse_err(e.to_string()))?;

    let mut deps = Vec::new();
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(Value::Object(map)) = value.get(field) {
            for (name, version) in map {
                if let Some(version) = version.as_str() {
                    deps.push(Dependency::new(name, version, Ecosystem::Npm, false));
                }
            }
        }
    }
    Ok(deps)
}

/// Parse a `package-lock.json` (lockfileVersion 2/3 `packages`, with a fallback
/// to the legacy v1 `dependencies` tree). Entries are exact (`is_locked = true`).
pub fn parse_package_lock(content: &str) -> Result<Vec<Dependency>> {
    let value: Value = serde_json::from_str(content).map_err(|e| parse_err(e.to_string()))?;

    let mut deps = Vec::new();

    // lockfileVersion 2/3: a flat `packages` map keyed by install path.
    if let Some(Value::Object(packages)) = value.get("packages") {
        for (path, entry) in packages {
            if path.is_empty() {
                continue; // The empty key is the root project itself.
            }
            let name = package_name_from_path(path);
            if let Some(version) = entry.get("version").and_then(Value::as_str) {
                deps.push(Dependency::new(name, version, Ecosystem::Npm, true));
            }
        }
        return Ok(deps);
    }

    // lockfileVersion 1: a nested `dependencies` object keyed by package name.
    if let Some(Value::Object(dependencies)) = value.get("dependencies") {
        for (name, entry) in dependencies {
            if let Some(version) = entry.get("version").and_then(Value::as_str) {
                deps.push(Dependency::new(name, version, Ecosystem::Npm, true));
            }
        }
    }

    Ok(deps)
}

/// Derive a package name from an install path such as `node_modules/foo` or
/// `node_modules/foo/node_modules/@scope/bar`.
fn package_name_from_path(path: &str) -> &str {
    match path.rfind("node_modules/") {
        Some(idx) => &path[idx + "node_modules/".len()..],
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_json_sections() {
        let content = r#"{
            "dependencies": { "react": "^18.2.0" },
            "devDependencies": { "typescript": "5.4.2" }
        }"#;
        let deps = parse_package_json(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "react"));
    }

    #[test]
    fn parses_lockfile_v3_packages() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root" },
                "node_modules/lodash": { "version": "4.17.21" },
                "node_modules/@scope/util": { "version": "2.0.0" }
            }
        }"#;
        let deps = parse_package_lock(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(
            deps.iter()
                .any(|d| d.name == "@scope/util" && d.version == "2.0.0")
        );
    }

    #[test]
    fn derives_scoped_name() {
        assert_eq!(
            package_name_from_path("node_modules/@scope/bar"),
            "@scope/bar"
        );
    }
}
