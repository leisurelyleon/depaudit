//! Parsers for Cargo manifests (`Cargo.toml`) and lockfiles (`Cargo.lock`).

use toml::Value;

use crate::model::{Dependency, Ecosystem};
use crate::{CoreError, Result};

fn parse_err(reason: impl Into<String>) -> CoreError {
    CoreError::Parse {
        ecosystem: Ecosystem::Cargo,
        reason: reason.into(),
    }
}

/// Parse a `Cargo.toml` manifest. Versions here are declared ranges, so the
/// resulting dependencies are marked `is_locked = false`.
pub fn parse_cargo_toml(content: &str) -> Result<Vec<Dependency>> {
    let value: Value = toml::from_str(content).map_err(|e| parse_err(e.to_string()))?;

    let mut deps = Vec::new();
    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(Value::Table(table)) = value.get(table_name) {
            for (name, spec) in table {
                if let Some(version) = extract_version(spec) {
                    deps.push(Dependency::new(name, version, Ecosystem::Cargo, false));
                }
            }
        }
    }
    Ok(deps)
}

/// Extract a version from a specifier that may be a bare string (`serde = "1"`)
/// or a table (`serde = { version = "1", features = [...] }`).
fn extract_version(spec: &Value) -> Option<String> {
    match spec {
        Value::String(s) => Some(s.clone()),
        Value::Table(t) => t.get("version").and_then(Value::as_str).map(str::to_owned),
        _ => None,
    }
}

/// Parse a `Cargo.lock` file. Entries are exact, so dependencies are locked.
pub fn parse_cargo_lock(content: &str) -> Result<Vec<Dependency>> {
    let value: Value = toml::from_str(content).map_err(|e| parse_err(e.to_string()))?;

    let mut deps = Vec::new();
    if let Some(Value::Array(packages)) = value.get("package") {
        for pkg in packages {
            let name = pkg.get("name").and_then(Value::as_str);
            let version = pkg.get("version").and_then(Value::as_str);
            if let (Some(name), Some(version)) = (name, version) {
                deps.push(Dependency::new(name, version, Ecosystem::Cargo, true));
            }
        }
    }
    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_and_table_versions() {
        let content = r#"
            [dependencies]
            serde = "1.0.197"
            tokio = { version = "1.36.0", features = ["full"] }
        "#;
        let deps = parse_cargo_toml(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(
            deps.iter()
                .any(|d| d.name == "serde" && d.version == "1.0.197")
        );
        assert!(
            deps.iter()
                .any(|d| d.name == "tokio" && d.version == "1.36.0")
        );
    }

    #[test]
    fn parses_lockfile_packages() {
        let content = r#"
            [[package]]
            name = "anyhow"
            version = "1.0.80"

            [[package]]
            name = "libc"
            version = "0.2.153"
        "#;
        let deps = parse_cargo_lock(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().all(|d| d.is_locked));
    }
}
