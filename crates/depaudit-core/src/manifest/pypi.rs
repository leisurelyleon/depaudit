//! Parsers for Python manifests (`requirements.txt`, `pyproject.toml`).

use toml::Value;

use crate::model::{Dependency, Ecosystem};
use crate::{CoreError, Result};

fn parse_err(reason: impl Into<String>) -> CoreError {
    CoreError::Parse {
        ecosystem: Ecosystem::PyPI,
        reason: reason.into(),
    }
}

/// Parse a `requirements.txt`. Pinned (`==`) entries are treated as locked.
pub fn parse_requirements_txt(content: &str) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    for raw in content.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() || line.starts_with('-') {
            continue; // Skip blanks, comments, and option lines (`-r base.txt`).
        }
        if let Some((name, version, pinned)) = parse_requirement(line) {
            deps.push(Dependency::new(name, version, Ecosystem::PyPI, pinned));
        }
    }
    Ok(deps)
}

/// Parse a `pyproject.toml`, supporting both PEP 621 (`[project] dependencies`)
/// and Poetry (`[tool.poetry.dependencies]`).
pub fn parse_pyproject_toml(content: &str) -> Result<Vec<Dependency>> {
    let value: Value = toml::from_str(content).map_err(|e| parse_err(e.to_string()))?;
    let mut deps = Vec::new();

    // PEP 621: project.dependencies is an array of PEP 508 strings.
    if let Some(Value::Array(list)) = value.get("project").and_then(|p| p.get("dependencies")) {
        for item in list {
            if let Some(req) = item.as_str() {
                if let Some((name, version, pinned)) = parse_requirement(req) {
                    deps.push(Dependency::new(name, version, Ecosystem::PyPI, pinned));
                }
            }
        }
    }

    // Poetry: tool.poetry.dependencies is a table of name -> version spec.
    if let Some(Value::Table(table)) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
    {
        for (name, spec) in table {
            if name == "python" {
                continue; // Not a real package dependency.
            }
            let version = match spec {
                Value::String(s) => s.clone(),
                Value::Table(t) => t
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or("*")
                    .to_owned(),
                _ => "*".to_owned(),
            };
            deps.push(Dependency::new(name, version, Ecosystem::PyPI, false));
        }
    }

    Ok(deps)
}

/// Remove a trailing `# comment`.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

/// Parse a PEP 508-style requirement into (name, version, is_pinned). Strips
/// extras and environment markers. Returns `None` when no name is present.
fn parse_requirement(req: &str) -> Option<(String, String, bool)> {
    let req = req.split(';').next().unwrap_or(req).trim();
    if req.is_empty() {
        return None;
    }

    // Multi-char operators are tested before single-char ones.
    const OPERATORS: [&str; 8] = ["===", "==", ">=", "<=", "~=", "!=", ">", "<"];
    for op in OPERATORS {
        if let Some(idx) = req.find(op) {
            let name = clean_name(&req[..idx]);
            let version = req[idx + op.len()..].trim().to_owned();
            if name.is_empty() {
                return None;
            }
            let pinned = op == "==" || op == "===";
            return Some((name, version, pinned));
        }
    }

    let name = clean_name(req);
    if name.is_empty() {
        None
    } else {
        Some((name, "*".to_owned(), false))
    }
}

/// Strip extras (`pkg[extra]`) and whitespace from a package name.
fn clean_name(raw: &str) -> String {
    let raw = raw.trim();
    match raw.find('[') {
        Some(idx) => raw[..idx].trim().to_owned(),
        None => raw.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pinned_and_ranged_requirements() {
        let content = "Django==4.2.0\nrequests>=2.31.0\n# a comment\nflask";
        let deps = parse_requirements_txt(content).unwrap();
        assert_eq!(deps.len(), 3);
        let django = deps.iter().find(|d| d.name == "Django").unwrap();
        assert!(django.is_locked);
        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.version, "*");
    }

    #[test]
    fn strips_extras_and_markers() {
        let parsed = parse_requirement("uvicorn[standard]==0.29.0 ; python_version >= '3.8'");
        assert_eq!(parsed, Some(("uvicorn".to_owned(), "0.29.0".to_owned(), true)));
    }

    #[test]
    fn parses_pep621_dependencies() {
        let content = r#"
            [project]
            dependencies = ["httpx>=0.27.0", "pydantic==2.6.0"]
        "#;
        let deps = parse_pyproject_toml(content).unwrap();
        assert_eq!(deps.len(), 2);
    }
}
