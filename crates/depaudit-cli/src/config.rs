//! Project configuration loaded from an optional `.depaudit.toml` file.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// User-tunable configuration. Every field has a sensible default, so a missing
/// or partial config file is always valid.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// SPDX identifiers explicitly allowed. Empty = allow anything not denied.
    pub allowed_licenses: Vec<String>,
    /// SPDX identifiers explicitly denied.
    pub denied_licenses: Vec<String>,
    /// Popular package names used as typosquat reference points.
    pub popular_packages: Vec<String>,
    /// Directory names skipped during traversal.
    pub ignore_dirs: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allowed_licenses: vec![
                "MIT".into(),
                "Apache-2.0".into(),
                "BSD-2-Clause".into(),
                "BSD-3-Clause".into(),
                "ISC".into(),
                "Unicode-3.0".into(),
            ],
            denied_licenses: Vec::new(),
            popular_packages: Vec::new(),
            ignore_dirs: vec![
                ".git".into(),
                "target".into(),
                "node_modules".into(),
                ".venv".into(),
                "venv".into(),
                "dist".into(),
                "build".into(),
            ],
        }
    }
}

impl Config {
    /// Load configuration from `path`, falling back to defaults when the file
    /// does not exist. A present-but-malformed file is a hard error.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let config: Config = toml::from_str(&text)
            .with_context(|| format!("parsing config file {}", path.display()))?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_yields_defaults() {
        let cfg = Config::load_or_default(Path::new("does-not-exist.toml")).unwrap();
        assert!(cfg.allowed_licenses.contains(&"MIT".to_owned()));
        assert!(cfg.ignore_dirs.contains(&"target".to_owned()));
    }

    #[test]
    fn partial_config_merges_with_defaults() {
        // Only override denied_licenses; everything else stays default.
        let toml = r#"denied_licenses = ["AGPL-3.0"]"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.denied_licenses, vec!["AGPL-3.0".to_owned()]);
        // serde(default) fills the rest:
        assert!(cfg.allowed_licenses.contains(&"MIT".to_owned()));
    }
}
