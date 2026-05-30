//! Subcommand implementations and the shared scan pipeline.

pub mod check;
pub mod scan;
pub mod update_db;

use std::path::Path;

use anyhow::{Context, Result};
use walkdir::WalkDir;

use depaudit_core::advisory::{AdvisoryDb, match_dependency};
use depaudit_core::license::LicensePolicy;
use depaudit_core::manifest::{self, ManifestKind};
use depaudit_core::model::Dependency;
use depaudit_core::{Report, typosquat};

use crate::config::Config;

/// Walk `root`, parse every recognized manifest, and collect all dependencies
/// alongside a count of manifests successfully scanned.
pub fn collect_dependencies(root: &Path, config: &Config) -> Result<(Vec<Dependency>, usize)> {
    let mut deps = Vec::new();
    let mut manifests_scanned = 0;

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_ignored_dir(e, &config.ignore_dirs))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // Skip unreadable entries rather than aborting.
        };
        if !entry.file_type().is_file() {
            continue;
        }

        let Some(file_name) = entry.file_name().to_str() else {
            continue;
        };
        let Some(kind) = ManifestKind::from_file_name(file_name) else {
            continue;
        };

        let content = std::fs::read_to_string(entry.path())
            .with_context(|| format!("reading manifest {}", entry.path().display()))?;

        match manifest::parse(kind, &content) {
            Ok(parsed) => {
                manifests_scanned += 1;
                deps.extend(parsed);
            }
            Err(e) => {
                // A malformed manifest is reported but does not abort the scan.
                eprintln!("warning: skipping {}: {e}", entry.path().display());
            }
        }
    }

    Ok((deps, manifests_scanned))
}

/// True when a directory entry is in the configured ignore list.
fn is_ignored_dir(entry: &walkdir::DirEntry, ignore_dirs: &[String]) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    entry
        .file_name()
        .to_str()
        .map(|name| ignore_dirs.iter().any(|d| d == name))
        .unwrap_or(false)
}

/// Run the full analysis pipeline over a set of dependencies, producing a report.
pub fn analyze(
    deps: Vec<Dependency>,
    manifests_scanned: usize,
    db: &AdvisoryDb,
    config: &Config,
) -> Report {
    let policy = LicensePolicy::new(
        config.allowed_licenses.clone(),
        config.denied_licenses.clone(),
    );
    let popular: Vec<&str> = config.popular_packages.iter().map(String::as_str).collect();

    let mut report = Report::new();
    report.manifests_scanned = manifests_scanned;
    report.dependencies_examined = deps.len();

    for dep in &deps {
        // Vulnerability matching.
        report.extend_findings(match_dependency(dep, db));

        // Typosquat heuristic (only when reference names are configured).
        if !popular.is_empty() {
            if let Some(finding) = typosquat::evaluate(dep, &popular) {
                report.extend_findings([finding]);
            }
        }

        // License policy is evaluated by the caller when license metadata is
        // available; `policy` is threaded through for that future wiring.
        let _ = &policy;
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use depaudit_core::advisory::Advisory;
    use depaudit_core::model::{Ecosystem, Severity};

    #[test]
    fn analyze_flags_known_vuln() {
        let db = AdvisoryDb::from_advisories(vec![Advisory {
            id: "TEST-0001".into(),
            ecosystem: Ecosystem::Cargo,
            package: "badcrate".into(),
            vulnerable_range: ">=1.0.0, <1.2.0".into(),
            severity: Severity::High,
            summary: "bad".into(),
        }]);
        let deps = vec![Dependency::new("badcrate", "1.1.0", Ecosystem::Cargo, true)];
        let report = analyze(deps, 1, &db, &Config::default());
        assert_eq!(report.total_findings(), 1);
    }
}
