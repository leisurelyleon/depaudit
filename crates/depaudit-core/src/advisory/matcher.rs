//! Matching dependencies against advisory version ranges.

use semver::{Version, VersionReq};

use crate::advisory::{Advisory, AdvisoryDb};
use crate::model::{Dependency, Finding, FindingKind};

/// Check a dependency against every advisory in the database, returning a
/// [`Finding`] for each match. Dependencies whose version cannot be parsed as a
/// concrete semantic version are skipped — we cannot make a sound claim about a
/// range-only spec without resolution.
pub fn match_dependency(dep: &Dependency, db: &AdvisoryDb) -> Vec<Finding> {
    let Some(version) = parse_version(&dep.version) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for advisory in db.advisories_for(&dep.name, dep.ecosystem) {
        if advisory_matches(advisory, &version) {
            findings.push(
                Finding::new(
                    FindingKind::Vulnerability,
                    advisory.severity,
                    dep.clone(),
                    advisory.summary.clone(),
                )
                .with_advisory_id(advisory.id.clone()),
            );
        }
    }
    findings
}

/// True when `version` satisfies the advisory's vulnerable range.
fn advisory_matches(advisory: &Advisory, version: &Version) -> bool {
    match VersionReq::parse(&advisory.vulnerable_range) {
        Ok(req) => req.matches(version),
        Err(_) => false,
    }
}

/// Parse a version string, tolerating a leading `v` (Go module style). Returns
/// `None` for ranges, wildcards, or non-semver specifiers.
fn parse_version(raw: &str) -> Option<Version> {
    let trimmed = raw.trim().trim_start_matches('v');
    Version::parse(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Dependency, Ecosystem, Severity};

    fn sample_db() -> AdvisoryDb {
        AdvisoryDb::from_advisories(vec![Advisory {
            id: "TEST-0001".to_owned(),
            ecosystem: Ecosystem::Cargo,
            package: "badcrate".to_owned(),
            vulnerable_range: ">=1.0.0, <1.2.0".to_owned(),
            severity: Severity::High,
            summary: "Example vulnerability".to_owned(),
        }])
    }

    #[test]
    fn matches_version_inside_range() {
        let dep = Dependency::new("badcrate", "1.1.0", Ecosystem::Cargo, true);
        let findings = match_dependency(&dep, &sample_db());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].advisory_id.as_deref(), Some("TEST-0001"));
    }

    #[test]
    fn ignores_version_outside_range() {
        let dep = Dependency::new("badcrate", "1.2.0", Ecosystem::Cargo, true);
        assert!(match_dependency(&dep, &sample_db()).is_empty());
    }

    #[test]
    fn ignores_wrong_ecosystem() {
        let dep = Dependency::new("badcrate", "1.1.0", Ecosystem::Npm, true);
        assert!(match_dependency(&dep, &sample_db()).is_empty());
    }

    #[test]
    fn skips_unparseable_version() {
        let dep = Dependency::new("badcrate", "^1.1.0", Ecosystem::Cargo, false);
        assert!(match_dependency(&dep, &sample_db()).is_empty());
    }
}
