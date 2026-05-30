//! Aggregation of findings into a final report.

use serde::{Deserialize, Serialize};

use crate::model::{Finding, Severity};

/// The aggregated result of a scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// Number of manifests successfully scanned.
    pub manifests_scanned: usize,
    /// Number of distinct dependencies examined.
    pub dependencies_examined: usize,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a batch of findings to the report.
    pub fn extend_findings(&mut self, findings: impl IntoIterator<Item = Finding>) {
        self.findings.extend(findings);
    }

    /// The highest severity present among all findings, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Count of findings at a given severity.
    pub fn count_at(&self, severity: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == severity).count()
    }

    /// Total number of findings.
    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }

    /// Whether this report should fail a CI run, given a minimum severity
    /// threshold at or above which any finding is a failure.
    pub fn should_fail(&self, threshold: Severity) -> bool {
        self.findings.iter().any(|f| f.severity >= threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Dependency, Ecosystem, FindingKind};

    fn finding(severity: Severity) -> Finding {
        let dep = Dependency::new("x", "1.0.0", Ecosystem::Cargo, true);
        Finding::new(FindingKind::Vulnerability, severity, dep, "msg")
    }

    #[test]
    fn max_severity_picks_highest() {
        let mut r = Report::new();
        r.extend_findings([finding(Severity::Low), finding(Severity::Critical), finding(Severity::Medium)]);
        assert_eq!(r.max_severity(), Some(Severity::Critical));
    }

    #[test]
    fn should_fail_respects_threshold() {
        let mut r = Report::new();
        r.extend_findings([finding(Severity::Medium)]);
        assert!(r.should_fail(Severity::Low));
        assert!(r.should_fail(Severity::Medium));
        assert!(!r.should_fail(Severity::High));
    }

    #[test]
    fn empty_report_has_no_max_severity() {
        assert_eq!(Report::new().max_severity(), None);
    }
}
