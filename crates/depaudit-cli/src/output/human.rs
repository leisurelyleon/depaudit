//! Human-readable, colored terminal output.

use depaudit_core::model::Severity;
use depaudit_core::Report;
use owo_colors::OwoColorize;

/// Render a report as a colored, human-friendly summary.
pub fn render(report: &Report) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "Scanned {} manifest(s), {} dependency(ies).\n",
        report.manifests_scanned, report.dependencies_examined
    ));

    if report.findings.is_empty() {
        out.push_str(&"No issues found.\n".green().to_string());
        return out;
    }

    out.push('\n');
    for finding in &report.findings {
        let tag = severity_tag(finding.severity);
        let id = finding
            .advisory_id
            .as_deref()
            .map(|i| format!(" [{i}]"))
            .unwrap_or_default();
        out.push_str(&format!(
            "{tag} {}@{} ({}){id}\n    {}\n",
            finding.dependency.name,
            finding.dependency.version,
            finding.dependency.ecosystem,
            finding.message,
        ));
    }

    out.push_str(&format!(
        "\nSummary: {} critical, {} high, {} medium, {} low.\n",
        report.count_at(Severity::Critical),
        report.count_at(Severity::High),
        report.count_at(Severity::Medium),
        report.count_at(Severity::Low),
    ));

    out
}

/// A colored, fixed-width severity tag.
fn severity_tag(severity: Severity) -> String {
    match severity {
        Severity::Critical => "CRITICAL".bright_red().bold().to_string(),
        Severity::High => "HIGH    ".red().to_string(),
        Severity::Medium => "MEDIUM  ".yellow().to_string(),
        Severity::Low => "LOW     ".blue().to_string(),
        Severity::Info => "INFO    ".dimmed().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depaudit_core::model::{Dependency, Ecosystem, Finding, FindingKind};

    #[test]
    fn renders_clean_report() {
        let report = Report::new();
        let out = render(&report);
        assert!(out.contains("No issues found"));
    }

    #[test]
    fn renders_findings_with_details() {
        let mut report = Report::new();
        report.manifests_scanned = 1;
        report.dependencies_examined = 1;
        let dep = Dependency::new("badcrate", "1.1.0", Ecosystem::Cargo, true);
        report.extend_findings([Finding::new(
            FindingKind::Vulnerability,
            Severity::High,
            dep,
            "known issue",
        )
        .with_advisory_id("TEST-0001")]);

        let out = render(&report);
        assert!(out.contains("badcrate"));
        assert!(out.contains("TEST-0001"));
    }
}
