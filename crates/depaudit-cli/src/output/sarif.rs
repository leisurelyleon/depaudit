//! SARIF 2.1.0 output for GitHub code-scanning integration.
//!
//! We emit a minimal but spec-valid SARIF log: one run, one tool, one rule per
//! distinct finding kind, and one result per finding. This is what lets
//! `depaudit` results appear natively in a repository's Security tab.

use serde_json::{Value, json};

use depaudit_core::Report;
use depaudit_core::model::{FindingKind, Severity};

/// SARIF schema URL and version emitted in the log header.
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

/// Render a report as a SARIF 2.1.0 JSON log.
pub fn render(report: &Report) -> anyhow::Result<String> {
    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": rule_id(f.kind),
                "level": sarif_level(f.severity),
                "message": { "text": f.message },
                "properties": {
                    "package": f.dependency.name,
                    "version": f.dependency.version,
                    "ecosystem": f.dependency.ecosystem.to_string(),
                    "advisoryId": f.advisory_id,
                }
            })
        })
        .collect();

    let log = json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "depaudit",
                    "informationUri": "https://github.com/josephleoned/depaudit",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules(),
                }
            },
            "results": results,
        }]
    });

    Ok(serde_json::to_string_pretty(&log)?)
}

/// The stable rule identifier for a finding kind.
fn rule_id(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::Vulnerability => "vulnerability",
        FindingKind::License => "license-policy",
        FindingKind::Typosquat => "typosquat",
    }
}

/// The set of rule definitions referenced by results.
fn rules() -> Value {
    json!([
        { "id": "vulnerability", "name": "KnownVulnerability",
          "shortDescription": { "text": "Dependency has a known security advisory." } },
        { "id": "license-policy", "name": "LicensePolicyViolation",
          "shortDescription": { "text": "Dependency license violates configured policy." } },
        { "id": "typosquat", "name": "PossibleTyposquat",
          "shortDescription": { "text": "Dependency name resembles a popular package." } },
    ])
}

/// Map severity onto SARIF's `level` vocabulary (`error`/`warning`/`note`).
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depaudit_core::model::{Dependency, Ecosystem, Finding};

    #[test]
    fn produces_spec_shaped_sarif() {
        let mut report = Report::new();
        let dep = Dependency::new("badcrate", "1.1.0", Ecosystem::Cargo, true);
        report.extend_findings([Finding::new(
            FindingKind::Vulnerability,
            Severity::High,
            dep,
            "known issue",
        )]);

        let out = render(&report).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "depaudit");
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn severity_maps_to_sarif_levels() {
        assert_eq!(sarif_level(Severity::Critical), "error");
        assert_eq!(sarif_level(Severity::Medium), "warning");
        assert_eq!(sarif_level(Severity::Low), "note");
    }
}
