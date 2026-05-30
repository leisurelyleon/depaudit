//! Machine-readable JSON output.

use depaudit_core::Report;

/// Render a report as pretty-printed JSON.
pub fn render(report: &Report) -> anyhow::Result<String> {
    let json = serde_json::to_string_pretty(report)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use depaudit_core::model::{Dependency, Ecosystem, Finding, FindingKind, Severity};

    #[test]
    fn produces_valid_json() {
        let mut report = Report::new();
        let dep = Dependency::new("x", "1.0.0", Ecosystem::Cargo, true);
        report.extend_findings([Finding::new(
            FindingKind::Vulnerability,
            Severity::Low,
            dep,
            "msg",
        )]);

        let out = render(&report).unwrap();
        // Round-trips back into a generic JSON value.
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(parsed.get("findings").is_some());
    }
}
