//! Fetching advisories from the OSV API (<https://osv.dev>).
//!
//! OSV exposes a `POST /v1/query` endpoint that, given a package name,
//! ecosystem, and version, returns the vulnerabilities affecting it. We map
//! OSV's response onto `depaudit-core`'s [`Advisory`] type.
//!
//! Mapping notes (intentional simplifications, documented honestly):
//! - OSV expresses affected versions as `introduced` / `fixed` event pairs;
//!   we translate these into a single semver requirement string.
//! - OSV severity can appear as a CVSS vector or a coarse label; we use the
//!   coarse `database_specific.severity` label when present and default to
//!   `Medium` otherwise.

use serde::{Deserialize, Serialize};

use depaudit_core::advisory::Advisory;
use depaudit_core::model::{Ecosystem, Severity};

use crate::Result;

/// Default OSV query endpoint.
const OSV_ENDPOINT: &str = "https://api.osv.dev/v1/query";

/// A client for the OSV advisory API.
#[derive(Debug, Clone)]
pub struct OsvClient {
    client: reqwest::Client,
    endpoint: String,
}

impl OsvClient {
    /// Create a client targeting the public OSV endpoint.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: OSV_ENDPOINT.to_owned(),
        }
    }

    /// Create a client targeting a custom endpoint (useful for tests/mirrors).
    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: endpoint.into(),
        }
    }

    /// Query OSV for advisories affecting a specific package version.
    pub async fn query(
        &self,
        name: &str,
        ecosystem: Ecosystem,
        version: &str,
    ) -> Result<Vec<Advisory>> {
        let body = OsvQuery {
            version,
            package: OsvQueryPackage {
                name,
                ecosystem: osv_ecosystem(ecosystem),
            },
        };

        let response = self
            .client
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let parsed: OsvResponse = response.json().await?;
        Ok(map_response(parsed, name, ecosystem))
    }
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Map our ecosystem enum onto OSV's ecosystem identifiers.
fn osv_ecosystem(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Cargo => "crates.io",
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "PyPI",
        Ecosystem::Go => "Go",
    }
}

/// Strip a leading `v` and surrounding whitespace from a version token.
fn normalize(version: &str) -> String {
    version.trim().trim_start_matches('v').to_owned()
}

/// Map a coarse OSV severity label to our [`Severity`]. Defaults to `Medium`
/// when absent or unrecognized.
fn map_severity(label: Option<&str>) -> Severity {
    match label.map(str::to_ascii_uppercase).as_deref() {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MODERATE" | "MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        _ => Severity::Medium,
    }
}

/// Translate a sequence of OSV range events into a semver requirement string,
/// e.g. `>=1.0.0, <1.2.0`. Returns `None` only when there are no events at all.
fn build_version_req(events: &[OsvEvent]) -> Option<String> {
    if events.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    for event in events {
        if let Some(introduced) = &event.introduced {
            // `0` is OSV's sentinel for "from the beginning".
            if introduced != "0" {
                parts.push(format!(">={}", normalize(introduced)));
            }
        }
        if let Some(fixed) = &event.fixed {
            parts.push(format!("<{}", normalize(fixed)));
        }
        if let Some(last) = &event.last_affected {
            parts.push(format!("<={}", normalize(last)));
        }
    }

    // Events existed but only said "introduced at 0": all versions affected.
    if parts.is_empty() {
        return Some(">=0.0.0".to_owned());
    }

    Some(parts.join(", "))
}

/// Convert a parsed OSV response into core advisories for the queried package.
fn map_response(response: OsvResponse, queried_name: &str, ecosystem: Ecosystem) -> Vec<Advisory> {
    let mut advisories = Vec::new();

    for vuln in response.vulns {
        let severity = map_severity(vuln.database_specific.and_then(|d| d.severity).as_deref());

        let mut matched = false;
        for affected in &vuln.affected {
            if affected.package.name != queried_name {
                continue;
            }
            for range in &affected.ranges {
                if let Some(req) = build_version_req(&range.events) {
                    advisories.push(Advisory {
                        id: vuln.id.clone(),
                        ecosystem,
                        package: queried_name.to_owned(),
                        vulnerable_range: req,
                        severity,
                        summary: vuln.summary.clone(),
                    });
                    matched = true;
                }
            }
        }

        // The query was already version-constrained by OSV, so if we couldn't
        // reconstruct a precise range, record a catch-all rather than dropping
        // a real advisory.
        if !matched {
            advisories.push(Advisory {
                id: vuln.id,
                ecosystem,
                package: queried_name.to_owned(),
                vulnerable_range: ">=0.0.0".to_owned(),
                severity,
                summary: vuln.summary,
            });
        }
    }

    advisories
}

// --- OSV wire types -------------------------------------------------------
// Only the fields we consume are modeled; unknown fields are ignored by serde.

#[derive(Debug, Serialize)]
struct OsvQuery<'a> {
    version: &'a str,
    package: OsvQueryPackage<'a>,
}

#[derive(Debug, Serialize)]
struct OsvQueryPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Debug, Default, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    database_specific: Option<OsvDbSpecific>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    name: String,
    #[allow(dead_code)]
    #[serde(default)]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct OsvDbSpecific {
    severity: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_ecosystems() {
        assert_eq!(osv_ecosystem(Ecosystem::Cargo), "crates.io");
        assert_eq!(osv_ecosystem(Ecosystem::PyPI), "PyPI");
    }

    #[test]
    fn maps_severity_labels() {
        assert_eq!(map_severity(Some("critical")), Severity::Critical);
        assert_eq!(map_severity(Some("MODERATE")), Severity::Medium);
        assert_eq!(map_severity(None), Severity::Medium);
    }

    #[test]
    fn builds_bounded_range() {
        let events = vec![
            OsvEvent {
                introduced: Some("1.0.0".into()),
                ..Default::default()
            },
            OsvEvent {
                fixed: Some("1.2.0".into()),
                ..Default::default()
            },
        ];
        assert_eq!(
            build_version_req(&events).as_deref(),
            Some(">=1.0.0, <1.2.0")
        );
    }

    #[test]
    fn introduced_zero_means_all_versions() {
        let events = vec![OsvEvent {
            introduced: Some("0".into()),
            ..Default::default()
        }];
        assert_eq!(build_version_req(&events).as_deref(), Some(">=0.0.0"));
    }

    #[test]
    fn empty_events_yields_none() {
        assert_eq!(build_version_req(&[]), None);
    }

    #[test]
    fn maps_full_response_from_json() {
        let json = r#"{
            "vulns": [{
                "id": "GHSA-test-0001",
                "summary": "Example flaw",
                "affected": [{
                    "package": { "name": "badcrate", "ecosystem": "crates.io" },
                    "ranges": [{
                        "type": "SEMVER",
                        "events": [{ "introduced": "1.0.0" }, { "fixed": "1.2.0" }]
                    }]
                }],
                "database_specific": { "severity": "HIGH" }
            }]
        }"#;

        let parsed: OsvResponse = serde_json::from_str(json).unwrap();
        let advisories = map_response(parsed, "badcrate", Ecosystem::Cargo);

        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "GHSA-test-0001");
        assert_eq!(advisories[0].vulnerable_range, ">=1.0.0, <1.2.0");
        assert_eq!(advisories[0].severity, Severity::High);
    }
}
