//! Shared domain types used across the entire analysis pipeline.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A supported dependency ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Cargo,
    Npm,
    PyPI,
    Go,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Ecosystem::Cargo => "Cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Go => "Go",
        };
        f.write_str(s)
    }
}

/// A single resolved (or declared) dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    /// The exact version string as declared in the manifest.
    pub version: String,
    pub ecosystem: Ecosystem,
    /// True when this came from a lockfile (exact) vs. a manifest (range).
    pub is_locked: bool,
}

impl Dependency {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        ecosystem: Ecosystem,
        is_locked: bool,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            ecosystem,
            is_locked,
        }
    }
}

/// Severity ranking for a finding. Ordered so comparisons work as expected
/// (`Severity::Critical > Severity::Low`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        f.write_str(s)
    }
}

/// The category of issue a finding represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    Vulnerability,
    License,
    Typosquat,
}

/// A single issue discovered during a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub dependency: Dependency,
    /// Human-readable explanation of the issue.
    pub message: String,
    /// Optional stable identifier (e.g. advisory ID like "RUSTSEC-2024-0001").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_id: Option<String>,
}

impl Finding {
    pub fn new(
        kind: FindingKind,
        severity: Severity,
        dependency: Dependency,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            severity,
            dependency,
            message: message.into(),
            advisory_id: None,
        }
    }

    pub fn with_advisory_id(mut self, id: impl Into<String>) -> Self {
        self.advisory_id = Some(id.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_correctly() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn ecosystem_display_matches_expected() {
        assert_eq!(Ecosystem::Npm.to_string(), "npm");
        assert_eq!(Ecosystem::PyPI.to_string(), "PyPI");
    }

    #[test]
    fn finding_builder_attaches_advisory_id() {
        let dep = Dependency::new("left-pad", "1.0.0", Ecosystem::Npm, true);
        let f = Finding::new(
            FindingKind::Vulnerability,
            Severity::High,
            dep,
            "known issue",
        )
        .with_advisory_id("GHSA-xxxx");
        assert_eq!(f.advisory_id.as_deref(), Some("GHSA-xxxx"));
    }
}
