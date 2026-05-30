//! License policy classification.
//!
//! License metadata is supplied by the resolver layer (`depaudit-db` /
//! `depaudit-cli`); this module decides whether a given SPDX identifier is
//! permitted under a configured policy and, if not, how severe the violation is.

use std::collections::BTreeSet;

use crate::model::{Dependency, Finding, FindingKind, Severity};

/// A license policy: explicitly allowed and explicitly denied SPDX identifiers.
#[derive(Debug, Clone)]
pub struct LicensePolicy {
    allowed: BTreeSet<String>,
    denied: BTreeSet<String>,
}

impl LicensePolicy {
    /// Build a policy from allowed and denied SPDX identifiers.
    pub fn new(
        allowed: impl IntoIterator<Item = String>,
        denied: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
            denied: denied.into_iter().collect(),
        }
    }

    /// Evaluate a dependency's declared license. Returns `Some(Finding)` on a
    /// policy violation, or `None` when the license is allowed.
    pub fn evaluate(&self, dep: &Dependency, license: &str) -> Option<Finding> {
        let license = license.trim();

        if self.denied.contains(license) {
            return Some(Finding::new(
                FindingKind::License,
                Severity::High,
                dep.clone(),
                format!("license '{license}' is explicitly denied by policy"),
            ));
        }

        // An empty allow-list means "allow anything not explicitly denied".
        if self.allowed.is_empty() || self.allowed.contains(license) {
            return None;
        }

        Some(Finding::new(
            FindingKind::License,
            Severity::Medium,
            dep.clone(),
            format!("license '{license}' is not in the allowed set"),
        ))
    }
}

impl Default for LicensePolicy {
    /// A permissive default mirroring the project's own `deny.toml`.
    fn default() -> Self {
        let allowed = [
            "MIT",
            "Apache-2.0",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "Unicode-3.0",
        ]
        .into_iter()
        .map(str::to_owned);
        Self::new(allowed, std::iter::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;

    fn dep() -> Dependency {
        Dependency::new("somelib", "1.0.0", Ecosystem::Cargo, true)
    }

    #[test]
    fn allows_listed_license() {
        assert!(LicensePolicy::default().evaluate(&dep(), "MIT").is_none());
    }

    #[test]
    fn flags_unlisted_license() {
        let finding = LicensePolicy::default()
            .evaluate(&dep(), "GPL-3.0")
            .unwrap();
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn denied_license_is_high_severity() {
        let policy = LicensePolicy::new(std::iter::empty(), ["AGPL-3.0".to_owned()]);
        let finding = policy.evaluate(&dep(), "AGPL-3.0").unwrap();
        assert_eq!(finding.severity, Severity::High);
    }
}
