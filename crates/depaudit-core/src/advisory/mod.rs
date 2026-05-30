//! Security advisories and the database that holds them.

pub mod db;
pub mod matcher;

pub use db::AdvisoryDb;
pub use matcher::match_dependency;

use serde::{Deserialize, Serialize};

use crate::model::{Ecosystem, Severity};

/// A single security advisory describing a vulnerable range of a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    /// Stable identifier, e.g. `RUSTSEC-2024-0001` or `GHSA-xxxx-xxxx-xxxx`.
    pub id: String,
    pub ecosystem: Ecosystem,
    /// The affected package name.
    pub package: String,
    /// A semver requirement describing the vulnerable versions,
    /// e.g. `">=1.0.0, <1.2.3"`.
    pub vulnerable_range: String,
    pub severity: Severity,
    /// Short human-readable description.
    pub summary: String,
}
