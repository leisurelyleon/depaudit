//! Core logic for `depaudit`.
//!
//! This crate is intentionally I/O-free: it parses already-loaded manifest
//! text, matches dependencies against an advisory set, classifies licenses,
//! detects typosquat risk, and aggregates findings. All filesystem and network
//! access lives in `depaudit-db` and `depaudit-cli`. Keeping this crate pure
//! makes the entire analysis path trivially unit-testable.

pub mod advisory;
pub mod license;
pub mod manifest;
pub mod model;
pub mod report;
pub mod typosquat;

pub use model::{Dependency, Ecosystem, Finding, Severity};
pub use report::Report;

/// Crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("failed to parse {ecosystem} manifest: {reason}")]
    Parse {
        ecosystem: Ecosystem,
        reason: String,
    },

    #[error("invalid version specifier '{spec}': {reason}")]
    Version { spec: String, reason: String },

    #[error("advisory database error: {0}")]
    Advisory(String),
}

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, CoreError>;
