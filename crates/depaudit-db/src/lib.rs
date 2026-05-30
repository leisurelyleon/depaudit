//! Advisory database fetching and local caching for `depaudit`.
//!
//! This crate owns all I/O for advisories:
//! - [`fetch`] pulls advisories from the OSV API (network).
//! - [`cache`] persists and loads the advisory database locally (filesystem),
//!   enabling fully offline, air-gapped scans.
//!
//! The pure analysis logic lives in `depaudit-core`; this crate only moves data
//! in and out of it.

pub mod cache;
pub mod fetch;

pub use cache::CacheStore;
pub use fetch::OsvClient;

/// Crate-wide error type covering filesystem, network, and serialization paths.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("core error: {0}")]
    Core(#[from] depaudit_core::CoreError),
}

/// Convenience result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, DbError>;
