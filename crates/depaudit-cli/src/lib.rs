//! Library surface of the depaudit CLI, exposed so integration tests and
//! external callers can reuse the scan pipeline without the binary.

pub mod cli;
pub mod commands;
pub mod config;
pub mod output;

pub use commands::{analyze, collect_dependencies};
pub use config::Config;
