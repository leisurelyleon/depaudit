//! Command-line argument definitions (clap derive).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use depaudit_core::model::Severity;

/// A fast, offline-capable polyglot dependency & supply-chain auditor.
#[derive(Debug, Parser)]
#[command(name = "depaudit", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a directory and report all findings.
    Scan(ScanArgs),
    /// Scan in CI mode: exit non-zero when findings meet the fail threshold.
    Check(CheckArgs),
    /// Refresh the local advisory database cache from OSV.
    UpdateDb(UpdateDbArgs),
}

#[derive(Debug, clap::Args)]
pub struct ScanArgs {
    /// Path to the project directory to scan.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Path to the config file.
    #[arg(long, default_value = ".depaudit.toml")]
    pub config: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct CheckArgs {
    /// Path to the project directory to scan.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Minimum severity that constitutes a CI failure.
    #[arg(long, value_enum, default_value_t = SeverityArg::High)]
    pub fail_on: SeverityArg,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Path to the config file.
    #[arg(long, default_value = ".depaudit.toml")]
    pub config: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct UpdateDbArgs {
    /// Only update advisories for packages found under this path.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Path to the config file.
    #[arg(long, default_value = ".depaudit.toml")]
    pub config: PathBuf,
}

/// Selectable output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

/// Severity as a CLI argument. Kept distinct from the core enum so clap's
/// `ValueEnum` derive lives at the boundary, not on the domain type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}
