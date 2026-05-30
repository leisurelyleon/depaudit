//! Rendering a [`Report`] in the user's chosen format.

pub mod human;
pub mod json;
pub mod sarif;

use depaudit_core::Report;

use crate::cli::OutputFormat;

/// Render a report to a `String` in the requested format.
pub fn render(report: &Report, format: OutputFormat) -> anyhow::Result<String> {
    match format {
        OutputFormat::Human => Ok(human::render(report)),
        OutputFormat::Json => json::render(report),
        OutputFormat::Sarif => sarif::render(report),
    }
}
