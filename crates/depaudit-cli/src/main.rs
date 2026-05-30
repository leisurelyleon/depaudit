//! `depaudit` command-line entry point.

mod cli;
mod commands;
mod config;
mod output;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch to the selected subcommand, returning its intended exit code.
async fn run() -> Result<i32> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => commands::scan::run(args),
        Command::Check(args) => commands::check::run(args),
        Command::UpdateDb(args) => commands::update_db::run(args).await,
    }
}
