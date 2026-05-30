//! `depaudit scan` — scan a directory and print a report.

use anyhow::Result;

use depaudit_core::advisory::AdvisoryDb;
use depaudit_db::CacheStore;

use crate::cli::ScanArgs;
use crate::commands::{analyze, collect_dependencies};
use crate::config::Config;
use crate::output;

/// Execute the `scan` subcommand. Returns the process exit code.
pub fn run(args: ScanArgs) -> Result<i32> {
    let config = Config::load_or_default(&args.config)?;
    let (deps, manifests_scanned) = collect_dependencies(&args.path, &config)?;

    let db = load_db();
    let report = analyze(deps, manifests_scanned, &db, &config);

    let rendered = output::render(&report, args.format)?;
    println!("{rendered}");

    Ok(0)
}

/// Load the cached advisory DB, or fall back to an empty DB (with a warning)
/// when no cache exists yet. `scan` never fails solely due to a missing cache.
fn load_db() -> AdvisoryDb {
    let store = CacheStore::default_location();
    if !store.exists() {
        eprintln!(
            "warning: no advisory cache found; run `depaudit update-db` for vulnerability checks."
        );
        return AdvisoryDb::default();
    }
    match store.load() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("warning: failed to load advisory cache ({e}); continuing without it.");
            AdvisoryDb::default()
        }
    }
}
