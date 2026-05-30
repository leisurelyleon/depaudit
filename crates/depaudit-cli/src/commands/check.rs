//! `depaudit check` — CI mode: scan and exit non-zero on findings that meet
//! the configured severity threshold.

use anyhow::Result;

use depaudit_core::advisory::AdvisoryDb;
use depaudit_db::CacheStore;

use crate::cli::CheckArgs;
use crate::commands::{analyze, collect_dependencies};
use crate::config::Config;
use crate::output;

/// Exit code returned when findings meet or exceed the fail threshold.
const EXIT_FINDINGS: i32 = 1;

/// Execute the `check` subcommand. Returns the process exit code.
pub fn run(args: CheckArgs) -> Result<i32> {
    let config = Config::load_or_default(&args.config)?;
    let (deps, manifests_scanned) = collect_dependencies(&args.path, &config)?;

    let db = load_db();
    let report = analyze(deps, manifests_scanned, &db, &config);

    let rendered = output::render(&report, args.format)?;
    println!("{rendered}");

    let threshold = args.fail_on.into();
    if report.should_fail(threshold) {
        eprintln!("check failed: findings at or above {threshold} severity.");
        Ok(EXIT_FINDINGS)
    } else {
        Ok(0)
    }
}

/// Identical cache loading to `scan`, duplicated deliberately: `check` and
/// `scan` may diverge (e.g. `check` could later require a fresh cache).
fn load_db() -> AdvisoryDb {
    let store = CacheStore::default_location();
    match store.load() {
        Ok(db) => db,
        Err(_) => AdvisoryDb::default(),
    }
}
