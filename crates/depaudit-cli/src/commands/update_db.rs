//! `depaudit update-db` — refresh the local advisory cache from OSV.

use anyhow::Result;

use depaudit_core::advisory::{Advisory, AdvisoryDb};
use depaudit_db::{CacheStore, OsvClient};

use crate::cli::UpdateDbArgs;
use crate::commands::collect_dependencies;
use crate::config::Config;

/// Execute the `update-db` subcommand. Returns the process exit code.
pub async fn run(args: UpdateDbArgs) -> Result<i32> {
    let config = Config::load_or_default(&args.config)?;
    let (deps, _) = collect_dependencies(&args.path, &config)?;

    let client = OsvClient::new();
    let mut advisories: Vec<Advisory> = Vec::new();

    println!("Querying OSV for {} dependency(ies)...", deps.len());
    for dep in &deps {
        match client.query(&dep.name, dep.ecosystem, &dep.version).await {
            Ok(found) => advisories.extend(found),
            Err(e) => eprintln!("warning: OSV query failed for {}: {e}", dep.name),
        }
    }

    let db = AdvisoryDb::from_advisories(advisories);
    let store = CacheStore::default_location();
    store.store(&db)?;

    println!(
        "Cached {} advisory(ies) to {}.",
        db.len(),
        store.cache_path().display()
    );
    Ok(0)
}
