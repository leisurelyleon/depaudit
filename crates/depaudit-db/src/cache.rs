//! Local, offline-first persistence of the advisory database.
//!
//! The cache is a single JSON file inside a cache directory. Once populated,
//! scans run with zero network access — the property that makes `depaudit`
//! usable in air-gapped and CI environments.

use std::fs;
use std::path::{Path, PathBuf};

use depaudit_core::advisory::AdvisoryDb;

use crate::Result;

/// The file name used for the cached advisory database.
const CACHE_FILE_NAME: &str = "advisories.json";

/// A handle to an on-disk advisory cache rooted at a directory.
#[derive(Debug, Clone)]
pub struct CacheStore {
    root: PathBuf,
}

impl CacheStore {
    /// Create a cache store rooted at `root`. The directory is created lazily
    /// on the first [`store`](Self::store) call.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve the default cache location: the `DEPAUDIT_CACHE_DIR` environment
    /// variable when set, otherwise `.depaudit-cache` in the current directory.
    pub fn default_location() -> Self {
        match std::env::var_os("DEPAUDIT_CACHE_DIR") {
            Some(dir) => Self::new(PathBuf::from(dir)),
            None => Self::new(PathBuf::from(".depaudit-cache")),
        }
    }

    /// The full path to the cache file.
    pub fn cache_path(&self) -> PathBuf {
        self.root.join(CACHE_FILE_NAME)
    }

    /// The root directory of the cache.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether a cached database currently exists on disk.
    pub fn exists(&self) -> bool {
        self.cache_path().exists()
    }

    /// Load the advisory database from disk.
    pub fn load(&self) -> Result<AdvisoryDb> {
        let json = fs::read_to_string(self.cache_path())?;
        let db = AdvisoryDb::from_json(&json)?;
        Ok(db)
    }

    /// Persist the advisory database to disk, creating the root directory if
    /// necessary.
    pub fn store(&self, db: &AdvisoryDb) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        let json = db.to_json()?;
        fs::write(self.cache_path(), json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depaudit_core::advisory::Advisory;
    use depaudit_core::model::{Ecosystem, Severity};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A unique temp directory, dependency-free (no `tempfile` crate needed).
    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("depaudit-cache-test-{nanos}"))
    }

    fn sample_db() -> AdvisoryDb {
        AdvisoryDb::from_advisories(vec![Advisory {
            id: "TEST-0001".to_owned(),
            ecosystem: Ecosystem::Cargo,
            package: "badcrate".to_owned(),
            vulnerable_range: ">=1.0.0, <1.2.0".to_owned(),
            severity: Severity::High,
            summary: "Example vulnerability".to_owned(),
        }])
    }

    #[test]
    fn store_then_load_round_trips() {
        let dir = unique_temp_dir();
        let store = CacheStore::new(&dir);

        assert!(!store.exists());
        store.store(&sample_db()).unwrap();
        assert!(store.exists());

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);

        let _ = fs::remove_dir_all(&dir); // best-effort cleanup
    }

    #[test]
    fn default_location_respects_env_override() {
        // SAFETY: single-threaded test; we set and read one env var.
        unsafe { std::env::set_var("DEPAUDIT_CACHE_DIR", "/tmp/depaudit-custom") };
        let store = CacheStore::default_location();
        assert_eq!(store.root(), Path::new("/tmp/depaudit-custom"));
        unsafe { std::env::remove_var("DEPAUDIT_CACHE_DIR") };
    }
}
