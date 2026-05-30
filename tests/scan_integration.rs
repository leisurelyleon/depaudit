//! End-to-end integration tests that exercise the library pipeline against
//! on-disk fixture projects. These complement the per-crate unit tests by
//! verifying the discovery + parse path over real files.

use std::path::PathBuf;

use depaudit_core::advisory::AdvisoryDb;

// The integration test reuses the CLI crate's pipeline as a library. To make
// that possible, the CLI crate exposes a thin `lib.rs` (see note below).
use depaudit_cli::{analyze, collect_dependencies, Config};

/// Resolve a path under `tests/fixtures/`.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn scans_npm_fixture_and_finds_dependencies() {
    let config = Config::default();
    let (deps, manifests) = collect_dependencies(&fixture("vulnerable-npm"), &config).unwrap();

    assert_eq!(manifests, 1);
    assert!(deps.iter().any(|d| d.name == "lodash"));
    assert!(deps.iter().any(|d| d.name == "left-pad"));
}

#[test]
fn scans_mixed_ecosystem_fixture() {
    let config = Config::default();
    let (deps, manifests) = collect_dependencies(&fixture("mixed-ecosystem"), &config).unwrap();

    // requirements.txt + go.mod = 2 manifests.
    assert_eq!(manifests, 2);
    assert!(deps.iter().any(|d| d.name == "django"));
    assert!(deps.iter().any(|d| d.name == "github.com/spf13/cobra"));
}

#[test]
fn clean_fixture_produces_no_findings_with_empty_db() {
    let config = Config::default();
    let (deps, manifests) = collect_dependencies(&fixture("clean-cargo"), &config).unwrap();
    let report = analyze(deps, manifests, &AdvisoryDb::default(), &config);

    assert!(report.findings.is_empty());
}
