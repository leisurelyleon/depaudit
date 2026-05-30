//! Manifest parsing across supported ecosystems.
//!
//! Each parser is pure: it takes already-loaded file text and returns the
//! declared dependencies. Filesystem discovery lives in the CLI layer.

pub mod cargo;
pub mod gomod;
pub mod npm;
pub mod pypi;

use crate::model::{Dependency, Ecosystem};
use crate::Result;

/// Identifies which manifest parser applies to a given file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    CargoToml,
    CargoLock,
    PackageJson,
    PackageLockJson,
    RequirementsTxt,
    PyprojectToml,
    GoMod,
    GoSum,
}

impl ManifestKind {
    /// Map a bare file name to its manifest kind, if recognized.
    pub fn from_file_name(name: &str) -> Option<Self> {
        match name {
            "Cargo.toml" => Some(Self::CargoToml),
            "Cargo.lock" => Some(Self::CargoLock),
            "package.json" => Some(Self::PackageJson),
            "package-lock.json" => Some(Self::PackageLockJson),
            "requirements.txt" => Some(Self::RequirementsTxt),
            "pyproject.toml" => Some(Self::PyprojectToml),
            "go.mod" => Some(Self::GoMod),
            "go.sum" => Some(Self::GoSum),
            _ => None,
        }
    }

    /// The ecosystem this manifest kind belongs to.
    pub fn ecosystem(self) -> Ecosystem {
        match self {
            Self::CargoToml | Self::CargoLock => Ecosystem::Cargo,
            Self::PackageJson | Self::PackageLockJson => Ecosystem::Npm,
            Self::RequirementsTxt | Self::PyprojectToml => Ecosystem::PyPI,
            Self::GoMod | Self::GoSum => Ecosystem::Go,
        }
    }
}

/// Parse a manifest's textual content into a list of dependencies.
pub fn parse(kind: ManifestKind, content: &str) -> Result<Vec<Dependency>> {
    match kind {
        ManifestKind::CargoToml => cargo::parse_cargo_toml(content),
        ManifestKind::CargoLock => cargo::parse_cargo_lock(content),
        ManifestKind::PackageJson => npm::parse_package_json(content),
        ManifestKind::PackageLockJson => npm::parse_package_lock(content),
        ManifestKind::RequirementsTxt => pypi::parse_requirements_txt(content),
        ManifestKind::PyprojectToml => pypi::parse_pyproject_toml(content),
        ManifestKind::GoMod => gomod::parse_go_mod(content),
        ManifestKind::GoSum => gomod::parse_go_sum(content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_known_manifests() {
        assert_eq!(ManifestKind::from_file_name("Cargo.toml"), Some(ManifestKind::CargoToml));
        assert_eq!(ManifestKind::from_file_name("go.sum"), Some(ManifestKind::GoSum));
        assert_eq!(ManifestKind::from_file_name("random.txt"), None);
    }

    #[test]
    fn maps_to_correct_ecosystem() {
        assert_eq!(ManifestKind::PackageJson.ecosystem(), Ecosystem::Npm);
        assert_eq!(ManifestKind::GoMod.ecosystem(), Ecosystem::Go);
    }
}
