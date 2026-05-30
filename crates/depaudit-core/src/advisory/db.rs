//! The advisory database: an in-memory collection of known advisories.

use serde::{Deserialize, Serialize};

use crate::advisory::Advisory;
use crate::model::Ecosystem;

/// An in-memory advisory database. In production this is loaded from the cached
/// JSON maintained by `depaudit-db`; in tests it can be built directly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvisoryDb {
    advisories: Vec<Advisory>,
}

impl AdvisoryDb {
    /// Build a database from a list of advisories.
    pub fn from_advisories(advisories: Vec<Advisory>) -> Self {
        Self { advisories }
    }

    /// Parse a database from its JSON representation.
    pub fn from_json(json: &str) -> crate::Result<Self> {
        serde_json::from_str(json).map_err(|e| crate::CoreError::Advisory(e.to_string()))
    }

    /// Serialize the database to pretty JSON.
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| crate::CoreError::Advisory(e.to_string()))
    }

    /// Total number of advisories held.
    pub fn len(&self) -> usize {
        self.advisories.len()
    }

    /// Returns true when the database holds no advisories.
    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }

    /// Iterate over advisories matching a package name and ecosystem.
    pub fn advisories_for(
        &self,
        package: &str,
        ecosystem: Ecosystem,
    ) -> impl Iterator<Item = &Advisory> {
        self.advisories
            .iter()
            .filter(move |a| a.ecosystem == ecosystem && a.package == package)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn json_round_trip() {
        let db = AdvisoryDb::from_advisories(vec![Advisory {
            id: "TEST-0001".to_owned(),
            ecosystem: Ecosystem::Cargo,
            package: "badcrate".to_owned(),
            vulnerable_range: ">=1.0.0, <1.2.0".to_owned(),
            severity: Severity::High,
            summary: "Example".to_owned(),
        }]);
        let json = db.to_json().unwrap();
        let restored = AdvisoryDb::from_json(&json).unwrap();
        assert_eq!(restored.len(), 1);
    }
}
