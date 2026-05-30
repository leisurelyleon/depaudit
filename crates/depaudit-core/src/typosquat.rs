//! Typosquat / dependency-confusion heuristics.
//!
//! Flags dependency names that are suspiciously close (small edit distance) to
//! well-known popular package names without matching exactly — a common
//! signature of typosquatting attacks.

use crate::model::{Dependency, Finding, FindingKind, Severity};

/// Maximum edit distance at which a name is considered a possible typosquat.
const MAX_DISTANCE: usize = 1;

/// Evaluate a dependency against a list of popular names. Returns `Some(Finding)`
/// when the name is within [`MAX_DISTANCE`] edits of a popular name but is not an
/// exact match.
pub fn evaluate(dep: &Dependency, popular: &[&str]) -> Option<Finding> {
    let name = dep.name.as_str();

    if popular.contains(&name) {
        return None; // Exact match: legitimate.
    }

    for &candidate in popular {
        if levenshtein(name, candidate) <= MAX_DISTANCE {
            return Some(Finding::new(
                FindingKind::Typosquat,
                Severity::Medium,
                dep.clone(),
                format!("name '{name}' closely resembles popular package '{candidate}'"),
            ));
        }
    }

    None
}

/// Levenshtein (edit) distance via the standard two-row dynamic-programming
/// approach.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();

    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr: Vec<usize> = vec![0; b.len() + 1];

    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("flaw", "lawn"), 2);
        assert_eq!(levenshtein("same", "same"), 0);
    }

    #[test]
    fn flags_one_edit_away() {
        // "requets" is one deletion away from "requests".
        let dep = Dependency::new("requets", "1.0.0", Ecosystem::PyPI, true);
        assert!(evaluate(&dep, &["requests", "numpy", "flask"]).is_some());
    }

    #[test]
    fn ignores_exact_match() {
        let dep = Dependency::new("requests", "1.0.0", Ecosystem::PyPI, true);
        assert!(evaluate(&dep, &["requests"]).is_none());
    }

    #[test]
    fn ignores_distant_names() {
        let dep = Dependency::new("totally-different", "1.0.0", Ecosystem::PyPI, true);
        assert!(evaluate(&dep, &["requests", "numpy"]).is_none());
    }
}
