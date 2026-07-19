//! Stable output-selection policy shared by every presentation adapter.
//!
//! The scanner keeps permanent historical evidence, while user-facing output
//! normally exposes only current, non-wildcard findings. Keeping that rule in
//! one core module prevents human, JSON, JSONL, streaming, and file output from
//! drifting apart.

use crate::model::{Finding, ObservationState, ScanResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingSelection {
    include_non_live: bool,
    include_wildcard: bool,
}

impl FindingSelection {
    pub const CURRENT: Self = Self::new(false, false);

    pub const fn new(include_non_live: bool, include_wildcard: bool) -> Self {
        Self {
            include_non_live,
            include_wildcard,
        }
    }

    pub const fn includes(self, finding: &Finding) -> bool {
        if finding.wildcard {
            self.include_wildcard
        } else {
            self.include_non_live || matches!(finding.state, ObservationState::Live)
        }
    }

    pub fn project(self, result: &ScanResult) -> ScanResult {
        let mut projected = result.clone();
        projected.findings.retain(|finding| self.includes(finding));
        projected
    }
}

impl Default for FindingSelection {
    fn default() -> Self {
        Self::CURRENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(state: ObservationState, wildcard: bool) -> Finding {
        Finding {
            state,
            wildcard,
            ..Finding::default()
        }
    }

    #[test]
    fn current_selection_is_live_and_non_wildcard_only() {
        let selection = FindingSelection::CURRENT;
        assert!(selection.includes(&finding(ObservationState::Live, false)));
        assert!(!selection.includes(&finding(ObservationState::Historical, false)));
        assert!(!selection.includes(&finding(ObservationState::Unverified, false)));
        assert!(!selection.includes(&finding(ObservationState::Live, true)));
    }

    #[test]
    fn opt_ins_are_independent_and_preserve_existing_semantics() {
        let historical = finding(ObservationState::Historical, false);
        let wildcard = finding(ObservationState::Unverified, true);

        assert!(FindingSelection::new(true, false).includes(&historical));
        assert!(!FindingSelection::new(true, false).includes(&wildcard));
        assert!(!FindingSelection::new(false, true).includes(&historical));
        assert!(FindingSelection::new(false, true).includes(&wildcard));
    }
}
