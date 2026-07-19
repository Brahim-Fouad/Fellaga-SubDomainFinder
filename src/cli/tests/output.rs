use fellaga_core::model::{AxfrAttempt, AxfrStatus, Finding, ObservationState};
use fellaga_core::output::FindingSelection;
use fellaga_core::scanner::ProgressEvent;
use std::collections::BTreeSet;

use crate::cli::output::{
    StreamJsonlMode, finding_selected_for_output, raw_name_list, raw_output_diagnostic_event,
    scan_progress_enabled, stream_jsonl_mode,
};

#[test]
fn stream_jsonl_always_waits_for_final_classification() {
    assert_eq!(stream_jsonl_mode(false, false), StreamJsonlMode::Disabled);
    assert_eq!(stream_jsonl_mode(false, true), StreamJsonlMode::Disabled);
    assert_eq!(stream_jsonl_mode(true, false), StreamJsonlMode::FinalOnly);
    assert_eq!(stream_jsonl_mode(true, true), StreamJsonlMode::FinalOnly);
}

#[test]
fn show_keeps_stderr_diagnostics_and_quiet_disables_them() {
    assert!(scan_progress_enabled(false, false, false));
    assert!(scan_progress_enabled(false, true, false));
    assert!(!scan_progress_enabled(true, false, false));
    assert!(!scan_progress_enabled(true, false, true));
    assert!(raw_output_diagnostic_event(&ProgressEvent::Phase {
        name: "passive".to_owned(),
        detail: "one source".to_owned(),
    }));
    assert!(!raw_output_diagnostic_event(&ProgressEvent::Finding(
        Finding::default()
    )));
    assert!(raw_output_diagnostic_event(&ProgressEvent::AxfrAttempt(
        AxfrAttempt {
            nameserver: String::new(),
            address: String::new(),
            status: AxfrStatus::Empty,
            error: None,
            records: Vec::new(),
            names: BTreeSet::new(),
        }
    )));
}

#[test]
fn raw_name_output_is_sorted_deduplicated_and_empty_safe() {
    assert_eq!(
        raw_name_list(["www.example.com", "api.example.com", "www.example.com"]),
        "api.example.com\nwww.example.com"
    );
    assert_eq!(raw_name_list(std::iter::empty()), "");
}

#[test]
fn every_output_defaults_to_final_live_non_wildcard_findings() {
    let finding = |state, wildcard| Finding {
        state,
        wildcard,
        ..Finding::default()
    };
    let live = finding(ObservationState::Live, false);
    let historical = finding(ObservationState::Historical, false);
    let wildcard = finding(ObservationState::Unverified, true);

    assert!(finding_selected_for_output(&live, false, false));
    assert!(!finding_selected_for_output(&historical, false, false));
    assert!(!finding_selected_for_output(&wildcard, false, false));
    assert!(finding_selected_for_output(&historical, true, false));
    assert!(!finding_selected_for_output(&wildcard, true, false));
    assert!(finding_selected_for_output(&wildcard, false, true));
}

#[test]
fn strict_live_selection_rejects_stale_unverified_and_wildcard_findings() {
    let selected = |state, wildcard| {
        FindingSelection::CURRENT.includes(&Finding {
            state,
            wildcard,
            ..Finding::default()
        })
    };
    assert!(selected(ObservationState::Live, false));
    assert!(!selected(ObservationState::Historical, false));
    assert!(!selected(ObservationState::Unverified, false));
    assert!(!selected(ObservationState::Unverified, true));
    assert!(!selected(ObservationState::Live, true));
}
