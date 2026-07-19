use clap::{CommandFactory, Parser};

use crate::cli::args::{Cli, Command, MetadataDiscoveryArg, NetworkControlArg};
use crate::cli::commands::scan::{metadata_discovery_enabled, validate_no_target_contact};
use crate::cli::profile::ScanProfile;

#[test]
fn scan_help_describes_quiet_and_finalized_streaming_exactly() {
    let command = Cli::command();
    let scan = command.find_subcommand("scan").expect("scan command");
    let help_for = |id: &str| {
        scan.get_arguments()
            .find(|argument| argument.get_id() == id)
            .and_then(|argument| argument.get_help())
            .map(ToString::to_string)
    };
    assert_eq!(
        help_for("quiet").as_deref(),
        Some("Suppress all human findings, progress, and summary output")
    );
    assert_eq!(
        help_for("stream_jsonl").as_deref(),
        Some("Write finalized finding events as JSONL after each domain completes classification")
    );
}

#[test]
fn show_parses_as_a_final_raw_output_mode_and_conflicts_with_structured_output() {
    let parsed = Cli::try_parse_from(["fellaga", "scan", "example.com", "--show"]).unwrap();
    let Command::Scan(parsed) = parsed.command else {
        panic!("scan command expected");
    };
    assert!(parsed.show);

    for structured in ["--json", "--jsonl", "--stream-jsonl"] {
        assert!(
            Cli::try_parse_from(["fellaga", "scan", "example.com", "--show", structured]).is_err(),
            "--show unexpectedly accepted {structured}"
        );
    }
}

#[test]
fn verbosity_and_explicit_non_live_output_parse_without_ambiguity() {
    let parsed = Cli::try_parse_from([
        "fellaga",
        "scan",
        "example.com",
        "-vv",
        "--include-non-live",
    ])
    .unwrap();
    let Command::Scan(parsed) = parsed.command else {
        panic!("scan command expected");
    };
    assert_eq!(parsed.verbose, 2);
    assert!(parsed.include_non_live);

    assert!(
        Cli::try_parse_from([
            "fellaga",
            "scan",
            "example.com",
            "--include-non-live",
            "--only-live",
        ])
        .is_err()
    );
    assert!(Cli::try_parse_from(["fellaga", "scan", "example.com", "-v", "--quiet"]).is_err());
}

#[test]
fn list_is_live_only_unless_all_states_are_requested() {
    let parsed = Cli::try_parse_from(["fellaga", "list", "--domain", "example.com"]).unwrap();
    let Command::List(parsed) = parsed.command else {
        panic!("list command expected");
    };
    assert!(!parsed.all);
    assert!(!parsed.only_live);
    assert!(!parsed.all || parsed.only_live);

    let parsed =
        Cli::try_parse_from(["fellaga", "list", "--domain", "example.com", "--all-states"])
            .unwrap();
    let Command::List(parsed) = parsed.command else {
        panic!("list command expected");
    };
    assert!(parsed.all);
    assert!(!parsed.only_live);
}

#[test]
fn intelligent_scan_controls_parse_with_safe_defaults_and_explicit_overrides() {
    let defaults = Cli::try_parse_from(["fellaga", "scan", "example.com"]).unwrap();
    let Command::Scan(defaults) = defaults.command else {
        panic!("scan command expected");
    };
    assert_eq!(defaults.dns.network_control, NetworkControlArg::Adaptive);
    assert_eq!(defaults.metadata_discovery, MetadataDiscoveryArg::Auto);
    assert!(metadata_discovery_enabled(
        defaults.metadata_discovery,
        false,
        defaults.no_web
    ));

    let overridden = Cli::try_parse_from([
        "fellaga",
        "scan",
        "example.com",
        "--network-control",
        "fixed",
        "--metadata-discovery",
        "all",
        "--no-web",
    ])
    .unwrap();
    let Command::Scan(overridden) = overridden.command else {
        panic!("scan command expected");
    };
    assert_eq!(overridden.dns.network_control, NetworkControlArg::Fixed);
    assert_eq!(overridden.metadata_discovery, MetadataDiscoveryArg::All);
    assert!(!metadata_discovery_enabled(
        overridden.metadata_discovery,
        false,
        overridden.no_web
    ));
    assert!(!metadata_discovery_enabled(
        MetadataDiscoveryArg::Auto,
        true,
        false
    ));
}

#[test]
fn no_target_contact_requires_the_passive_profile() {
    let parsed = Cli::try_parse_from([
        "fellaga",
        "scan",
        "example.com",
        "--profile",
        "passive",
        "--no-target-contact",
    ])
    .unwrap();
    let Command::Scan(parsed) = parsed.command else {
        panic!("scan command expected");
    };
    assert!(parsed.no_target_contact);
    assert!(validate_no_target_contact(parsed.profile, true).is_ok());
    for profile in [ScanProfile::Deep, ScanProfile::Balanced, ScanProfile::Turbo] {
        assert!(validate_no_target_contact(profile, true).is_err());
    }
    assert!(validate_no_target_contact(ScanProfile::Deep, false).is_ok());
}
