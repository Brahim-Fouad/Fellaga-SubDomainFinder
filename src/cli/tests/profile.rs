use crate::cli::profile::ScanProfile;

#[test]
fn profiles_disable_cumulative_runtime_limits_by_default() {
    for profile in [
        ScanProfile::Deep,
        ScanProfile::Balanced,
        ScanProfile::Passive,
        ScanProfile::Turbo,
    ] {
        let defaults = profile.defaults();
        assert_eq!(defaults.max_runtime, 0);
        assert_eq!(defaults.active_max_runtime, 0);
        assert_eq!(defaults.passive_max_runtime, 0);
        assert_eq!(defaults.internetdb_max_runtime, 0);
        assert_eq!(defaults.nsec_max_runtime, 0);
        assert_eq!(defaults.ct_max_runtime, 0);
        assert_eq!(defaults.web_max_runtime, 0);
        assert_eq!(defaults.pipeline_budget, 0);
        assert!(
            defaults
                .recursive_words
                .saturating_mul(defaults.recursive_hosts)
                <= 1_000_000
        );
    }
}
