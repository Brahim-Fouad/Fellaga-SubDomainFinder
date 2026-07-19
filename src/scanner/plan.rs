use super::*;
use std::ops::Deref;

/// Internal representation of a cumulative phase limit.
///
/// Public `ScanOptions` keeps `Duration::ZERO` for Rust API compatibility, but
/// orchestration no longer carries that numeric convention through every
/// phase. A zero duration is converted once, at the application boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TimeLimit {
    Unlimited,
    Limited(Duration),
}

impl TimeLimit {
    pub(super) const fn from_duration(value: Duration) -> Self {
        if value.is_zero() {
            Self::Unlimited
        } else {
            Self::Limited(value)
        }
    }

    pub(super) const fn remaining(self) -> Option<Duration> {
        match self {
            Self::Unlimited => None,
            Self::Limited(value) => Some(value),
        }
    }

    pub(super) fn reached(self, started: Instant) -> bool {
        match self {
            Self::Unlimited => false,
            Self::Limited(value) => started.elapsed() >= value,
        }
    }

    pub(super) fn label(self) -> String {
        match self {
            Self::Unlimited => "sans limite cumulative".to_owned(),
            Self::Limited(value) => format!("limite cumulative {} s", value.as_secs()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ExecutionLimits {
    pub(super) active: TimeLimit,
    pub(super) passive: TimeLimit,
    pub(super) certificate_transparency: TimeLimit,
    pub(super) dnssec: TimeLimit,
    pub(super) web: TimeLimit,
    pub(super) internetdb: TimeLimit,
}

impl From<&ScanOptions> for ExecutionLimits {
    fn from(options: &ScanOptions) -> Self {
        Self {
            active: TimeLimit::from_duration(options.active_phase_timeout),
            passive: TimeLimit::from_duration(options.passive_phase_timeout),
            certificate_transparency: TimeLimit::from_duration(options.ct_phase_timeout),
            dnssec: TimeLimit::from_duration(options.nsec_phase_timeout),
            web: TimeLimit::from_duration(options.web_phase_timeout),
            internetdb: TimeLimit::from_duration(options.internetdb_phase_timeout),
        }
    }
}

/// Validated application plan used by the coordinator.
///
/// `ScanOptions` remains the compatibility DTO. Derived policies live beside
/// it and cannot silently disagree across phases.
#[derive(Debug, Clone)]
pub(super) struct ScanPlan {
    raw: ScanOptions,
    pub(super) limits: ExecutionLimits,
}

impl ScanPlan {
    pub(super) fn new(raw: ScanOptions) -> Self {
        let limits = ExecutionLimits::from(&raw);
        Self { raw, limits }
    }

    pub(super) const fn raw(&self) -> &ScanOptions {
        &self.raw
    }
}

impl Deref for ScanPlan {
    type Target = ScanOptions;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_converted_once_to_an_explicit_unlimited_limit() {
        assert_eq!(
            TimeLimit::from_duration(Duration::ZERO),
            TimeLimit::Unlimited
        );
        assert_eq!(TimeLimit::Unlimited.remaining(), None);
    }

    #[test]
    fn bounded_limits_keep_their_exact_duration() {
        let duration = Duration::from_secs(17);
        assert_eq!(
            TimeLimit::from_duration(duration).remaining(),
            Some(duration)
        );
    }
}
