use serde::{Deserialize, Serialize};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkControl {
    #[default]
    Adaptive,
    Fixed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkGovernorSnapshot {
    pub current_rate: u64,
    pub current_concurrency: usize,
    pub minimum_rate_seen: u64,
    pub maximum_rate_seen: u64,
    pub backoffs: usize,
    pub degraded: bool,
}

#[derive(Debug)]
struct WindowState {
    started: Instant,
    pending_requests: u64,
    pending_failures: u64,
    pending_total_ms: u64,
    aggregate_requests: u64,
    aggregate_failures: u64,
    aggregate_total_ms: u64,
    baseline_rtt_ms: f64,
    healthy_windows: u8,
    backoffs: usize,
    minimum_rate_seen: u64,
    maximum_rate_seen: u64,
    degraded: bool,
}

/// Shared AIMD-style governor. The configured values are hard ceilings; the
/// adaptive mode deliberately starts below them and learns how much pressure
/// the current connection and resolver set can sustain.
#[derive(Debug)]
pub struct NetworkGovernor {
    mode: NetworkControl,
    max_rate: u64,
    max_concurrency: usize,
    current_rate: AtomicU64,
    current_concurrency: AtomicUsize,
    window: Mutex<WindowState>,
}

impl NetworkGovernor {
    pub fn new(mode: NetworkControl, max_rate: u64, max_concurrency: usize) -> Self {
        let max_concurrency = max_concurrency.max(1);
        let initial_rate = match mode {
            NetworkControl::Fixed => max_rate,
            NetworkControl::Adaptive if max_rate == 0 => 0,
            NetworkControl::Adaptive => max_rate.clamp(1, 50),
        };
        let initial_concurrency = match mode {
            NetworkControl::Fixed => max_concurrency,
            NetworkControl::Adaptive => max_concurrency.clamp(1, 32),
        };
        Self {
            mode,
            max_rate,
            max_concurrency,
            current_rate: AtomicU64::new(initial_rate),
            current_concurrency: AtomicUsize::new(initial_concurrency),
            window: Mutex::new(WindowState {
                started: Instant::now(),
                pending_requests: 0,
                pending_failures: 0,
                pending_total_ms: 0,
                aggregate_requests: 0,
                aggregate_failures: 0,
                aggregate_total_ms: 0,
                baseline_rtt_ms: 0.0,
                healthy_windows: 0,
                backoffs: 0,
                minimum_rate_seen: initial_rate,
                maximum_rate_seen: initial_rate,
                degraded: false,
            }),
        }
    }

    pub fn current_rate(&self) -> u64 {
        self.current_rate.load(Ordering::Relaxed)
    }

    pub fn current_concurrency(&self) -> usize {
        self.current_concurrency.load(Ordering::Relaxed).max(1)
    }

    pub const fn mode(&self) -> NetworkControl {
        self.mode
    }

    /// Observe one or more completed requests. Unlike [`Self::observe_aggregate`],
    /// these values are deltas. This is the preferred path for shared
    /// governors because every producer contributes to the same pending
    /// window without maintaining conflicting cumulative baselines.
    pub(crate) fn observe_delta(&self, requests: u64, failures: u64, total_ms: u64) {
        if self.mode == NetworkControl::Fixed || requests == 0 {
            return;
        }
        let Ok(mut state) = self.window.lock() else {
            return;
        };
        state.pending_requests = state.pending_requests.saturating_add(requests);
        state.pending_failures = state.pending_failures.saturating_add(failures);
        state.pending_total_ms = state.pending_total_ms.saturating_add(total_ms);
        self.evaluate_elapsed_window(&mut state);
    }

    /// Observe cumulative counters from a single producer.
    ///
    /// This method is retained for API compatibility. Shared producers should
    /// use delta observations so one producer cannot reset or consume another
    /// producer's baseline.
    pub fn observe_aggregate(&self, requests: u64, failures: u64, total_ms: u64) {
        if self.mode == NetworkControl::Fixed {
            return;
        }
        let Ok(mut state) = self.window.lock() else {
            return;
        };
        let delta_requests = requests.saturating_sub(state.aggregate_requests);
        let delta_failures = failures.saturating_sub(state.aggregate_failures);
        let delta_ms = total_ms.saturating_sub(state.aggregate_total_ms);
        state.aggregate_requests = requests;
        state.aggregate_failures = failures;
        state.aggregate_total_ms = total_ms;
        state.pending_requests = state.pending_requests.saturating_add(delta_requests);
        state.pending_failures = state.pending_failures.saturating_add(delta_failures);
        state.pending_total_ms = state.pending_total_ms.saturating_add(delta_ms);
        self.evaluate_elapsed_window(&mut state);
    }

    fn evaluate_elapsed_window(&self, state: &mut WindowState) {
        if state.started.elapsed() < Duration::from_secs(5) {
            return;
        }
        let delta_requests = state.pending_requests;
        let delta_failures = state.pending_failures;
        let delta_ms = state.pending_total_ms;
        state.started = Instant::now();
        state.pending_requests = 0;
        state.pending_failures = 0;
        state.pending_total_ms = 0;
        if delta_requests == 0 {
            return;
        }

        let failure_rate = delta_failures as f64 / delta_requests as f64;
        let average_rtt = delta_ms as f64 / delta_requests as f64;
        if state.baseline_rtt_ms == 0.0 && average_rtt > 0.0 {
            state.baseline_rtt_ms = average_rtt;
        }
        let latency_degraded =
            state.baseline_rtt_ms > 0.0 && average_rtt > state.baseline_rtt_ms * 2.0;
        if failure_rate > 0.02 || latency_degraded {
            let current_rate = self.current_rate();
            if current_rate > 0 {
                let floor = self.max_rate.clamp(1, 10);
                let reduced = ((current_rate as f64 * 0.70).floor() as u64)
                    .max(floor)
                    .min(self.max_rate);
                self.current_rate.store(reduced, Ordering::Relaxed);
            }
            let reduced_concurrency =
                (self.current_concurrency() / 2).max(self.max_concurrency.clamp(1, 8));
            self.current_concurrency
                .store(reduced_concurrency, Ordering::Relaxed);
            state.healthy_windows = 0;
            state.backoffs = state.backoffs.saturating_add(1);
            state.degraded = true;
        } else {
            if average_rtt > 0.0 {
                state.baseline_rtt_ms = if state.baseline_rtt_ms == 0.0 {
                    average_rtt
                } else {
                    state.baseline_rtt_ms * 0.90 + average_rtt * 0.10
                };
            }
            let healthy = failure_rate < 0.005
                && (state.baseline_rtt_ms == 0.0 || average_rtt < state.baseline_rtt_ms * 1.5);
            state.healthy_windows = if healthy {
                state.healthy_windows.saturating_add(1)
            } else {
                0
            };
            if state.healthy_windows >= 3 {
                let current_rate = self.current_rate();
                if current_rate > 0 {
                    let increased = ((current_rate as f64 * 1.10).ceil() as u64)
                        .max(current_rate.saturating_add(1))
                        .min(self.max_rate);
                    self.current_rate.store(increased, Ordering::Relaxed);
                }
                self.current_concurrency.store(
                    self.current_concurrency()
                        .saturating_add(8)
                        .min(self.max_concurrency),
                    Ordering::Relaxed,
                );
                state.healthy_windows = 0;
                state.degraded = false;
            }
        }
        let rate = self.current_rate();
        state.minimum_rate_seen = state.minimum_rate_seen.min(rate);
        state.maximum_rate_seen = state.maximum_rate_seen.max(rate);
    }

    #[cfg(test)]
    pub(crate) fn elapse_window_for_test(&self) {
        self.window.lock().unwrap().started = Instant::now() - Duration::from_secs(6);
    }

    #[cfg(test)]
    pub(crate) fn evaluate_pending_for_test(&self) {
        let mut state = self.window.lock().unwrap();
        state.started = Instant::now() - Duration::from_secs(6);
        self.evaluate_elapsed_window(&mut state);
    }

    pub fn snapshot(&self) -> NetworkGovernorSnapshot {
        let Ok(state) = self.window.lock() else {
            return NetworkGovernorSnapshot {
                current_rate: self.current_rate(),
                current_concurrency: self.current_concurrency(),
                ..NetworkGovernorSnapshot::default()
            };
        };
        NetworkGovernorSnapshot {
            current_rate: self.current_rate(),
            current_concurrency: self.current_concurrency(),
            minimum_rate_seen: state.minimum_rate_seen,
            maximum_rate_seen: state.maximum_rate_seen,
            backoffs: state.backoffs,
            degraded: state.degraded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_mode_starts_below_the_hard_ceiling() {
        let governor = NetworkGovernor::new(NetworkControl::Adaptive, 250, 128);
        assert_eq!(governor.current_rate(), 50);
        assert_eq!(governor.current_concurrency(), 32);
    }

    #[test]
    fn fixed_mode_preserves_configured_values() {
        let governor = NetworkGovernor::new(NetworkControl::Fixed, 250, 128);
        assert_eq!(governor.current_rate(), 250);
        assert_eq!(governor.current_concurrency(), 128);
    }

    #[test]
    fn degraded_window_reduces_pressure() {
        let governor = NetworkGovernor::new(NetworkControl::Adaptive, 250, 128);
        governor.elapse_window_for_test();
        governor.observe_aggregate(100, 5, 10_000);
        assert!(governor.current_rate() <= 35);
        assert!(governor.current_concurrency() <= 16);
        assert_eq!(governor.snapshot().backoffs, 1);
    }

    #[test]
    fn exactly_two_percent_failures_does_not_degrade_but_more_does() {
        let governor = NetworkGovernor::new(NetworkControl::Adaptive, 250, 128);
        governor.elapse_window_for_test();
        governor.observe_aggregate(100, 2, 10_000);
        assert_eq!(governor.current_rate(), 50);
        assert_eq!(governor.snapshot().backoffs, 0);

        governor.elapse_window_for_test();
        governor.observe_aggregate(200, 5, 20_000);
        assert_eq!(governor.current_rate(), 35);
        assert_eq!(governor.snapshot().backoffs, 1);
    }

    #[test]
    fn three_healthy_windows_recover_after_a_backoff() {
        let governor = NetworkGovernor::new(NetworkControl::Adaptive, 250, 128);
        governor.elapse_window_for_test();
        governor.observe_aggregate(100, 5, 10_000);
        assert_eq!(governor.current_rate(), 35);
        assert_eq!(governor.current_concurrency(), 16);

        for window in 1..=2 {
            governor.elapse_window_for_test();
            governor.observe_aggregate(100 + window * 100, 5, 10_000 + window * 10_000);
            assert_eq!(governor.current_rate(), 35);
            assert!(governor.snapshot().degraded);
        }
        governor.elapse_window_for_test();
        governor.observe_aggregate(400, 5, 40_000);
        assert_eq!(governor.current_rate(), 39);
        assert_eq!(governor.current_concurrency(), 24);
        assert!(!governor.snapshot().degraded);
    }

    #[test]
    fn an_unlimited_rate_stays_unlimited_during_backoff_and_recovery() {
        let governor = NetworkGovernor::new(NetworkControl::Adaptive, 0, 128);
        assert_eq!(governor.current_rate(), 0);

        governor.elapse_window_for_test();
        governor.observe_aggregate(100, 100, 10_000);
        assert_eq!(governor.current_rate(), 0);
        assert_eq!(governor.snapshot().backoffs, 1);

        for window in 1..=3 {
            governor.elapse_window_for_test();
            governor.observe_aggregate(100 + window * 100, 100, 10_000 + window * 10_000);
        }
        assert_eq!(governor.current_rate(), 0);
        assert!(!governor.snapshot().degraded);
    }
}
