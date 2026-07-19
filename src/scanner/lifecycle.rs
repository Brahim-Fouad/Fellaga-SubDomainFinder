use super::*;

/// Persists an interrupted state if the scan future is cancelled by a timeout,
/// Ctrl+C, or by a caller dropping it before `scan_inner` returns.  The
/// checkpoint intentionally remains incomplete so `--resume` can reuse it.
pub(super) struct ScanRunGuard {
    database: Database,
    scan_id: i64,
    started: Instant,
    armed: bool,
}

pub(super) struct CheckpointHeartbeat {
    stop: Option<tokio::sync::watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl CheckpointHeartbeat {
    pub(super) fn start(
        database: Database,
        scan_id: i64,
        domain: String,
        options_hash: String,
        every: Duration,
    ) -> Self {
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        // A checkpoint period comes from public library configuration as well
        // as the CLI. Clamp pathological values so interval construction can
        // never overflow Tokio's monotonic clock.
        let every = every.clamp(Duration::from_secs(1), Duration::from_secs(86_400));
        let task = tokio::spawn(async move {
            let now = tokio::time::Instant::now();
            let first_tick = now.checked_add(every).unwrap_or(now);
            let mut interval = tokio::time::interval_at(first_tick, every);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let _ = database.upsert_checkpoint(
                            scan_id,
                            &domain,
                            "running",
                            &options_hash,
                        );
                    }
                    changed = stopped.changed() => {
                        if changed.is_err() || *stopped.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub(super) async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for CheckpointHeartbeat {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl ScanRunGuard {
    pub(super) fn new(database: Database, scan_id: i64, started: Instant) -> Self {
        Self {
            database,
            scan_id,
            started,
            armed: true,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ScanRunGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.database.finish_scan(
            self.scan_id,
            "interrupted",
            0,
            0,
            0,
            self.started.elapsed().as_millis(),
            &["scan annulé; checkpoint conservé pour --resume".to_owned()],
        );
    }
}
