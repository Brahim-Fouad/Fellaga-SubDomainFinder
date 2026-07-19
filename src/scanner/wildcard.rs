use super::*;

impl Scanner {
    pub fn new(database: Database, dns: DnsEngine, options: ScanOptions) -> Self {
        let passive_concurrency = effective_passive_concurrency(options.passive_concurrency);
        Self {
            database,
            dns,
            trusted_dns: None,
            options: ScanPlan::new(options),
            progress: None,
            passive_request_slots: Arc::new(tokio::sync::Semaphore::new(passive_concurrency)),
        }
    }

    pub fn with_progress(mut self, progress: ProgressCallback) -> Self {
        self.progress = Some(progress);
        self
    }

    pub fn with_trusted_dns(mut self, trusted_dns: DnsEngine) -> Self {
        self.trusted_dns = Some(trusted_dns);
        self
    }

    pub(super) fn emit(&self, event: ProgressEvent) {
        if let Some(progress) = &self.progress {
            progress(event);
        }
    }

    pub(super) async fn await_with_phase_heartbeat<F, T>(
        &self,
        name: impl Into<String>,
        detail: impl Into<String>,
        future: F,
    ) -> T
    where
        F: std::future::Future<Output = T>,
    {
        const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);

        let name = name.into();
        let detail = detail.into();
        let started = Instant::now();
        tokio::pin!(future);
        loop {
            tokio::select! {
                biased;
                output = &mut future => return output,
                _ = tokio::time::sleep(HEARTBEAT_EVERY) => {
                    self.emit(ProgressEvent::Phase {
                        name: name.clone(),
                        detail: format!(
                            "{detail}; en cours depuis {:.0}s",
                            started.elapsed().as_secs_f64()
                        ),
                    });
                }
            }
        }
    }

    pub(super) fn parent_zone(host: &str, domain: &str) -> Option<String> {
        let relative = host.strip_suffix(&format!(".{domain}"))?;
        let (_, parent) = relative.split_once('.')?;
        Some(format!("{parent}.{domain}"))
    }

    pub(super) fn ancestor_zones(host: &str, domain: &str) -> Vec<String> {
        let mut zones = Vec::new();
        let mut current = host;
        while let Some((_, parent)) = current.split_once('.') {
            if parent == domain {
                break;
            }
            if !parent.ends_with(&format!(".{domain}")) {
                break;
            }
            zones.push(parent.to_owned());
            current = parent;
        }
        zones
    }

    pub(super) fn applicable_wildcard_signature<'a>(
        host: &str,
        root_wildcard: &'a BTreeSet<String>,
        wildcard_by_parent: &'a BTreeMap<String, BTreeSet<String>>,
    ) -> &'a BTreeSet<String> {
        let mut current = host;
        while let Some((_, parent)) = current.split_once('.') {
            if let Some(signature) = wildcard_by_parent.get(parent) {
                return signature;
            }
            current = parent;
        }
        root_wildcard
    }

    pub(super) fn applicable_wildcard_zone<'a>(
        host: &str,
        wildcard_by_parent: &'a BTreeMap<String, BTreeSet<String>>,
    ) -> Option<&'a str> {
        let mut current = host;
        while let Some((_, parent)) = current.split_once('.') {
            if let Some((zone, _)) = wildcard_by_parent.get_key_value(parent) {
                return Some(zone.as_str());
            }
            current = parent;
        }
        None
    }

    pub(super) fn has_reliable_wildcard_profile(
        host: &str,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
        reliable_wildcard_zones: &BTreeSet<String>,
    ) -> bool {
        Self::applicable_wildcard_zone(host, wildcard_by_parent)
            .is_some_and(|zone| reliable_wildcard_zones.contains(zone))
    }

    pub(super) fn deferred_wildcard_hosts(
        hosts: impl IntoIterator<Item = String>,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> BTreeSet<String> {
        hosts
            .into_iter()
            .filter(|host| {
                wildcard_signature_is_deferred(Self::applicable_wildcard_signature(
                    host,
                    root_wildcard,
                    wildcard_by_parent,
                ))
            })
            .collect()
    }

    pub(super) fn is_strict_enrichment_seed(
        answer: &ResolvedHost,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> bool {
        let signature =
            Self::applicable_wildcard_signature(&answer.fqdn, root_wildcard, wildcard_by_parent);
        !wildcard_signature_is_indeterminate(signature)
            && (!wildcard_signature_is_confirmed(signature)
                || !DnsEngine::matches_wildcard(answer, signature))
    }

    pub(super) fn answer_is_wildcard_ambiguous(
        answer: &ResolvedHost,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> bool {
        let signature =
            Self::applicable_wildcard_signature(&answer.fqdn, root_wildcard, wildcard_by_parent);
        wildcard_signature_is_indeterminate(signature)
            || (wildcard_signature_is_confirmed(signature)
                && DnsEngine::matches_wildcard(answer, signature))
    }

    pub(super) fn answer_matches_confirmed_wildcard_signature(
        answer: &ResolvedHost,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> bool {
        let signature =
            Self::applicable_wildcard_signature(&answer.fqdn, root_wildcard, wildcard_by_parent);
        wildcard_signature_is_confirmed(signature) && DnsEngine::matches_wildcard(answer, signature)
    }

    pub(super) fn answer_matches_confirmed_wildcard(
        answer: &ResolvedHost,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> bool {
        let signature =
            Self::applicable_wildcard_signature(&answer.fqdn, root_wildcard, wildcard_by_parent);
        wildcard_signature_is_confirmed(signature)
            && DnsEngine::exactly_matches_wildcard(answer, signature)
    }

    pub(super) fn dnssec_wildcard_suspects(
        answers: &[ResolvedHost],
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Vec<String> {
        let mut ranked = answers
            .iter()
            .filter(|answer| {
                Self::answer_is_wildcard_ambiguous(answer, root_wildcard, wildcard_by_parent)
            })
            .map(|answer| {
                (
                    u8::from(!Self::answer_matches_confirmed_wildcard(
                        answer,
                        root_wildcard,
                        wildcard_by_parent,
                    )),
                    answer.fqdn.clone(),
                )
            })
            .collect::<Vec<_>>();
        ranked.sort();
        ranked.dedup_by(|left, right| left.1 == right.1);
        ranked
            .into_iter()
            .map(|(_, fqdn)| fqdn)
            .take(DNSSEC_WILDCARD_SUSPECT_CAP)
            .collect()
    }

    pub(super) async fn quarantine_dnssec_wildcard_suspects(
        &self,
        scan_id: i64,
        domain: &str,
        suspects: Vec<String>,
        phase_deadline: Option<tokio::time::Instant>,
    ) -> Result<BTreeSet<String>> {
        if suspects.is_empty() {
            return Ok(BTreeSet::new());
        }
        let dns = self.trusted_dns.as_ref().unwrap_or(&self.dns);
        let nonexistent =
            assess_dnssec_suspects_bounded(domain, suspects, phase_deadline, |fqdn| async move {
                // TXT is intentionally orthogonal to the A/AAAA response that
                // triggered wildcard suspicion. A real owner yields secure
                // exact-owner NODATA, while a synthesized owner can expose the
                // validated denial needed to prove that QNAME nonexistent.
                dns.dnssec_denial_assessment(&fqdn, RecordType::TXT).await
            })
            .await;
        if nonexistent.is_empty() {
            return Ok(nonexistent);
        }
        let hosts = nonexistent.iter().cloned().collect::<Vec<_>>();
        self.database
            .quarantine_dnssec_nonexistent(scan_id, domain, &hosts)?;
        self.emit(ProgressEvent::Phase {
            name: "DNSSEC wildcard".to_owned(),
            detail: format!(
                "{} faux positif(s) prouvé(s) inexistant(s), cache actif purgé avec audit",
                nonexistent.len()
            ),
        });
        Ok(nonexistent)
    }

    pub(super) async fn wildcard_profile_cached(&self, zone: &str) -> WildcardProfileObservation {
        let (dns, require_positive_consensus) = self
            .trusted_dns
            .as_ref()
            .map(|dns| (dns, true))
            .unwrap_or((&self.dns, false));
        wildcard_profile_observed(
            &self.database,
            dns,
            zone,
            self.options.wildcard_refresh,
            self.options.refresh_cache,
            require_positive_consensus,
        )
        .await
    }

    pub(super) async fn wildcard_profiles_cached(
        &self,
        zones: Vec<String>,
    ) -> BTreeMap<String, WildcardProfileObservation> {
        let scanner = self;
        stream::iter(zones)
            .map(|zone| async move {
                let observation = scanner.wildcard_profile_cached(&zone).await;
                (zone, observation)
            })
            .buffer_unordered(16)
            .collect()
            .await
    }

    pub(super) async fn wildcard_profile_cached_bounded(
        &self,
        zone: &str,
        deadline: Option<tokio::time::Instant>,
    ) -> (WildcardProfileObservation, bool) {
        match deadline {
            Some(deadline) if deadline <= tokio::time::Instant::now() => (
                WildcardProfileObservation {
                    signature: Some(indeterminate_wildcard_signature()),
                    current_probe_reliable: false,
                },
                true,
            ),
            Some(deadline) => {
                match tokio::time::timeout_at(deadline, self.wildcard_profile_cached(zone)).await {
                    Ok(observation) => (observation, false),
                    Err(_) => (
                        WildcardProfileObservation {
                            signature: Some(indeterminate_wildcard_signature()),
                            current_probe_reliable: false,
                        },
                        true,
                    ),
                }
            }
            None => (self.wildcard_profile_cached(zone).await, false),
        }
    }

    pub(super) async fn wildcard_profiles_cached_bounded(
        &self,
        zones: Vec<String>,
        deadline: Option<tokio::time::Instant>,
    ) -> WildcardProfilesBatch {
        if zones.is_empty() {
            return WildcardProfilesBatch::default();
        }
        if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
            return WildcardProfilesBatch {
                signatures: zones
                    .into_iter()
                    .map(|zone| (zone, indeterminate_wildcard_signature()))
                    .collect(),
                reliable_zones: BTreeSet::new(),
                deadline_exhausted: true,
            };
        }
        let result = match deadline {
            Some(deadline) => {
                tokio::time::timeout_at(deadline, self.wildcard_profiles_cached(zones.clone()))
                    .await
                    .ok()
            }
            None => Some(self.wildcard_profiles_cached(zones.clone()).await),
        };
        match result {
            Some(observations) => {
                let mut batch = WildcardProfilesBatch::default();
                for (zone, observation) in observations {
                    if observation.current_probe_reliable {
                        batch.reliable_zones.insert(zone.clone());
                    }
                    batch.signatures.insert(
                        zone,
                        observation
                            .signature
                            .unwrap_or_else(indeterminate_wildcard_signature),
                    );
                }
                batch
            }
            None => WildcardProfilesBatch {
                signatures: zones
                    .into_iter()
                    .map(|zone| (zone, indeterminate_wildcard_signature()))
                    .collect(),
                reliable_zones: BTreeSet::new(),
                deadline_exhausted: true,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn register_wildcard_parents_bounded(
        &self,
        hosts: &[String],
        domain: &str,
        _parent_by_host: &mut HashMap<String, String>,
        wildcard_by_parent: &mut BTreeMap<String, BTreeSet<String>>,
        reliable_wildcard_zones: &mut BTreeSet<String>,
        limit: usize,
        deadline: Option<tokio::time::Instant>,
    ) -> WildcardParentRegistration {
        let mut counts = HashMap::<String, usize>::new();
        let mut deepest_parents = BTreeSet::new();
        for host in hosts {
            if let Some(parent) = Self::parent_zone(host, domain) {
                deepest_parents.insert(parent);
            }
            for ancestor in Self::ancestor_zones(host, domain) {
                let count = counts.entry(ancestor).or_default();
                *count = count.saturating_add(1);
            }
        }
        let mut parents = counts.into_iter().collect::<Vec<_>>();
        parents.sort_by_key(|(parent, count)| {
            (Reverse(*count), parent.split('.').count(), parent.clone())
        });
        let parents = parents
            .into_iter()
            .map(|(parent, _)| parent)
            .filter(|parent| {
                wildcard_by_parent
                    .get(parent)
                    .is_none_or(wildcard_signature_is_deferred)
            })
            .take(limit.max(1))
            .collect::<Vec<_>>();
        let selected = parents.iter().cloned().collect::<BTreeSet<_>>();
        let omitted_deepest =
            unprofiled_deepest_parents(deepest_parents, wildcard_by_parent, &selected);
        let profiles = self
            .wildcard_profiles_cached_bounded(parents, deadline)
            .await;
        wildcard_by_parent.extend(profiles.signatures);
        reliable_wildcard_zones.extend(profiles.reliable_zones);
        for parent in &omitted_deepest {
            wildcard_by_parent
                .entry(parent.clone())
                .or_insert_with(deferred_wildcard_signature);
        }
        WildcardParentRegistration {
            deadline_exhausted: profiles.deadline_exhausted,
            deferred_parents: omitted_deepest.len(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn register_wildcard_parents_with_budget(
        &self,
        hosts: &[String],
        domain: &str,
        parent_by_host: &mut HashMap<String, String>,
        wildcard_by_parent: &mut BTreeMap<String, BTreeSet<String>>,
        reliable_wildcard_zones: &mut BTreeSet<String>,
        limit: usize,
        remaining: &mut Option<Duration>,
    ) -> WildcardParentRegistration {
        let started = Instant::now();
        let deadline = phase_deadline(*remaining);
        // Profile one bounded parent page per enrichment wave. Any omitted
        // deepest parent is marked deferred and its hosts stay in SQLite for
        // a later resume instead of extending this phase indefinitely.
        let registration = self
            .register_wildcard_parents_bounded(
                hosts,
                domain,
                parent_by_host,
                wildcard_by_parent,
                reliable_wildcard_zones,
                limit,
                deadline,
            )
            .await;
        consume_phase_budget(remaining, started.elapsed());
        if registration.deadline_exhausted && remaining.is_some() {
            *remaining = Some(Duration::ZERO);
        }
        registration
    }
}
