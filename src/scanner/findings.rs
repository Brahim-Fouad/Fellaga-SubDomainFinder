use super::*;

impl Scanner {
    pub(super) fn finding_for_answer(
        &self,
        answer: &ResolvedHost,
        sources: &BTreeMap<String, BTreeSet<String>>,
        root_wildcard: &BTreeSet<String>,
        _parent_by_host: &HashMap<String, String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Option<Finding> {
        let mut answer_sources = sources.get(&answer.fqdn).cloned().unwrap_or_default();
        if answer.authoritative_validation {
            answer_sources.insert("authoritative-validation".to_owned());
        }
        let families = evidence_families(&answer_sources);
        let strong_observation = families.len() >= 2
            || answer_sources.iter().any(|source| {
                source.starts_with("axfr:")
                    || source.starts_with("tls-cert:")
                    || source.starts_with("dnssec-nsec:")
                    || source.starts_with("dns-graph:")
                    || source.starts_with("passive:ct-direct")
                    || source.starts_with("passive:crtsh")
                    || source.starts_with("passive:certspotter")
            });
        let wildcard_signature =
            Self::applicable_wildcard_signature(&answer.fqdn, root_wildcard, wildcard_by_parent);
        let wildcard_indeterminate = wildcard_signature_is_indeterminate(wildcard_signature);
        let wildcard = wildcard_signature_is_confirmed(wildcard_signature)
            && DnsEngine::matches_wildcard(answer, wildcard_signature);
        let wildcard_ambiguous = wildcard || wildcard_indeterminate;
        if wildcard && !self.options.include_wildcard {
            return None;
        }
        if wildcard_indeterminate && !self.options.include_wildcard && !strong_observation {
            return None;
        }
        let recently_verified = was_recently_verified(
            answer.last_verified_at,
            self.options.verification_max_age,
            crate::util::now_epoch(),
        );
        let state = if wildcard_ambiguous {
            crate::model::ObservationState::Unverified
        } else if !answer.from_cache || recently_verified {
            crate::model::ObservationState::Live
        } else {
            crate::model::ObservationState::Historical
        };
        let confidence = assess_confidence(
            &answer_sources,
            wildcard_ambiguous,
            state,
            !answer.from_cache,
        );
        let discovery_score = confidence.score as f64 / 100.0;
        let generation_path = answer_sources
            .iter()
            .filter(|source| {
                source.starts_with("candidate:")
                    || source.starts_with("grammar:")
                    || source.starts_with("dns-wave-")
                    || source.starts_with("metadata:")
            })
            .cloned()
            .collect::<Vec<_>>();
        Some(Finding {
            fqdn: answer.fqdn.clone(),
            records: answer.records.clone(),
            sources: answer_sources,
            wildcard: wildcard_ambiguous,
            from_cache: answer.from_cache,
            confidence,
            state,
            last_verified_at: (!wildcard_ambiguous)
                .then_some(answer.last_verified_at)
                .flatten(),
            evidence_families: families,
            authoritative_validation: answer.authoritative_validation,
            wildcard_verdict: if wildcard_ambiguous {
                WildcardVerdict::Ambiguous
            } else {
                WildcardVerdict::ExactOwner
            },
            owner_proofs: if answer.authoritative_validation {
                BTreeSet::from([OwnerProof::AuthoritativeDistinct])
            } else if !wildcard_ambiguous {
                BTreeSet::from([OwnerProof::ControlDistribution])
            } else {
                BTreeSet::new()
            },
            generation_path,
            discovery_score: Some(discovery_score),
        })
    }

    pub(super) fn finding_for_unresolved_seed(
        &self,
        fqdn: String,
        sources: BTreeSet<String>,
        fallback_state: crate::model::ObservationState,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Finding {
        let families = evidence_families(&sources);
        let authoritative = families.contains(&crate::model::EvidenceFamily::Authoritative);
        let signature =
            Self::applicable_wildcard_signature(&fqdn, root_wildcard, wildcard_by_parent);
        let wildcard_ambiguous = !authoritative
            && (wildcard_signature_is_confirmed(signature)
                || wildcard_signature_is_indeterminate(signature));
        let state = if authoritative {
            crate::model::ObservationState::Live
        } else {
            fallback_state
        };
        let from_cache = sources
            .iter()
            .all(|source| source.contains(":cache") || source.contains(":stale"));
        let confidence = assess_confidence(
            &sources,
            wildcard_ambiguous,
            state,
            authoritative && !from_cache,
        );
        let discovery_score = confidence.score as f64 / 100.0;
        Finding {
            fqdn,
            records: Vec::new(),
            sources,
            wildcard: wildcard_ambiguous,
            from_cache,
            confidence,
            state,
            last_verified_at: None,
            evidence_families: families,
            authoritative_validation: authoritative,
            wildcard_verdict: if wildcard_ambiguous {
                WildcardVerdict::Ambiguous
            } else if authoritative {
                WildcardVerdict::ExactOwner
            } else {
                WildcardVerdict::NotProfiled
            },
            owner_proofs: authoritative
                .then_some(OwnerProof::AuthoritativeDistinct)
                .into_iter()
                .collect(),
            generation_path: Vec::new(),
            discovery_score: Some(discovery_score),
        }
    }

    pub(super) fn unverified_seed_audit_finding(
        fqdn: String,
        sources: BTreeSet<String>,
        generation_path: &str,
    ) -> Finding {
        let evidence_families = evidence_families(&sources);
        let state = crate::model::ObservationState::Unverified;
        let confidence = assess_confidence(&sources, false, state, false);
        Finding {
            fqdn,
            records: Vec::new(),
            from_cache: sources
                .iter()
                .all(|source| source.contains(":cache") || source.contains(":stale")),
            sources,
            wildcard: false,
            discovery_score: Some(f64::from(confidence.score) / 100.0),
            confidence,
            state,
            last_verified_at: None,
            evidence_families,
            authoritative_validation: false,
            wildcard_verdict: WildcardVerdict::NotProfiled,
            owner_proofs: BTreeSet::new(),
            generation_path: vec![generation_path.to_owned()],
        }
    }

    pub(super) fn append_persistent_inventory(
        &self,
        domain: &str,
        findings: &mut Vec<Finding>,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<usize> {
        let mut known = findings
            .iter()
            .map(|finding| finding.fqdn.clone())
            .collect::<BTreeSet<_>>();
        let before = findings.len();
        let mut cursor = None::<String>;
        loop {
            let inventory =
                self.database
                    .current_inventory_page(domain, false, cursor.as_deref(), 4_096)?;
            if inventory.is_empty() {
                break;
            }
            cursor = inventory.last().map(|entry| entry.fqdn.clone());
            let missing_names = inventory
                .iter()
                .filter(|entry| !known.contains(&entry.fqdn))
                .map(|entry| entry.fqdn.clone())
                .collect::<Vec<_>>();
            let cached = self.database.fresh_cache(&missing_names)?;
            for entry in inventory {
                if !known.insert(entry.fqdn.clone()) {
                    continue;
                }
                let answer = cached.get(&entry.fqdn).and_then(|cached| match cached {
                    CachedAnswer::Positive(answer) => Some(answer),
                    CachedAnswer::Negative => None,
                });
                let signature = Self::applicable_wildcard_signature(
                    &entry.fqdn,
                    root_wildcard,
                    wildcard_by_parent,
                );
                let wildcard_indeterminate = wildcard_signature_is_indeterminate(signature);
                let confirmed_wildcard_match = wildcard_signature_is_confirmed(signature)
                    && answer.is_some_and(|answer| DnsEngine::matches_wildcard(answer, signature));
                let wildcard = wildcard_indeterminate || confirmed_wildcard_match;
                if confirmed_wildcard_match && !self.options.include_wildcard {
                    continue;
                }
                let state = if wildcard {
                    crate::model::ObservationState::Unverified
                } else {
                    entry.state
                };
                let families = evidence_families(&entry.sources);
                let confidence = assess_confidence(&entry.sources, wildcard, state, false);
                let discovery_score = confidence.score as f64 / 100.0;
                findings.push(Finding {
                    fqdn: entry.fqdn,
                    records: answer
                        .map(|answer| answer.records.clone())
                        .unwrap_or_default(),
                    sources: entry.sources,
                    wildcard,
                    from_cache: true,
                    confidence,
                    state,
                    last_verified_at: (!wildcard).then_some(entry.last_verified_at).flatten(),
                    evidence_families: families,
                    authoritative_validation: answer
                        .is_some_and(|answer| answer.authoritative_validation),
                    wildcard_verdict: if wildcard {
                        WildcardVerdict::Ambiguous
                    } else {
                        WildcardVerdict::NotProfiled
                    },
                    owner_proofs: BTreeSet::new(),
                    generation_path: vec!["persistent_inventory".to_owned()],
                    discovery_score: Some(discovery_score),
                });
            }
        }
        findings.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
        Ok(findings.len().saturating_sub(before))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn finalize_no_target_contact_scan(
        &self,
        scan_id: i64,
        domain: &str,
        started: Instant,
        sources: BTreeMap<String, BTreeSet<String>>,
        ct_monitor: CtMonitorResult,
        pipeline_metrics: PipelineMetrics,
        mut phase_timings: Vec<PhaseTiming>,
        mut warnings: Vec<String>,
    ) -> Result<ScanResult> {
        let resolver_metrics = merge_resolver_metrics(
            self.dns.take_metrics(),
            self.trusted_dns
                .as_ref()
                .map(DnsEngine::take_metrics)
                .unwrap_or_default(),
        );
        let dns_queries = resolver_metrics
            .iter()
            .map(|metric| metric.requests)
            .sum::<u64>();
        if dns_queries != 0 {
            bail!(
                "no-target-contact invariant violated: {dns_queries} DNS request(s) were emitted"
            );
        }

        let finalization_started = Instant::now();
        let candidate_count = sources.len();
        let mut findings = sources
            .iter()
            .map(|(fqdn, origins)| {
                Self::unverified_seed_audit_finding(
                    fqdn.clone(),
                    origins.clone(),
                    "passive_provider_only",
                )
            })
            .collect::<Vec<_>>();
        findings.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));

        let warning =
            "no-target-contact: passive-provider names were retained without DNS validation"
                .to_owned();
        self.emit(ProgressEvent::Warning(warning.clone()));
        warnings.push(warning);
        self.database.store_scan_observations(domain, &sources)?;
        self.database
            .persist_unverified_findings_preserving_state(scan_id, domain, &findings)?;
        let current_names = self.database.current_seed_output_names(
            domain,
            &findings
                .iter()
                .map(|finding| finding.fqdn.clone())
                .collect::<Vec<_>>(),
        )?;
        findings.retain(|finding| current_names.contains(&finding.fqdn));
        if self.options.only_live {
            findings.clear();
        }
        self.database.persist_scan_snapshot(scan_id, &findings)?;
        self.database.store_resolver_metrics(&resolver_metrics)?;
        self.database
            .store_pipeline_metrics(scan_id, &pipeline_metrics)?;
        self.database.finalize_scan_with_learning(
            scan_id,
            domain,
            &HashMap::new(),
            &HashMap::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            candidate_count,
            findings.len(),
            0,
            started.elapsed().as_millis(),
            &warnings,
        )?;
        phase_timings.push(PhaseTiming {
            phase: "finalization".to_owned(),
            duration_ms: finalization_started.elapsed().as_millis(),
        });

        Ok(ScanResult {
            scan_id,
            domain: domain.to_owned(),
            status: "completed".to_owned(),
            resumable: false,
            candidates: candidate_count,
            resolved_from_network: 0,
            cache_hits: 0,
            duration_ms: started.elapsed().as_millis(),
            phase_timings,
            wildcard_detected: false,
            findings,
            axfr_attempts: Vec::new(),
            tls_certificates: Vec::new(),
            dns_edges: Vec::new(),
            child_zones: BTreeSet::new(),
            service_endpoints: Vec::new(),
            web_observations: Vec::new(),
            dnssec_walks: Vec::new(),
            ct_monitor,
            pipeline: pipeline_metrics,
            resolver_metrics,
            scheduler_metrics: SchedulerMetrics {
                stop_reason: Some(StopReason::QueueDrained),
                ..SchedulerMetrics::default()
            },
            warnings,
        })
    }
}
