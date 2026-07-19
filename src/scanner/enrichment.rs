use super::*;

pub(super) async fn run<'scan>(
    state: ActiveValidationState<'scan>,
) -> Result<EnrichmentState<'scan>> {
    let ActiveValidationState {
        execution,
        mut warnings,
        pipeline_metrics,
        mut phase_timings,
        mut sources,
        mut passive_budget_remaining,
        mut nsec_budget_remaining,
        mut nsec_budget_warning_emitted,
        mut web_budget_remaining,
        mut web_budget_exhausted,
        mut passive_zones_queried,
        ct_monitor,
        axfr_attempts,
        mut active_budget_remaining,
        mut recursive_budget_exhausted,
        candidate_expansion_stopped_naturally,
        root_wildcard,
        mut wildcard_by_parent,
        mut reliable_wildcard_zones,
        mut parent_by_host,
        mut answers,
        mut pipeline,
        mut validation_rounds,
        mut pipeline_names_validated,
        mut graph_processed,
        mut web_processed,
        mut tls_processed,
        remaining_yield_upper_bound,
        mut cache_hits,
        mut network_resolved,
    } = state;
    let scanner = execution.scanner;
    let scan_id = execution.scan_id;
    let domain = execution.domain;
    let started = execution.started;
    let enrichment_started = Instant::now();
    let mut dns_edges = Vec::<DiscoveryEdge>::new();
    let mut child_zones = BTreeSet::new();
    let mut service_endpoints = Vec::<ServiceEndpoint>::new();
    if scanner.options.dns_graph {
        scanner.emit(ProgressEvent::Phase {
            name: "graphe DNS".to_owned(),
            detail: "MX/NS/SOA/TXT/CAA/SRV/HTTPS/SVCB et zones enfants".to_owned(),
        });
        let graph_input = answers
            .values()
            .filter(|answer| {
                Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
            })
            .take(scanner.options.graph_max_hosts)
            .map(|answer| answer.fqdn.clone())
            .collect::<Vec<_>>();
        graph_processed.extend(graph_input.iter().cloned());
        let mut graph = scanner
            .await_with_phase_heartbeat(
                "graphe DNS",
                "interrogation des enregistrements et délégations",
                discover_dns_graph(
                    &scanner.dns,
                    domain,
                    graph_input,
                    scanner.options.graph_max_hosts,
                    scanner.options.service_discovery,
                ),
            )
            .await;
        for answer in answers.values().filter(|answer| {
            Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
        }) {
            for record in &answer.records {
                let target = (record.record_type == "CNAME")
                    .then(|| normalize_observed_name(&record.value, domain))
                    .flatten();
                if let Some(target) = &target {
                    graph.names.insert(target.clone());
                }
                graph.edges.insert(DiscoveryEdge {
                    owner: answer.fqdn.clone(),
                    record_type: record.record_type.clone(),
                    value: record.value.clone(),
                    target,
                });
            }
        }
        scanner.database.store_discovery_graph(
            domain,
            &graph.edges,
            &graph.service_endpoints,
            &graph.child_zones,
        )?;
        scanner.emit(ProgressEvent::DnsGraph {
            queries: graph.queried,
            edges: graph.edges.len(),
            names: graph.names.len(),
            child_zones: graph.child_zones.len(),
            services: graph.service_endpoints.len(),
            duration_ms: graph.duration_ms,
        });
        for edge in &graph.edges {
            if let Some(target) = &edge.target {
                sources.entry(target.clone()).or_default().insert(format!(
                    "dns-graph:{}:{}",
                    edge.record_type.to_ascii_lowercase(),
                    edge.owner
                ));
            }
        }
        for name in &graph.names {
            pipeline.enqueue(name.clone(), 90);
        }
        let graph_hosts = if scanner.options.pipeline {
            pipeline.drain(scanner.options.pipeline_budget)
        } else {
            graph
                .names
                .iter()
                .filter(|name| !answers.contains_key(*name))
                .cloned()
                .collect::<Vec<_>>()
        };
        if !graph_hosts.is_empty() {
            validation_rounds += 1;
            pipeline_names_validated += graph_hosts.len();
        }
        let graph_resolution = scanner
            .validate_enrichment_batch_bounded(
                scan_id,
                domain,
                &graph_hosts,
                "DNS graphe",
                &started,
                &sources,
                &root_wildcard,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                &mut reliable_wildcard_zones,
                20,
                &mut active_budget_remaining,
            )
            .await?;
        cache_hits += graph_resolution.cache_hits;
        network_resolved += graph_resolution.resolved_from_network;
        for answer in graph_resolution.answers {
            answers.insert(answer.fqdn.clone(), answer);
        }
        dns_edges = graph.edges.into_iter().collect();
        child_zones = graph.child_zones;
        service_endpoints = graph.service_endpoints.into_iter().collect();
    }

    // PTR is an independent enrichment capability. Keeping it outside the
    // DNS-graph gate means --no-dns-graph no longer disables --ptr.
    if scanner.options.ptr_pivot && active_candidate_work_allowed(active_budget_remaining) {
        let addresses = prioritized_answer_addresses(
            answers.values().filter(|answer| {
                Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
            }),
            false,
            scanner.options.ptr_max_ips,
        );
        if !addresses.is_empty() {
            scanner.emit(ProgressEvent::Phase {
                name: "pivot PTR".to_owned(),
                detail: format!("{} adresse(s) confirmée(s), vague bornée", addresses.len()),
            });
            let ptr_started = Instant::now();
            let ptr_deadline = phase_deadline(active_budget_remaining);
            let (reverse_names, ptr_deadline_exhausted) = scanner
                .await_with_phase_heartbeat(
                    "pivot PTR",
                    "résolution inverse des adresses confirmées",
                    scanner.dns.reverse_names_until(addresses, ptr_deadline),
                )
                .await;
            consume_phase_budget(&mut active_budget_remaining, ptr_started.elapsed());
            if ptr_deadline_exhausted {
                if active_budget_remaining.is_some() {
                    active_budget_remaining = Some(Duration::ZERO);
                }
                let warning =
                        "PTR: limite cumulative DNS active atteinte; résultats inverses terminés conservés"
                            .to_owned();
                scanner.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
            }
            let mut ptr_names = BTreeSet::new();
            let mut ptr_edges = BTreeSet::new();
            for (address, names) in reverse_names {
                for name in names {
                    if let Some(name) = normalize_observed_name(&name, domain) {
                        ptr_names.insert(name.clone());
                        ptr_edges.insert(DiscoveryEdge {
                            owner: address.to_string(),
                            record_type: "PTR".to_owned(),
                            value: name.clone(),
                            target: Some(name),
                        });
                    }
                }
            }
            scanner.database.store_discovery_graph(
                domain,
                &ptr_edges,
                &BTreeSet::new(),
                &BTreeSet::new(),
            )?;
            for edge in &ptr_edges {
                if let Some(target) = &edge.target {
                    sources
                        .entry(target.clone())
                        .or_default()
                        .insert(format!("dns-graph:ptr:{}", edge.owner));
                }
            }
            for name in &ptr_names {
                pipeline.enqueue(name.clone(), 90);
            }
            let ptr_hosts = if scanner.options.pipeline {
                pipeline.drain(scanner.options.pipeline_budget)
            } else {
                ptr_names
                    .iter()
                    .filter(|name| !answers.contains_key(*name))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !ptr_hosts.is_empty() {
                validation_rounds += 1;
                pipeline_names_validated += ptr_hosts.len();
            }
            let ptr_resolution = scanner
                .validate_enrichment_batch_bounded(
                    scan_id,
                    domain,
                    &ptr_hosts,
                    "DNS PTR",
                    &started,
                    &sources,
                    &root_wildcard,
                    &mut parent_by_host,
                    &mut wildcard_by_parent,
                    &mut reliable_wildcard_zones,
                    20,
                    &mut active_budget_remaining,
                )
                .await?;
            cache_hits += ptr_resolution.cache_hits;
            network_resolved += ptr_resolution.resolved_from_network;
            for answer in ptr_resolution.answers {
                answers.insert(answer.fqdn.clone(), answer);
            }
            dns_edges.extend(ptr_edges);
        }
    } else if scanner.options.ptr_pivot {
        scanner.emit(ProgressEvent::Phase {
            name: "pivot PTR".to_owned(),
            detail: "ignoré: limite cumulative DNS active déjà atteinte".to_owned(),
        });
    }

    if scanner.options.internetdb_pivot {
        let addresses = prioritized_answer_addresses(
            answers.values().filter(|answer| {
                Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
            }),
            true,
            scanner.options.internetdb_max_ips,
        );
        if !addresses.is_empty() {
            let phase_limit = scanner.options.limits.internetdb.remaining();
            let phase_limit_label = phase_limit
                .map(|limit| format!("limite cumulative {}s", limit.as_secs()))
                .unwrap_or_else(|| "sans limite cumulative".to_owned());
            scanner.emit(ProgressEvent::Phase {
                name: "pivot InternetDB".to_owned(),
                detail: format!(
                    "{} IP publique(s), une seule vague, {phase_limit_label}",
                    addresses.len(),
                ),
            });
            let deadline = phase_deadline(phase_limit);
            let refresh_seconds =
                i64::try_from(scanner.options.internetdb_refresh.as_secs()).unwrap_or(i64::MAX);
            let retry_seconds =
                i64::try_from(INTERNETDB_ERROR_RETRY_AFTER.as_secs()).unwrap_or(i64::MAX);
            let mut pivot_names = BTreeSet::new();
            let mut pivot_edges = BTreeSet::new();
            let mut phase_deadline_reached = false;
            let mut provider_rate_limited = false;

            for address in addresses {
                if phase_deadline_reached || provider_rate_limited {
                    break;
                }
                if deadline
                    .as_ref()
                    .is_some_and(|deadline| tokio::time::Instant::now() >= *deadline)
                {
                    phase_deadline_reached = true;
                    break;
                }
                if pivot_names.len() >= INTERNETDB_MAX_AGGREGATE_NAMES {
                    break;
                }
                let now = now_epoch();
                let cached = scanner.database.ip_hostname_cache(
                    INTERNETDB_PROVIDER,
                    address,
                    INTERNETDB_MAX_HOSTNAMES_PER_IP,
                )?;
                let cache_decision = internetdb_cache_decision(
                    cached.as_ref(),
                    now,
                    refresh_seconds,
                    retry_seconds,
                    scanner.options.refresh_cache,
                );

                let (hostnames, qualifier) = if let InternetDbCacheDecision::Use {
                    hostnames,
                    qualifier,
                } = cache_decision
                {
                    (hostnames, qualifier)
                } else {
                    let request_timeout = deadline
                        .as_ref()
                        .map(|deadline| {
                            deadline
                                .saturating_duration_since(tokio::time::Instant::now())
                                .min(INTERNETDB_REQUEST_TIMEOUT)
                        })
                        .unwrap_or(INTERNETDB_REQUEST_TIMEOUT);
                    if request_timeout.is_zero() {
                        phase_deadline_reached = true;
                        break;
                    }
                    match tokio::time::timeout(
                        request_timeout,
                        crate::passive::lookup_internetdb(address, request_timeout),
                    )
                    .await
                    {
                        Ok(Ok(lookup)) => {
                            scanner.database.store_ip_hostname_success(
                                INTERNETDB_PROVIDER,
                                address,
                                &lookup.hostnames,
                            )?;
                            if lookup.truncated {
                                let warning = format!(
                                    "InternetDB {address}: plus de {INTERNETDB_MAX_HOSTNAMES_PER_IP} hostnames; résultat borné"
                                );
                                scanner.emit(ProgressEvent::Warning(warning.clone()));
                                warnings.push(warning);
                            }
                            (lookup.hostnames, "")
                        }
                        Ok(Err(error)) => {
                            let error = sanitize_external_error(
                                &format!("{error:#}"),
                                &scanner.options.api_keys,
                            );
                            scanner.database.store_ip_hostname_failure(
                                INTERNETDB_PROVIDER,
                                address,
                                &error,
                            )?;
                            let warning = format!("InternetDB {address}: {error}");
                            scanner.emit(ProgressEvent::Warning(warning.clone()));
                            warnings.push(warning);
                            let rate_limited = {
                                let error = error.to_ascii_lowercase();
                                error.contains("http 429")
                                    || error.contains("retry-after")
                                    || error.contains("quota")
                            };
                            if rate_limited {
                                provider_rate_limited = true;
                            }
                            let stale = cached
                                .as_ref()
                                .map(|cache| cache.hostnames.clone())
                                .unwrap_or_default();
                            if rate_limited && stale.is_empty() {
                                break;
                            }
                            (stale, ":stale")
                        }
                        Err(_) => {
                            let cumulative_deadline_reached = deadline
                                .as_ref()
                                .is_some_and(|deadline| tokio::time::Instant::now() >= *deadline);
                            phase_deadline_reached |= cumulative_deadline_reached;
                            let error = if cumulative_deadline_reached {
                                "phase deadline reached"
                            } else {
                                "request timeout"
                            };
                            scanner.database.store_ip_hostname_failure(
                                INTERNETDB_PROVIDER,
                                address,
                                error,
                            )?;
                            let stale = cached
                                .as_ref()
                                .map(|cache| cache.hostnames.clone())
                                .unwrap_or_default();
                            (stale, ":stale")
                        }
                    }
                };

                for hostname in hostnames {
                    if pivot_names.len() >= INTERNETDB_MAX_AGGREGATE_NAMES {
                        break;
                    }
                    let Some(name) = normalize_observed_name(&hostname, domain) else {
                        continue;
                    };
                    let provenance = format!("ip-pivot:{INTERNETDB_PROVIDER}:{address}{qualifier}");
                    sources.entry(name.clone()).or_default().insert(provenance);
                    pivot_names.insert(name.clone());
                    pivot_edges.insert(DiscoveryEdge {
                        owner: address.to_string(),
                        record_type: "INTERNETDB".to_owned(),
                        value: name.clone(),
                        target: Some(name),
                    });
                }
            }

            if phase_deadline_reached {
                let warning = "InternetDB: limite cumulative atteinte; résultats et cache déjà reçus conservés"
                        .to_owned();
                scanner.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
            }
            scanner.database.store_discovery_graph(
                domain,
                &pivot_edges,
                &BTreeSet::new(),
                &BTreeSet::new(),
            )?;
            for name in &pivot_names {
                pipeline.enqueue(name.clone(), 85);
            }
            let pivot_hosts = if scanner.options.pipeline {
                pipeline.drain(scanner.options.pipeline_budget)
            } else {
                pivot_names
                    .iter()
                    .filter(|name| !answers.contains_key(*name))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !pivot_hosts.is_empty() {
                validation_rounds += 1;
                pipeline_names_validated += pivot_hosts.len();
            }
            let pivot_resolution = scanner
                .validate_enrichment_batch_bounded(
                    scan_id,
                    domain,
                    &pivot_hosts,
                    "DNS InternetDB",
                    &started,
                    &sources,
                    &root_wildcard,
                    &mut parent_by_host,
                    &mut wildcard_by_parent,
                    &mut reliable_wildcard_zones,
                    20,
                    &mut active_budget_remaining,
                )
                .await?;
            cache_hits += pivot_resolution.cache_hits;
            network_resolved += pivot_resolution.resolved_from_network;
            for answer in pivot_resolution.answers {
                answers.insert(answer.fqdn.clone(), answer);
            }
            dns_edges.extend(pivot_edges);
        }
    }

    if scanner.options.passive && !child_zones.is_empty() {
        let passive_phase_started = Instant::now();
        let deadline = phase_deadline(passive_budget_remaining);
        let recursive_names = scanner
            .collect_passive_recursively(
                domain,
                child_zones.iter().cloned(),
                deadline,
                &mut passive_zones_queried,
                &mut sources,
                &mut warnings,
            )
            .await?;
        consume_phase_budget(
            &mut passive_budget_remaining,
            passive_phase_started.elapsed(),
        );
        let recursive_names = recursive_names
            .into_iter()
            .filter(|name| !answers.contains_key(name))
            .collect::<Vec<_>>();
        let recursive_resolution = scanner
            .validate_enrichment_batch_bounded(
                scan_id,
                domain,
                &recursive_names,
                "DNS passif récursif",
                &started,
                &sources,
                &root_wildcard,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                &mut reliable_wildcard_zones,
                20,
                &mut active_budget_remaining,
            )
            .await?;
        cache_hits += recursive_resolution.cache_hits;
        network_resolved += recursive_resolution.resolved_from_network;
        for answer in recursive_resolution.answers {
            answers.insert(answer.fqdn.clone(), answer);
        }
    }

    let mut dnssec_walks = Vec::<DnssecWalkResult>::new();
    if scanner.options.dnssec_nsec {
        let zones = std::iter::once(domain.to_owned())
            .chain(child_zones.iter().cloned())
            .collect::<BTreeSet<_>>();
        let phase_started = Instant::now();
        let deadline = phase_deadline(nsec_budget_remaining);
        let phase_limit = nsec_budget_remaining
            .map(|remaining| format!("limite cumulative: {} s restantes", remaining.as_secs()))
            .unwrap_or_else(|| "sans limite cumulative".to_owned());
        scanner.emit(ProgressEvent::Phase {
            name: "DNSSEC NSEC".to_owned(),
            detail: format!(
                "{} zone(s), parcours borné par le nombre de noms, cache permanent, {phase_limit}",
                zones.len()
            ),
        });
        let walks = scanner
            .await_with_phase_heartbeat(
                "DNSSEC NSEC",
                "parcours des zones",
                discover_nsec_bounded(
                    &scanner.database,
                    &scanner.dns,
                    domain,
                    zones,
                    scanner.options.nsec_timeout,
                    scanner.options.nsec_refresh,
                    scanner.options.nsec_max_names,
                    deadline,
                ),
            )
            .await;
        consume_phase_budget(&mut nsec_budget_remaining, phase_started.elapsed());
        if nsec_budget_remaining.is_some_and(|remaining| remaining.is_zero()) {
            let warning =
                "DNSSEC NSEC: limite cumulative configurée atteinte; résultats partiels conservés"
                    .to_owned();
            scanner.emit(ProgressEvent::Warning(warning.clone()));
            warnings.push(warning);
            nsec_budget_warning_emitted = true;
        }
        let nsec_names = walks
            .iter()
            .flat_map(|walk| walk.names.iter().cloned())
            .collect::<BTreeSet<_>>();
        scanner.emit(ProgressEvent::Dnssec {
            zones: walks.len(),
            walked: walks
                .iter()
                .filter(|walk| matches!(walk.status.as_str(), "walked" | "partial"))
                .count(),
            protected: walks
                .iter()
                .filter(|walk| {
                    matches!(
                        walk.status.as_str(),
                        "nsec3-protected" | "nsec-minimal-protected"
                    )
                })
                .count(),
            queries: walks.iter().map(|walk| walk.queries).sum(),
            names: nsec_names.len(),
        });
        for walk in &walks {
            for name in &walk.names {
                sources
                    .entry(name.clone())
                    .or_default()
                    .insert(format!("dnssec-nsec:{}", walk.nameserver));
            }
        }
        for name in nsec_names {
            pipeline.enqueue(name, 120);
        }
        let nsec_hosts = if scanner.options.pipeline {
            pipeline.drain(scanner.options.pipeline_budget)
        } else {
            pipeline.drain(usize::MAX)
        };
        if !nsec_hosts.is_empty() {
            validation_rounds += 1;
            pipeline_names_validated += nsec_hosts.len();
        }
        let nsec_resolution = scanner
            .validate_enrichment_batch_bounded(
                scan_id,
                domain,
                &nsec_hosts,
                "DNS NSEC",
                &started,
                &sources,
                &root_wildcard,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                &mut reliable_wildcard_zones,
                20,
                &mut active_budget_remaining,
            )
            .await?;
        cache_hits += nsec_resolution.cache_hits;
        network_resolved += nsec_resolution.resolved_from_network;
        for answer in nsec_resolution.answers {
            answers.insert(answer.fqdn.clone(), answer);
        }
        dnssec_walks = walks;
    }

    let mut web_observations = Vec::<WebObservation>::new();
    let mut measured_http_requests = 0_u64;
    let mut measured_http_bytes = 0_u64;
    let mut measured_tls_connections = 0_u64;
    if scanner.options.metadata_discovery {
        let metadata_phase_started = Instant::now();
        let metadata_budget = metadata_phase_budget(web_budget_remaining);
        let metadata_deadline = phase_deadline(metadata_budget);
        let mut metadata_hosts = vec![domain.to_owned()];
        metadata_hosts.extend(
            answers
                .values()
                .filter(|answer| {
                    Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                })
                .map(|answer| answer.fqdn.clone())
                .filter(|host| {
                    if scanner.options.metadata_all_hosts {
                        return true;
                    }
                    let relative = host
                        .strip_suffix(&format!(".{domain}"))
                        .unwrap_or(host.as_str());
                    matches!(
                        relative.split('.').next().unwrap_or_default(),
                        "api"
                            | "auth"
                            | "login"
                            | "sso"
                            | "developer"
                            | "dev"
                            | "mail"
                            | "account"
                            | "accounts"
                    )
                }),
        );
        metadata_hosts.sort();
        metadata_hosts.dedup();
        metadata_hosts.truncate(scanner.options.metadata_max_requests.div_ceil(6).max(1));
        let metadata_limit_label = metadata_budget
            .map(|limit| format!("limite cumulative partagée {}s", limit.as_secs()))
            .unwrap_or_else(|| "sans limite cumulative".to_owned());
        scanner.emit(ProgressEvent::Phase {
            name: "métadonnées standardisées".to_owned(),
            detail: format!(
                "{} hôte(s), {} requêtes HTTPS maximum, {metadata_limit_label}",
                metadata_hosts.len(),
                scanner.options.metadata_max_requests
            ),
        });
        let metadata_config = MetadataDiscoveryConfig {
            max_body_bytes: 512 * 1024,
            max_redirects: 2,
            max_requests: scanner.options.metadata_max_requests,
            request_timeout: scanner.options.web_timeout.min(Duration::from_secs(8)),
            phase_deadline: metadata_deadline,
            dns_concurrency: METADATA_DNS_CONCURRENCY,
        };
        let metadata_dns = scanner.trusted_dns.as_ref().unwrap_or(&scanner.dns);
        let metadata_result = scanner
            .await_with_phase_heartbeat(
                "métadonnées standardisées",
                "API Catalog, identité, Terraform et SSH",
                discover_metadata(metadata_dns, domain, metadata_hosts, metadata_config),
            )
            .await;
        consume_phase_budget(&mut web_budget_remaining, metadata_phase_started.elapsed());
        web_budget_exhausted |= web_budget_remaining.is_some_and(|remaining| remaining.is_zero());
        match metadata_result {
            Ok(metadata) => {
                measured_http_requests =
                    measured_http_requests.saturating_add(metadata.network_requests as u64);
                measured_http_bytes =
                    measured_http_bytes.saturating_add(metadata.bytes_transferred);
                for observation in &metadata.observations {
                    for name in &observation.names {
                        sources.entry(name.clone()).or_default().insert(format!(
                            "{}:{}",
                            observation.endpoint.source_name(),
                            observation.url
                        ));
                    }
                    web_observations.push(WebObservation {
                        url: observation.url.clone(),
                        status: observation.status,
                        names: observation.names.clone(),
                        from_cache: false,
                    });
                }
                for name in metadata.unique_names {
                    pipeline.enqueue(name, 130);
                }
                let metadata_candidates = if scanner.options.pipeline {
                    pipeline.drain(scanner.options.pipeline_budget)
                } else {
                    pipeline.drain(usize::MAX)
                };
                if !metadata_candidates.is_empty() {
                    validation_rounds += 1;
                    pipeline_names_validated += metadata_candidates.len();
                    let metadata_resolution = scanner
                        .validate_enrichment_batch_bounded(
                            scan_id,
                            domain,
                            &metadata_candidates,
                            "DNS métadonnées",
                            &started,
                            &sources,
                            &root_wildcard,
                            &mut parent_by_host,
                            &mut wildcard_by_parent,
                            &mut reliable_wildcard_zones,
                            12,
                            &mut active_budget_remaining,
                        )
                        .await?;
                    cache_hits += metadata_resolution.cache_hits;
                    network_resolved += metadata_resolution.resolved_from_network;
                    for answer in metadata_resolution.answers {
                        answers.insert(answer.fqdn.clone(), answer);
                    }
                }
                if metadata.budget_exhausted {
                    warnings.push(
                            "métadonnées standardisées: limite cumulative configurée atteinte, résultats partiels conservés"
                                .to_owned(),
                        );
                }
                if !metadata.failures.is_empty() {
                    scanner.emit(ProgressEvent::Phase {
                        name: "métadonnées standardisées".to_owned(),
                        detail: format!(
                            "{} requête(s), {} échec(s), {} nom(s)",
                            metadata.network_requests,
                            metadata.failures.len(),
                            sources
                                .values()
                                .filter(|origins| origins
                                    .iter()
                                    .any(|origin| { origin.starts_with("metadata:") }))
                                .count()
                        ),
                    });
                }
            }
            Err(error) => {
                let warning = format!("métadonnées standardisées indisponibles: {error:#}");
                scanner.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
            }
        }
    }
    if scanner.options.web_discovery {
        let mut web_hosts = answers
            .values()
            .filter(|answer| {
                Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
            })
            .map(|answer| answer.fqdn.clone())
            .collect::<Vec<_>>();
        web_hosts.push(domain.to_owned());
        web_hosts.sort_by_key(|host| {
            let relative = host
                .strip_suffix(&format!(".{domain}"))
                .unwrap_or(host.as_str());
            let first = relative.split('.').next().unwrap_or_default();
            let priority = match first {
                "www" => 0,
                "api" | "auth" | "login" | "account" | "accounts" => 1,
                "admin" | "portal" | "app" | "dashboard" => 2,
                _ if host == domain => 0,
                _ => 3,
            };
            (priority, relative.split('.').count(), host.clone())
        });
        web_hosts.dedup();
        web_hosts.truncate(scanner.options.web_max_hosts);
        web_processed.extend(web_hosts.iter().cloned());
        let web_phase_started = Instant::now();
        let web_deadline = phase_deadline(web_budget_remaining);
        let web_limit = web_budget_remaining
            .map(|remaining| format!("limite cumulative: {} s restantes", remaining.as_secs()))
            .unwrap_or_else(|| "sans limite cumulative".to_owned());
        scanner.emit(ProgressEvent::Phase {
            name: "web/JavaScript".to_owned(),
            detail: format!(
                "{} hôte(s), {} asset(s) maximum par hôte, {web_limit}",
                web_hosts.len(),
                scanner.options.web_assets_per_host
            ),
        });
        let web = scanner
            .await_with_phase_heartbeat(
                "web/JavaScript",
                "collecte des pages et assets",
                discover_web_bounded(
                    &scanner.database,
                    &scanner.dns,
                    domain,
                    web_hosts.clone(),
                    scanner.options.web_timeout,
                    scanner.options.web_refresh,
                    scanner.options.web_concurrency,
                    scanner.options.web_max_bytes,
                    scanner.options.web_assets_per_host,
                    web_deadline,
                ),
            )
            .await?;
        measured_http_requests = measured_http_requests.saturating_add(web.network_requests as u64);
        measured_http_bytes = measured_http_bytes.saturating_add(web.bytes_transferred);
        consume_phase_budget(&mut web_budget_remaining, web_phase_started.elapsed());
        web_budget_exhausted = web.budget_exhausted
            || web_budget_remaining.is_some_and(|remaining| remaining.is_zero());
        if web_budget_exhausted {
            let warning = "Web/JavaScript: limite cumulative configurée atteinte; résultats partiels conservés et travaux restants ignorés"
                    .to_owned();
            scanner.emit(ProgressEvent::Warning(warning.clone()));
            warnings.push(warning);
        }
        scanner.emit(ProgressEvent::WebDiscovery {
            hosts: web_hosts.len(),
            requests: web.network_requests,
            cache_hits: web.cache_hits,
            failures: web.failures,
            names: web.unique_names.len(),
            duration_ms: web.duration_ms,
        });
        for observation in &web.observations {
            for name in &observation.names {
                sources
                    .entry(name.clone())
                    .or_default()
                    .insert(format!("web:{}", observation.url));
            }
        }
        for name in &web.unique_names {
            pipeline.enqueue(name.clone(), 100);
        }
        let web_hosts_to_validate = if scanner.options.pipeline {
            pipeline.drain(scanner.options.pipeline_budget)
        } else {
            pipeline.drain(usize::MAX)
        };
        if !web_hosts_to_validate.is_empty() {
            validation_rounds += 1;
            pipeline_names_validated += web_hosts_to_validate.len();
        }
        let web_resolution = scanner
            .validate_enrichment_batch_bounded(
                scan_id,
                domain,
                &web_hosts_to_validate,
                "DNS web/JS",
                &started,
                &sources,
                &root_wildcard,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                &mut reliable_wildcard_zones,
                20,
                &mut active_budget_remaining,
            )
            .await?;
        cache_hits += web_resolution.cache_hits;
        network_resolved += web_resolution.resolved_from_network;
        for answer in web_resolution.answers {
            answers.insert(answer.fqdn.clone(), answer);
        }
        web_observations.extend(web.observations);
    }

    let mut tls_certificates = Vec::new();
    if scanner.options.tls_certificates {
        let endpoints = scanner.tls_endpoints(
            domain,
            &answers,
            &service_endpoints,
            &root_wildcard,
            &wildcard_by_parent,
        );
        tls_processed.extend(
            endpoints
                .iter()
                .map(|(host, port, transport)| format!("{host}:{port}:{transport}")),
        );
        let ports = endpoints
            .iter()
            .map(|(_, port, _)| *port)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(",");
        scanner.emit(ProgressEvent::Phase {
            name: "certificats TLS".to_owned(),
            detail: format!(
                "{} endpoint(s), port(s) {}, extraction SAN/CN",
                endpoints.len(),
                ports
            ),
        });
        let discovery = scanner
            .await_with_phase_heartbeat(
                "certificats TLS",
                "connexions TLS/STARTTLS et extraction SAN/CN",
                discover_tls_certificates(
                    &scanner.database,
                    &scanner.dns,
                    domain,
                    endpoints.clone(),
                    scanner.options.tls_timeout,
                    scanner.options.tls_refresh,
                    scanner.options.tls_concurrency,
                ),
            )
            .await?;
        measured_tls_connections = measured_tls_connections.saturating_add(
            discovery
                .attempted_network
                .saturating_add(discovery.differential_attempted) as u64,
        );
        scanner.emit(ProgressEvent::TlsCertificates {
            endpoints: endpoints.len(),
            network: discovery.attempted_network,
            successes: discovery.successful_network,
            failures: discovery.failed_network,
            cache_hits: discovery.cache_hits,
            names: discovery.unique_names.len(),
            duration_ms: discovery.duration_ms,
        });

        let selected_names = discovery
            .unique_names
            .iter()
            .take(scanner.options.max_passive)
            .cloned()
            .collect::<BTreeSet<_>>();
        for observation in &discovery.observations {
            for name in observation
                .names
                .iter()
                .filter(|name| selected_names.contains(*name))
            {
                sources.entry(name.clone()).or_default().insert(format!(
                    "tls-cert:{}:{}",
                    observation.endpoint, observation.port
                ));
            }
        }
        for name in selected_names {
            pipeline.enqueue(name, 110);
        }
        let tls_hosts = if scanner.options.pipeline {
            pipeline.drain(scanner.options.pipeline_budget)
        } else {
            pipeline.drain(usize::MAX)
        };
        if !tls_hosts.is_empty() {
            validation_rounds += 1;
            pipeline_names_validated += tls_hosts.len();
        }
        if !tls_hosts.is_empty() {
            scanner.emit(ProgressEvent::Phase {
                name: "DNS certificats TLS".to_owned(),
                detail: format!("{} nouveau(x) nom(s) SAN/CN à valider", tls_hosts.len()),
            });
            let tls_resolution = scanner
                .validate_enrichment_batch_bounded(
                    scan_id,
                    domain,
                    &tls_hosts,
                    "DNS certificats TLS",
                    &started,
                    &sources,
                    &root_wildcard,
                    &mut parent_by_host,
                    &mut wildcard_by_parent,
                    &mut reliable_wildcard_zones,
                    20,
                    &mut active_budget_remaining,
                )
                .await?;
            cache_hits += tls_resolution.cache_hits;
            network_resolved += tls_resolution.resolved_from_network;
            for answer in tls_resolution.answers {
                answers.insert(answer.fqdn.clone(), answer);
            }
        }
        tls_certificates = discovery.observations;
    }

    if scanner.options.pipeline {
        for round in 1..=scanner.options.pipeline_rounds {
            let graph_remaining = scanner
                .options
                .graph_max_hosts
                .saturating_sub(graph_processed.len());
            let web_remaining = if scanner.options.web_discovery && !web_budget_exhausted {
                scanner
                    .options
                    .web_max_hosts
                    .saturating_sub(web_processed.len())
            } else {
                0
            };
            let tls_remaining = scanner
                .options
                .tls_max_hosts
                .saturating_sub(tls_processed.len());
            let graph_hosts = answers
                .values()
                .filter(|answer| {
                    Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                })
                .map(|answer| &answer.fqdn)
                .filter(|host| !graph_processed.contains(*host))
                .take(graph_remaining)
                .cloned()
                .collect::<Vec<_>>();
            let web_hosts = answers
                .values()
                .filter(|answer| {
                    Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                })
                .map(|answer| &answer.fqdn)
                .filter(|host| !web_processed.contains(*host))
                .take(web_remaining)
                .cloned()
                .collect::<Vec<_>>();
            if graph_hosts.is_empty() && web_hosts.is_empty() && tls_remaining == 0 {
                break;
            }
            scanner.emit(ProgressEvent::Phase {
                name: format!("pipeline événementiel {round}"),
                detail: format!(
                    "{} hôte(s) graphe, {} hôte(s) web, capacité TLS restante {}",
                    graph_hosts.len(),
                    web_hosts.len(),
                    tls_remaining
                ),
            });

            if scanner.options.dns_graph && !graph_hosts.is_empty() {
                graph_processed.extend(graph_hosts.iter().cloned());
                let graph = scanner
                    .await_with_phase_heartbeat(
                        format!("pipeline événementiel {round}"),
                        "enrichissement du graphe DNS",
                        discover_dns_graph(
                            &scanner.dns,
                            domain,
                            graph_hosts,
                            graph_remaining,
                            false,
                        ),
                    )
                    .await;
                scanner.database.store_discovery_graph(
                    domain,
                    &graph.edges,
                    &graph.service_endpoints,
                    &graph.child_zones,
                )?;
                scanner.emit(ProgressEvent::DnsGraph {
                    queries: graph.queried,
                    edges: graph.edges.len(),
                    names: graph.names.len(),
                    child_zones: graph.child_zones.len(),
                    services: graph.service_endpoints.len(),
                    duration_ms: graph.duration_ms,
                });
                for edge in &graph.edges {
                    if let Some(target) = &edge.target {
                        sources.entry(target.clone()).or_default().insert(format!(
                            "dns-graph:{}:{}",
                            edge.record_type.to_ascii_lowercase(),
                            edge.owner
                        ));
                    }
                }
                for name in graph.names {
                    pipeline.enqueue(name, 90);
                }
                dns_edges.extend(graph.edges);
                dns_edges.sort();
                dns_edges.dedup();
                child_zones.extend(graph.child_zones);
                service_endpoints.extend(graph.service_endpoints);
                service_endpoints.sort();
                service_endpoints.dedup();
            }

            if scanner.options.web_discovery && !web_hosts.is_empty() {
                web_processed.extend(web_hosts.iter().cloned());
                let web_phase_started = Instant::now();
                let web_deadline = phase_deadline(web_budget_remaining);
                let web = scanner
                    .await_with_phase_heartbeat(
                        format!("pipeline événementiel {round}"),
                        "collecte web/JavaScript",
                        discover_web_bounded(
                            &scanner.database,
                            &scanner.dns,
                            domain,
                            web_hosts.clone(),
                            scanner.options.web_timeout,
                            scanner.options.web_refresh,
                            scanner.options.web_concurrency,
                            scanner.options.web_max_bytes,
                            scanner.options.web_assets_per_host,
                            web_deadline,
                        ),
                    )
                    .await?;
                measured_http_requests =
                    measured_http_requests.saturating_add(web.network_requests as u64);
                measured_http_bytes = measured_http_bytes.saturating_add(web.bytes_transferred);
                consume_phase_budget(&mut web_budget_remaining, web_phase_started.elapsed());
                if web.budget_exhausted
                    || web_budget_remaining.is_some_and(|remaining| remaining.is_zero())
                {
                    web_budget_exhausted = true;
                    let warning = "Web/JavaScript: limite cumulative configurée atteinte pendant le pipeline; résultats partiels conservés et travaux restants ignorés"
                            .to_owned();
                    scanner.emit(ProgressEvent::Warning(warning.clone()));
                    warnings.push(warning);
                }
                scanner.emit(ProgressEvent::WebDiscovery {
                    hosts: web_hosts.len(),
                    requests: web.network_requests,
                    cache_hits: web.cache_hits,
                    failures: web.failures,
                    names: web.unique_names.len(),
                    duration_ms: web.duration_ms,
                });
                for observation in &web.observations {
                    for name in &observation.names {
                        sources
                            .entry(name.clone())
                            .or_default()
                            .insert(format!("web:{}", observation.url));
                    }
                }
                for name in web.unique_names {
                    pipeline.enqueue(name, 100);
                }
                web_observations.extend(web.observations);
                web_observations.sort_by(|left, right| left.url.cmp(&right.url));
                web_observations.dedup_by(|left, right| left.url == right.url);
            }

            if scanner.options.tls_certificates && tls_remaining > 0 {
                let endpoints = scanner
                    .tls_endpoints(
                        domain,
                        &answers,
                        &service_endpoints,
                        &root_wildcard,
                        &wildcard_by_parent,
                    )
                    .into_iter()
                    .filter(|(host, port, transport)| {
                        !tls_processed.contains(&format!("{host}:{port}:{transport}"))
                    })
                    .take(tls_remaining)
                    .collect::<Vec<_>>();
                tls_processed.extend(
                    endpoints
                        .iter()
                        .map(|(host, port, transport)| format!("{host}:{port}:{transport}")),
                );
                if !endpoints.is_empty() {
                    let discovery = scanner
                        .await_with_phase_heartbeat(
                            format!("pipeline événementiel {round}"),
                            "collecte des certificats TLS/STARTTLS",
                            discover_tls_certificates(
                                &scanner.database,
                                &scanner.dns,
                                domain,
                                endpoints.clone(),
                                scanner.options.tls_timeout,
                                scanner.options.tls_refresh,
                                scanner.options.tls_concurrency,
                            ),
                        )
                        .await?;
                    measured_tls_connections = measured_tls_connections.saturating_add(
                        discovery
                            .attempted_network
                            .saturating_add(discovery.differential_attempted)
                            as u64,
                    );
                    scanner.emit(ProgressEvent::TlsCertificates {
                        endpoints: endpoints.len(),
                        network: discovery.attempted_network,
                        successes: discovery.successful_network,
                        failures: discovery.failed_network,
                        cache_hits: discovery.cache_hits,
                        names: discovery.unique_names.len(),
                        duration_ms: discovery.duration_ms,
                    });
                    for observation in &discovery.observations {
                        for name in &observation.names {
                            sources.entry(name.clone()).or_default().insert(format!(
                                "tls-cert:{}:{}",
                                observation.endpoint, observation.port
                            ));
                        }
                    }
                    for name in discovery.unique_names {
                        pipeline.enqueue(name, 110);
                    }
                    tls_certificates.extend(discovery.observations);
                    tls_certificates.sort_by(|left, right| {
                        (&left.endpoint, left.port).cmp(&(&right.endpoint, right.port))
                    });
                    tls_certificates.dedup_by(|left, right| {
                        left.endpoint == right.endpoint && left.port == right.port
                    });
                }
            }

            let new_hosts = pipeline.drain(scanner.options.pipeline_budget);
            if new_hosts.is_empty() {
                break;
            }
            validation_rounds += 1;
            pipeline_names_validated += new_hosts.len();
            let new_resolution = scanner
                .validate_enrichment_batch_bounded(
                    scan_id,
                    domain,
                    &new_hosts,
                    &format!("DNS pipeline {round}"),
                    &started,
                    &sources,
                    &root_wildcard,
                    &mut parent_by_host,
                    &mut wildcard_by_parent,
                    &mut reliable_wildcard_zones,
                    20,
                    &mut active_budget_remaining,
                )
                .await?;
            cache_hits += new_resolution.cache_hits;
            network_resolved += new_resolution.resolved_from_network;
            for answer in new_resolution.answers {
                answers.insert(answer.fqdn.clone(), answer);
            }
        }
    }

    if scanner.options.dnssec_nsec {
        let completed_zones = dnssec_walks
            .iter()
            .map(|walk| walk.zone.clone())
            .collect::<BTreeSet<_>>();
        let late_zones = child_zones
            .iter()
            .filter(|zone| !completed_zones.contains(*zone))
            .cloned()
            .collect::<BTreeSet<_>>();
        if !late_zones.is_empty() {
            let phase_started = Instant::now();
            let deadline = phase_deadline(nsec_budget_remaining);
            let walks = scanner
                .await_with_phase_heartbeat(
                    "DNSSEC NSEC zones filles",
                    "parcours des nouvelles zones déléguées",
                    discover_nsec_bounded(
                        &scanner.database,
                        &scanner.dns,
                        domain,
                        late_zones,
                        scanner.options.nsec_timeout,
                        scanner.options.nsec_refresh,
                        scanner.options.nsec_max_names,
                        deadline,
                    ),
                )
                .await;
            consume_phase_budget(&mut nsec_budget_remaining, phase_started.elapsed());
            if !nsec_budget_warning_emitted
                && nsec_budget_remaining.is_some_and(|remaining| remaining.is_zero())
            {
                let warning = "DNSSEC NSEC: limite cumulative configurée atteinte; résultats partiels conservés"
                        .to_owned();
                scanner.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
            }
            for walk in &walks {
                for name in &walk.names {
                    sources
                        .entry(name.clone())
                        .or_default()
                        .insert(format!("dnssec-nsec:{}", walk.nameserver));
                    pipeline.enqueue(name.clone(), 120);
                }
            }
            dnssec_walks.extend(walks);
            dnssec_walks.sort_by(|left, right| left.zone.cmp(&right.zone));
            let hosts = pipeline.drain(scanner.options.pipeline_budget);
            if !hosts.is_empty() {
                validation_rounds += 1;
                pipeline_names_validated += hosts.len();
                let late_nsec_resolution = scanner
                    .validate_enrichment_batch_bounded(
                        scan_id,
                        domain,
                        &hosts,
                        "DNS NSEC zones filles",
                        &started,
                        &sources,
                        &root_wildcard,
                        &mut parent_by_host,
                        &mut wildcard_by_parent,
                        &mut reliable_wildcard_zones,
                        20,
                        &mut active_budget_remaining,
                    )
                    .await?;
                cache_hits += late_nsec_resolution.cache_hits;
                network_resolved += late_nsec_resolution.resolved_from_network;
                for answer in late_nsec_resolution.answers {
                    answers.insert(answer.fqdn.clone(), answer);
                }
            }
        }
    }

    if !scanner.options.passive_only && scanner.options.recursive_depth > 1 {
        let mut recursive_words = scanner.recursive_wordlist()?;
        if scanner.options.adaptive {
            recursive_words.truncate(50);
        }
        let recursive_words = scanner
            .database
            .ensure_scan_recursive_words(scan_id, &recursive_words)?;
        let recursive_batch_limit = if scanner.options.adaptive {
            1_000
        } else {
            5_000
        };
        for depth in 2..=scanner.options.recursive_depth {
            let mut parents = answers
                .values()
                .filter(|answer| {
                    answer
                        .fqdn
                        .strip_suffix(&format!(".{domain}"))
                        .is_some_and(|relative| relative.split('.').count() == depth - 1)
                })
                .filter(|answer| {
                    Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                })
                .map(|answer| answer.fqdn.clone())
                .collect::<Vec<_>>();
            parents.sort();
            let parent_limit = if scanner.options.adaptive {
                scanner.options.recursive_hosts.min(20)
            } else {
                scanner.options.recursive_hosts
            };
            parents.truncate(parent_limit);
            scanner
                .database
                .persist_scan_recursive_parents(scan_id, depth, &parents)?;
            let persisted_parents = scanner.database.scan_recursive_parents(scan_id, depth)?;
            if persisted_parents.is_empty() || recursive_words.is_empty() {
                break;
            }
            if active_candidate_budget_exhausted(active_budget_remaining) {
                break;
            }
            scanner.emit(ProgressEvent::Phase {
                name: format!("récursion niveau {depth}"),
                detail: format!(
                    "{} parent(s), {} mot(s) par parent",
                    persisted_parents.len(),
                    recursive_words.len()
                ),
            });
            let recursive_profiles_started = Instant::now();
            let unprofiled_parents = persisted_parents
                .iter()
                .filter(|parent| !wildcard_by_parent.contains_key(*parent))
                .cloned()
                .collect::<Vec<_>>();
            let recursive_profiles = scanner
                .wildcard_profiles_cached_bounded(
                    unprofiled_parents,
                    phase_deadline(active_budget_remaining),
                )
                .await;
            wildcard_by_parent.extend(recursive_profiles.signatures);
            reliable_wildcard_zones.extend(recursive_profiles.reliable_zones);
            consume_phase_budget(
                &mut active_budget_remaining,
                recursive_profiles_started.elapsed(),
            );
            if recursive_profiles.deadline_exhausted && active_budget_remaining.is_some() {
                active_budget_remaining = Some(Duration::ZERO);
            }
            if active_candidate_budget_exhausted(active_budget_remaining) {
                break;
            }
            let mut depth_yield = 0_usize;
            loop {
                if active_candidate_budget_exhausted(active_budget_remaining) {
                    recursive_budget_exhausted = scanner
                        .database
                        .scan_recursive_depth_has_more(scan_id, depth)?;
                    break;
                }
                let refill_started = Instant::now();
                scanner.database.refill_scan_recursive_candidates(
                    scan_id,
                    depth,
                    recursive_batch_limit,
                )?;
                consume_phase_budget(&mut active_budget_remaining, refill_started.elapsed());
                if active_candidate_budget_exhausted(active_budget_remaining) {
                    recursive_budget_exhausted = scanner
                        .database
                        .scan_recursive_depth_has_more(scan_id, depth)?;
                    break;
                }
                let recursive_candidates = scanner.database.pending_scan_recursive_candidates(
                    scan_id,
                    depth,
                    recursive_batch_limit,
                )?;
                if recursive_candidates.is_empty() {
                    if scanner
                        .database
                        .scan_recursive_depth_has_more(scan_id, depth)?
                    {
                        continue;
                    }
                    break;
                }
                let mut recursive_hosts = Vec::with_capacity(recursive_candidates.len());
                let mut already_answered = Vec::new();
                for (fqdn, parent, _) in &recursive_candidates {
                    sources
                        .entry(fqdn.clone())
                        .or_default()
                        .insert("dns-recursive".to_owned());
                    parent_by_host.insert(fqdn.clone(), parent.clone());
                    if answers.contains_key(fqdn) {
                        already_answered.push(fqdn.clone());
                    } else {
                        recursive_hosts.push(fqdn.clone());
                    }
                }
                scanner
                    .database
                    .complete_scan_recursive_candidates(scan_id, &already_answered)?;
                if recursive_hosts.is_empty() {
                    continue;
                }

                let phase = format!("DNS niveau {depth}");
                let recursive_dns_started = Instant::now();
                let round_resolution = scanner
                    .resolve_batch_with_deadline(
                        scan_id,
                        domain,
                        &recursive_hosts,
                        &phase,
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                        &reliable_wildcard_zones,
                        phase_deadline(active_budget_remaining),
                        BatchDnsMode::Conservative,
                    )
                    .await?;
                consume_phase_budget(
                    &mut active_budget_remaining,
                    recursive_dns_started.elapsed(),
                );
                if round_resolution.deadline_exhausted && active_budget_remaining.is_some() {
                    active_budget_remaining = Some(Duration::ZERO);
                }
                let BatchResolution {
                    answers: round_answers,
                    cache_hits: round_cache_hits,
                    resolved_from_network: round_network_resolved,
                    not_started_hosts,
                    attempted_hosts,
                    ..
                } = round_resolution;
                scanner
                    .database
                    .mark_scan_recursive_candidates_started(scan_id, &attempted_hosts)?;
                let not_started = not_started_hosts.iter().cloned().collect::<BTreeSet<_>>();
                let terminal_hosts = recursive_hosts
                    .iter()
                    .filter(|host| !not_started.contains(*host))
                    .cloned()
                    .collect::<Vec<_>>();
                scanner
                    .database
                    .mark_scan_recursive_candidates_done(scan_id, &terminal_hosts)?;
                scanner
                    .database
                    .requeue_unstarted_scan_recursive_candidates(scan_id, &not_started_hosts)?;
                cache_hits += round_cache_hits;
                network_resolved += round_network_resolved;
                depth_yield = depth_yield.saturating_add(round_answers.len());
                for answer in round_answers {
                    answers.insert(answer.fqdn.clone(), answer);
                }
                if active_candidate_budget_exhausted(active_budget_remaining) {
                    recursive_budget_exhausted = scanner
                        .database
                        .scan_recursive_depth_has_more(scan_id, depth)?;
                    break;
                }
            }
            if recursive_budget_exhausted {
                break;
            }
            if scanner.options.adaptive && depth_yield < 2 {
                scanner.emit(ProgressEvent::Phase {
                    name: "adaptation".to_owned(),
                    detail: format!("récursion arrêtée au niveau {depth}: rendement {depth_yield}"),
                });
                break;
            }
        }
    }
    phase_timings.push(PhaseTiming {
        phase: "enrichment".to_owned(),
        duration_ms: enrichment_started.elapsed().as_millis(),
    });

    Ok(EnrichmentState {
        execution,
        warnings,
        pipeline_metrics,
        phase_timings,
        sources,
        ct_monitor,
        axfr_attempts,
        active_budget_remaining,
        candidate_expansion_stopped_naturally,
        root_wildcard,
        wildcard_by_parent,
        parent_by_host,
        answers,
        pipeline,
        validation_rounds,
        pipeline_names_validated,
        remaining_yield_upper_bound,
        cache_hits,
        network_resolved,
        dns_edges,
        child_zones,
        service_endpoints,
        dnssec_walks,
        web_observations,
        measured_http_requests,
        measured_http_bytes,
        measured_tls_connections,
        tls_certificates,
    })
}
