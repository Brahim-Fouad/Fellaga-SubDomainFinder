use crate::dns::{DnsEngine, DnsQueryResult};
use crate::dns_policy::{
    ExternalFeature, ExternalFeatureKind, PlanLimit, PolicyDelta, PolicyLimits, PolicyPlanner,
    PolicyQuery,
};
use crate::model::{DiscoveryEdge, ServiceEndpoint};
use crate::util::{extract_observed_names, normalize_hostname, normalize_observed_name};
use hickory_resolver::proto::rr::RecordType;
use std::collections::BTreeSet;
use std::time::Instant;

/// DNS-SD takes three network waves (browse -> service -> instance). SPF can
/// legitimately add up to six include/redirect levels. Keeping a separate
/// round limit makes the pipeline terminate even if a future planner bug were
/// to keep producing queries despite its global query budget.
const MAX_POLICY_WAVES: usize = 10;

const SERVICE_PREFIXES: &[&str] = &[
    "_autodiscover._tcp",
    "_caldavs._tcp",
    "_carddavs._tcp",
    "_git._tcp",
    "_imaps._tcp",
    "_imap._tcp",
    "_kerberos._tcp",
    "_ldap._tcp",
    "_minecraft._tcp",
    "_pop3s._tcp",
    "_pop3._tcp",
    "_sip._tcp",
    "_sip._udp",
    "_sipfederationtls._tcp",
    "_submission._tcp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
];

#[derive(Debug, Default)]
pub struct DnsGraphDiscovery {
    pub edges: BTreeSet<DiscoveryEdge>,
    pub names: BTreeSet<String>,
    pub child_zones: BTreeSet<String>,
    pub service_endpoints: BTreeSet<ServiceEndpoint>,
    /// Out-of-scope names are useful naming/provider signals, but are never
    /// promoted to DNS queries or regular in-scope candidates.
    pub external_features: BTreeSet<ExternalFeature>,
    pub policy_limits_hit: BTreeSet<PlanLimit>,
    pub policy_loops: BTreeSet<String>,
    pub queried: usize,
    pub duration_ms: u128,
}

fn query_plan(
    domain: &str,
    confirmed_hosts: Vec<String>,
    max_hosts: usize,
) -> (Vec<(String, RecordType)>, BTreeSet<String>) {
    let mut hosts = confirmed_hosts
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    hosts.sort_by_key(|host| {
        let label = host.split('.').next().unwrap_or_default();
        let priority = match label {
            "www" | "api" | "app" | "auth" | "admin" | "portal" | "dashboard" => 0,
            "mail" | "webmail" | "git" | "status" | "dev" | "test" | "staging" | "prod" => 1,
            _ if host == domain => 0,
            _ => 2,
        };
        (priority, host.split('.').count(), host.clone())
    });
    hosts.truncate(max_hosts.min(64));

    let suffix = format!(".{domain}");
    let mut zones = BTreeSet::from([domain.to_owned()]);
    for host in &hosts {
        let Some(relative) = host.strip_suffix(&suffix) else {
            continue;
        };
        if let Some((_, parent)) = relative.split_once('.') {
            zones.insert(format!("{parent}.{domain}"));
        }
    }

    let mut queries = Vec::new();
    for zone in &zones {
        queries.push((zone.clone(), RecordType::NS));
        queries.push((zone.clone(), RecordType::SOA));
    }
    for host in hosts {
        queries.push((host.clone(), RecordType::HTTPS));
        queries.push((host, RecordType::SVCB));
    }
    queries.extend([
        (domain.to_owned(), RecordType::MX),
        (domain.to_owned(), RecordType::TXT),
        (domain.to_owned(), RecordType::CAA),
    ]);
    (queries, zones)
}

fn endpoint_host(owner: &str, target: &str, domain: &str) -> Option<String> {
    if target == "." {
        return Some(owner.to_owned());
    }
    normalize_observed_name(target, domain)
        .or_else(|| (target == domain).then(|| target.to_owned()))
}

fn service_from_record(
    owner: &str,
    record_type: &str,
    value: &str,
    domain: &str,
) -> Option<ServiceEndpoint> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    match record_type {
        "SRV" if fields.len() >= 4 => {
            let port = fields[2].parse::<u16>().ok()?;
            let hostname = endpoint_host(owner, fields[3].trim_end_matches('.'), domain)?;
            let transport = if owner.contains("._udp.") {
                "udp"
            } else if owner.starts_with("_submission.") {
                "smtp-starttls"
            } else if owner.starts_with("_imap.") {
                "imap-starttls"
            } else if owner.starts_with("_pop3.") {
                "pop3-starttls"
            } else if owner.starts_with("_imaps.")
                || owner.starts_with("_pop3s.")
                || owner.starts_with("_caldavs.")
                || owner.starts_with("_carddavs.")
                || owner.starts_with("_sipfederationtls.")
                || owner.starts_with("_autodiscover.")
            {
                "tcp-tls"
            } else {
                "tcp"
            };
            Some(ServiceEndpoint {
                hostname,
                port,
                transport: transport.to_owned(),
                source: format!("dns-srv:{owner}"),
            })
        }
        "HTTPS" | "SVCB" if fields.len() >= 2 => {
            let hostname = endpoint_host(owner, fields[1].trim_end_matches('.'), domain)?;
            let port = fields
                .iter()
                .find_map(|field| field.strip_prefix("port="))
                .and_then(|port| port.trim_matches('"').parse::<u16>().ok())
                .or_else(|| (record_type == "HTTPS").then_some(443))?;
            Some(ServiceEndpoint {
                hostname,
                port,
                transport: "tcp-tls".to_owned(),
                source: format!("dns-{}:{}", record_type.to_ascii_lowercase(), owner),
            })
        }
        "MX" if fields.len() >= 2 => {
            let hostname = endpoint_host(owner, fields[1].trim_end_matches('.'), domain)?;
            Some(ServiceEndpoint {
                hostname,
                port: 25,
                transport: "smtp-starttls".to_owned(),
                source: format!("dns-mx:{owner}"),
            })
        }
        _ => None,
    }
}

fn absorb(results: Vec<DnsQueryResult>, domain: &str, discovery: &mut DnsGraphDiscovery) {
    discovery.queried += results.len();
    for result in results {
        for record in result.records {
            if result.owner != domain
                && matches!(record.record_type.as_str(), "NS" | "SOA")
                && matches!(result.query_type, RecordType::NS | RecordType::SOA)
            {
                discovery.child_zones.insert(result.owner.clone());
            }
            if let Some(endpoint) =
                service_from_record(&result.owner, &record.record_type, &record.value, domain)
            {
                discovery.service_endpoints.insert(endpoint);
            } else if record.record_type == "SRV"
                && let Some(target) = record
                    .value
                    .split_whitespace()
                    .nth(3)
                    .and_then(normalize_hostname)
                && !query_is_in_scope(&target, domain)
            {
                discovery.external_features.insert(ExternalFeature {
                    owner: result.owner.clone(),
                    value: target,
                    kind: ExternalFeatureKind::SrvTarget,
                });
            }
            let targets = extract_observed_names(&record.value, domain);
            discovery.names.extend(targets.clone());
            if targets.is_empty() {
                discovery.edges.insert(DiscoveryEdge {
                    owner: result.owner.clone(),
                    record_type: record.record_type,
                    value: record.value,
                    target: None,
                });
            } else {
                for target in targets {
                    discovery.edges.insert(DiscoveryEdge {
                        owner: result.owner.clone(),
                        record_type: record.record_type.clone(),
                        value: record.value.clone(),
                        target: Some(target),
                    });
                }
            }
        }
    }
}

fn query_is_in_scope(name: &str, domain: &str) -> bool {
    name == domain || name.ends_with(&format!(".{domain}"))
}

/// Adds one policy-planner delta to the graph and returns only queries that
/// remain inside the requested root. The planner already enforces this rule;
/// this second boundary is intentional defense in depth at the network call.
fn queue_policy_delta(
    delta: PolicyDelta,
    domain: &str,
    discovery: &mut DnsGraphDiscovery,
) -> Vec<PolicyQuery> {
    discovery.names.extend(delta.in_scope_names);
    discovery.external_features.extend(delta.external_features);
    discovery.policy_limits_hit.extend(delta.limits_hit);
    discovery.policy_loops.extend(delta.loops);

    let mut seen = BTreeSet::new();
    delta
        .queries
        .into_iter()
        .filter(|query| query_is_in_scope(&query.name, domain))
        .filter(|query| seen.insert((query.name.clone(), query.record_type.to_string())))
        .collect()
}

async fn discover_dns_policies(
    dns: &DnsEngine,
    domain: &str,
    zones: Vec<String>,
    discovery: &mut DnsGraphDiscovery,
) {
    let Ok(mut planner) = PolicyPlanner::new(domain, PolicyLimits::default()) else {
        return;
    };
    let initial = planner.initial_plan(zones);
    let mut pending = queue_policy_delta(initial, domain, discovery);

    for _ in 0..MAX_POLICY_WAVES {
        if pending.is_empty() {
            break;
        }
        let queries = pending
            .drain(..)
            .map(|query| (query.name, query.record_type))
            .collect::<Vec<_>>();
        let results = dns.query_many(queries).await;

        let mut next = Vec::new();
        for result in &results {
            for record in &result.records {
                let delta = planner.ingest_record(&result.owner, result.query_type, &record.value);
                next.extend(queue_policy_delta(delta, domain, discovery));
            }
        }
        absorb(results, domain, discovery);

        // PolicyPlanner performs scan-wide deduplication. Retain a local guard
        // as well so multiple RDATA values cannot duplicate a network request
        // in the same wave.
        let mut seen = BTreeSet::new();
        next.retain(|query| {
            query_is_in_scope(&query.name, domain)
                && seen.insert((query.name.clone(), query.record_type.to_string()))
        });
        pending = next;
    }
}

pub async fn discover_dns_graph(
    dns: &DnsEngine,
    domain: &str,
    confirmed_hosts: Vec<String>,
    max_hosts: usize,
    service_discovery: bool,
) -> DnsGraphDiscovery {
    let started = Instant::now();
    let (queries, planned_zones) = query_plan(domain, confirmed_hosts, max_hosts);

    let mut discovery = DnsGraphDiscovery::default();
    absorb(dns.query_many(queries).await, domain, &mut discovery);

    if service_discovery {
        let discovered_zones = planned_zones
            .into_iter()
            .chain(discovery.child_zones.iter().cloned())
            .collect::<BTreeSet<_>>();
        let zones = std::iter::once(domain.to_owned())
            .chain(discovered_zones.into_iter().filter(|zone| zone != domain))
            .take(PolicyLimits::default().max_zones)
            .collect::<Vec<_>>();
        let srv_queries = zones
            .iter()
            .cloned()
            .flat_map(|zone| {
                SERVICE_PREFIXES
                    .iter()
                    .map(move |prefix| (format!("{prefix}.{zone}"), RecordType::SRV))
            })
            .collect::<Vec<_>>();
        absorb(dns.query_many(srv_queries).await, domain, &mut discovery);
        discover_dns_policies(dns, domain, zones, &mut discovery).await;
    }

    discovery.duration_ms = started.elapsed().as_millis();
    discovery
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_policy::QueryPurpose;
    use crate::model::DnsRecord;

    #[test]
    fn parses_service_endpoints_from_dns_values() {
        let srv = service_from_record(
            "_sip._tcp.example.com",
            "SRV",
            "10 5 5061 sip.example.com.",
            "example.com",
        )
        .unwrap();
        assert_eq!(srv.hostname, "sip.example.com");
        assert_eq!(srv.port, 5061);

        let https = service_from_record(
            "api.example.com",
            "HTTPS",
            "1 edge.example.com. alpn=h2 port=8443",
            "example.com",
        )
        .unwrap();
        assert_eq!(https.hostname, "edge.example.com");
        assert_eq!(https.port, 8443);

        let submission = service_from_record(
            "_submission._tcp.example.com",
            "SRV",
            "0 1 587 mail.example.com.",
            "example.com",
        )
        .unwrap();
        assert_eq!(submission.transport, "smtp-starttls");
        assert_eq!(submission.port, 587);

        let mx = service_from_record("example.com", "MX", "10 mail.example.com.", "example.com")
            .unwrap();
        assert_eq!(mx.transport, "smtp-starttls");
        assert_eq!(mx.port, 25);
    }

    #[test]
    fn planner_queries_zone_boundaries_instead_of_every_leaf() {
        let (queries, zones) = query_plan(
            "example.com",
            vec![
                "www.example.com".to_owned(),
                "api.dev.example.com".to_owned(),
                "cdn.example.com".to_owned(),
            ],
            250,
        );
        assert!(zones.contains("dev.example.com"));
        assert!(queries.contains(&("dev.example.com".to_owned(), RecordType::NS)));
        assert!(!queries.contains(&("www.example.com".to_owned(), RecordType::NS)));
        assert!(queries.len() < 4 * 4 + 3);
    }

    #[test]
    fn policy_boundary_keeps_external_names_as_features_only() {
        let mut discovery = DnsGraphDiscovery::default();
        let external = ExternalFeature {
            owner: "example.com".to_owned(),
            value: "mail.vendor.net".to_owned(),
            kind: ExternalFeatureKind::SpfInclude,
        };
        let delta = PolicyDelta {
            queries: vec![
                PolicyQuery {
                    name: "_spf.example.com".to_owned(),
                    record_type: RecordType::TXT,
                    purpose: QueryPurpose::Spf,
                },
                // A malformed or future planner must still not cross this
                // final network boundary.
                PolicyQuery {
                    name: "mail.vendor.net".to_owned(),
                    record_type: RecordType::TXT,
                    purpose: QueryPurpose::Spf,
                },
            ],
            in_scope_names: BTreeSet::from(["mta-sts.example.com".to_owned()]),
            external_features: BTreeSet::from([external.clone()]),
            ..PolicyDelta::default()
        };

        let queued = queue_policy_delta(delta, "example.com", &mut discovery);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].name, "_spf.example.com");
        assert!(discovery.external_features.contains(&external));
        assert!(discovery.names.contains("mta-sts.example.com"));
        assert!(!discovery.names.contains("mail.vendor.net"));
    }

    #[test]
    fn policy_query_queue_is_deduplicated_and_scoped() {
        let mut discovery = DnsGraphDiscovery::default();
        let query = PolicyQuery {
            name: "_services._dns-sd._udp.example.com".to_owned(),
            record_type: RecordType::PTR,
            purpose: QueryPurpose::DnsSdBrowse,
        };
        let delta = PolicyDelta {
            queries: vec![query.clone(), query],
            ..PolicyDelta::default()
        };
        let queued = queue_policy_delta(delta, "example.com", &mut discovery);
        assert_eq!(queued.len(), 1);
        assert!(query_is_in_scope(&queued[0].name, "example.com"));
        assert!(!query_is_in_scope("notexample.com", "example.com"));
    }

    #[test]
    fn external_srv_target_is_retained_but_not_promoted() {
        let result = DnsQueryResult {
            owner: "_submission._tcp.example.com".to_owned(),
            query_type: RecordType::SRV,
            records: vec![DnsRecord {
                record_type: "SRV".to_owned(),
                value: "0 1 587 smtp.mail-provider.net.".to_owned(),
                ttl: 300,
            }],
        };
        let mut discovery = DnsGraphDiscovery::default();
        absorb(vec![result], "example.com", &mut discovery);

        assert!(discovery.names.is_empty());
        assert!(discovery.service_endpoints.is_empty());
        assert!(discovery.external_features.iter().any(|feature| {
            feature.kind == ExternalFeatureKind::SrvTarget
                && feature.value == "smtp.mail-provider.net"
        }));
    }
}
