use crate::util::{is_subdomain, normalize_hostname, normalize_observed_name};
use anyhow::{Result, bail};
use hickory_net::proto::rr::Name;
use hickory_resolver::proto::rr::RecordType;
use std::collections::{BTreeMap, BTreeSet};

/// RFC 7208 section 4.6.4 caps SPF terms that cause DNS lookups at ten.
pub const SPF_DNS_LOOKUP_LIMIT: usize = 10;
/// IANA-assigned RR type code for URI (RFC 7553). Hickory 0.26 does not expose
/// a named variant yet, but preserves unknown RR type codes on the wire.
pub const URI_RECORD_TYPE: RecordType = RecordType::Unknown(256);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyLimits {
    pub max_queries: usize,
    pub max_zones: usize,
    pub max_dns_sd_service_types: usize,
    pub max_dns_sd_instances: usize,
    pub max_spf_depth: usize,
    pub max_spf_lookups: usize,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            max_queries: 96,
            max_zones: 8,
            max_dns_sd_service_types: 24,
            max_dns_sd_instances: 64,
            max_spf_depth: 6,
            max_spf_lookups: SPF_DNS_LOOKUP_LIMIT,
        }
    }
}

impl PolicyLimits {
    fn sanitized(self) -> Self {
        Self {
            max_spf_lookups: self.max_spf_lookups.min(SPF_DNS_LOOKUP_LIMIT),
            max_spf_depth: self.max_spf_depth.min(16),
            ..self
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryPurpose {
    DnsSdBrowse,
    DnsSdService,
    DnsSdInstance,
    Naptr,
    Uri,
    Spf,
    Dmarc,
    MtaSts,
    TlsReporting,
    Bimi,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyQuery {
    pub name: String,
    pub record_type: RecordType,
    pub purpose: QueryPurpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExternalFeatureKind {
    DnsSdService,
    DnsSdInstance,
    SrvTarget,
    NaptrReplacement,
    UriTarget,
    SpfInclude,
    SpfRedirect,
    SpfA,
    SpfMx,
    SpfExists,
    TxtReference,
}

/// A useful out-of-scope relationship. It is deliberately never converted to
/// a `PolicyQuery`; callers may use it only as a provider/naming feature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExternalFeature {
    pub owner: String,
    pub value: String,
    pub kind: ExternalFeatureKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlanLimit {
    QueryBudget,
    ZoneBudget,
    DnsSdServiceBudget,
    DnsSdInstanceBudget,
    SpfDepth,
    SpfLookupBudget,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PolicyDelta {
    pub queries: Vec<PolicyQuery>,
    /// Only syntactically valid hostnames below the requested root are exposed
    /// as candidates. DNS protocol owners such as `_dmarc` stay query-only.
    pub in_scope_names: BTreeSet<String>,
    pub external_features: BTreeSet<ExternalFeature>,
    pub unsupported_terms: BTreeSet<String>,
    pub loops: BTreeSet<String>,
    pub limits_hit: BTreeSet<PlanLimit>,
}

impl PolicyDelta {
    fn merge_non_queries(&mut self, other: PolicyDelta) {
        self.in_scope_names.extend(other.in_scope_names);
        self.external_features.extend(other.external_features);
        self.unsupported_terms.extend(other.unsupported_terms);
        self.loops.extend(other.loops);
        self.limits_hit.extend(other.limits_hit);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailPolicyNames {
    pub spf_owner: String,
    pub dmarc: String,
    pub mta_sts_dns: String,
    pub mta_sts_host: String,
    pub tls_reporting: String,
    pub bimi_default: String,
}

pub fn mail_policy_names(domain: &str) -> Option<MailPolicyNames> {
    let domain = normalize_hostname(domain)?;
    Some(MailPolicyNames {
        spf_owner: domain.clone(),
        dmarc: format!("_dmarc.{domain}"),
        mta_sts_dns: format!("_mta-sts.{domain}"),
        mta_sts_host: format!("mta-sts.{domain}"),
        tls_reporting: format!("_smtp._tls.{domain}"),
        bimi_default: format!("default._bimi.{domain}"),
    })
}

/// Stateful, deterministic SPF planner. An instance represents one scan root,
/// so lookup accounting and loop detection are shared by the complete include
/// tree rather than reset for every TXT response.
#[derive(Debug, Clone)]
pub struct SpfPlanner {
    root_domain: String,
    max_depth: usize,
    max_lookups: usize,
    lookups_used: usize,
    expanded: BTreeSet<String>,
    pending_depths: BTreeMap<String, usize>,
}

impl SpfPlanner {
    pub fn new(root_domain: &str, max_depth: usize, max_lookups: usize) -> Result<Self> {
        let Some(root_domain) = normalize_hostname(root_domain) else {
            bail!("invalid SPF root domain: {root_domain}");
        };
        Ok(Self {
            root_domain,
            max_depth: max_depth.min(16),
            max_lookups: max_lookups.min(SPF_DNS_LOOKUP_LIMIT),
            lookups_used: 0,
            expanded: BTreeSet::new(),
            pending_depths: BTreeMap::new(),
        })
    }

    pub fn lookups_used(&self) -> usize {
        self.lookups_used
    }

    pub fn remaining_lookups(&self) -> usize {
        self.max_lookups.saturating_sub(self.lookups_used)
    }

    /// Expands one SPF TXT record. `include` and `redirect` queries returned by
    /// this method can be fed back through `expand` with their TXT response.
    pub fn expand(&mut self, owner: &str, record: &str) -> PolicyDelta {
        let mut delta = PolicyDelta::default();
        let Some(owner) = normalize_query_name(owner) else {
            delta.unsupported_terms.insert(owner.to_owned());
            return delta;
        };
        if !query_name_in_scope(&owner, &self.root_domain) {
            delta.external_features.insert(ExternalFeature {
                owner: self.root_domain.clone(),
                value: owner,
                kind: ExternalFeatureKind::SpfInclude,
            });
            return delta;
        }

        let depth = self.pending_depths.remove(&owner).unwrap_or(0);
        if depth > self.max_depth {
            delta.limits_hit.insert(PlanLimit::SpfDepth);
            return delta;
        }
        if !self.expanded.insert(owner.clone()) {
            delta.loops.insert(owner);
            return delta;
        }

        let record = normalize_txt_value(record);
        let mut terms = record.split_ascii_whitespace();
        let Some(version) = terms.next() else {
            return delta;
        };
        if !version.eq_ignore_ascii_case("v=spf1") {
            delta.unsupported_terms.insert(record.trim().to_owned());
            return delta;
        }

        for raw_term in terms {
            let term = raw_term.trim_start_matches(['+', '-', '~', '?']);
            let lower = term.to_ascii_lowercase();
            let (mechanism, raw_target) = if let Some(target) = lower.strip_prefix("include:") {
                (
                    SpfMechanism::Include,
                    Some(&term[term.len() - target.len()..]),
                )
            } else if let Some(target) = lower.strip_prefix("redirect=") {
                (
                    SpfMechanism::Redirect,
                    Some(&term[term.len() - target.len()..]),
                )
            } else if lower == "a" || lower.starts_with("a:") || lower.starts_with("a/") {
                (SpfMechanism::A, mechanism_target(term, "a"))
            } else if lower == "mx" || lower.starts_with("mx:") || lower.starts_with("mx/") {
                (SpfMechanism::Mx, mechanism_target(term, "mx"))
            } else if let Some(target) = lower.strip_prefix("exists:") {
                (
                    SpfMechanism::Exists,
                    Some(&term[term.len() - target.len()..]),
                )
            } else {
                continue;
            };

            if self.lookups_used >= self.max_lookups {
                delta.limits_hit.insert(PlanLimit::SpfLookupBudget);
                break;
            }
            self.lookups_used += 1;

            let target = raw_target.unwrap_or(&owner);
            if target.contains('%') {
                delta.unsupported_terms.insert(raw_term.to_owned());
                continue;
            }
            let Some(target) = normalize_query_name(target.trim_end_matches('/')) else {
                delta.unsupported_terms.insert(raw_term.to_owned());
                continue;
            };

            let kind = mechanism.feature_kind();
            if !query_name_in_scope(&target, &self.root_domain) {
                delta.external_features.insert(ExternalFeature {
                    owner: owner.clone(),
                    value: target,
                    kind,
                });
                continue;
            }
            if let Some(hostname) = normalize_observed_name(&target, &self.root_domain) {
                delta.in_scope_names.insert(hostname);
            }

            match mechanism {
                SpfMechanism::Include | SpfMechanism::Redirect => {
                    if self.expanded.contains(&target) {
                        delta.loops.insert(target);
                        continue;
                    }
                    let next_depth = depth + 1;
                    if next_depth > self.max_depth {
                        delta.limits_hit.insert(PlanLimit::SpfDepth);
                        continue;
                    }
                    self.pending_depths
                        .entry(target.clone())
                        .and_modify(|known| *known = (*known).min(next_depth))
                        .or_insert(next_depth);
                    delta.queries.push(PolicyQuery {
                        name: target,
                        record_type: RecordType::TXT,
                        purpose: QueryPurpose::Spf,
                    });
                }
                SpfMechanism::A => {
                    for record_type in [RecordType::A, RecordType::AAAA] {
                        delta.queries.push(PolicyQuery {
                            name: target.clone(),
                            record_type,
                            purpose: QueryPurpose::Spf,
                        });
                    }
                }
                SpfMechanism::Mx => delta.queries.push(PolicyQuery {
                    name: target,
                    record_type: RecordType::MX,
                    purpose: QueryPurpose::Spf,
                }),
                SpfMechanism::Exists => delta.queries.push(PolicyQuery {
                    name: target,
                    record_type: RecordType::A,
                    purpose: QueryPurpose::Spf,
                }),
            }
        }
        deduplicate_queries(&mut delta.queries);
        delta
    }
}

#[derive(Debug, Clone, Copy)]
enum SpfMechanism {
    Include,
    Redirect,
    A,
    Mx,
    Exists,
}

impl SpfMechanism {
    fn feature_kind(self) -> ExternalFeatureKind {
        match self {
            Self::Include => ExternalFeatureKind::SpfInclude,
            Self::Redirect => ExternalFeatureKind::SpfRedirect,
            Self::A => ExternalFeatureKind::SpfA,
            Self::Mx => ExternalFeatureKind::SpfMx,
            Self::Exists => ExternalFeatureKind::SpfExists,
        }
    }
}

/// Removes IPv4/IPv6 CIDR suffixes and returns an optional domain-spec.
fn mechanism_target<'a>(term: &'a str, mechanism: &str) -> Option<&'a str> {
    let tail = &term[mechanism.len()..];
    let domain = tail.strip_prefix(':')?;
    domain.split('/').next().filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
pub struct PolicyPlanner {
    root_domain: String,
    limits: PolicyLimits,
    planned_queries: BTreeSet<(String, String)>,
    service_types: BTreeSet<String>,
    service_instances: BTreeSet<String>,
    spf: SpfPlanner,
}

impl PolicyPlanner {
    pub fn new(root_domain: &str, limits: PolicyLimits) -> Result<Self> {
        let Some(root_domain) = normalize_hostname(root_domain) else {
            bail!("invalid DNS policy root domain: {root_domain}");
        };
        let limits = limits.sanitized();
        Ok(Self {
            spf: SpfPlanner::new(&root_domain, limits.max_spf_depth, limits.max_spf_lookups)?,
            root_domain,
            limits,
            planned_queries: BTreeSet::new(),
            service_types: BTreeSet::new(),
            service_instances: BTreeSet::new(),
        })
    }

    pub fn root_domain(&self) -> &str {
        &self.root_domain
    }

    pub fn spf_lookups_used(&self) -> usize {
        self.spf.lookups_used()
    }

    /// Builds the bounded first wave. Later DNS-SD waves are produced by
    /// `ingest_record`, after PTR answers reveal service types and instances.
    pub fn initial_plan<I, S>(&mut self, zones: I) -> PolicyDelta
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut delta = PolicyDelta::default();
        let mut zones = zones
            .into_iter()
            .filter_map(|zone| normalize_hostname(zone.as_ref()))
            .filter(|zone| zone == &self.root_domain || is_subdomain(zone, &self.root_domain))
            .collect::<BTreeSet<_>>();
        zones.remove(&self.root_domain);
        let zone_count = zones.len() + 1;
        if zone_count > self.limits.max_zones {
            delta.limits_hit.insert(PlanLimit::ZoneBudget);
        }

        let zones = std::iter::once(self.root_domain.clone())
            .chain(zones)
            .take(self.limits.max_zones);
        for zone in zones {
            self.push_query(
                &mut delta,
                format!("_services._dns-sd._udp.{zone}"),
                RecordType::PTR,
                QueryPurpose::DnsSdBrowse,
            );
            self.push_query(
                &mut delta,
                zone.clone(),
                RecordType::NAPTR,
                QueryPurpose::Naptr,
            );
            self.push_query(&mut delta, zone, URI_RECORD_TYPE, QueryPurpose::Uri);
        }

        if let Some(mail) = mail_policy_names(&self.root_domain) {
            self.push_query(
                &mut delta,
                mail.spf_owner,
                RecordType::TXT,
                QueryPurpose::Spf,
            );
            self.push_query(&mut delta, mail.dmarc, RecordType::TXT, QueryPurpose::Dmarc);
            self.push_query(
                &mut delta,
                mail.mta_sts_dns,
                RecordType::TXT,
                QueryPurpose::MtaSts,
            );
            self.push_query(
                &mut delta,
                mail.tls_reporting,
                RecordType::TXT,
                QueryPurpose::TlsReporting,
            );
            self.push_query(
                &mut delta,
                mail.bimi_default,
                RecordType::TXT,
                QueryPurpose::Bimi,
            );
            if let Some(name) = normalize_observed_name(&mail.mta_sts_host, &self.root_domain) {
                delta.in_scope_names.insert(name);
            }
            for record_type in [RecordType::A, RecordType::AAAA] {
                self.push_query(
                    &mut delta,
                    mail.mta_sts_host.clone(),
                    record_type,
                    QueryPurpose::MtaSts,
                );
            }
        }
        delta
    }

    /// Consumes one presentation-format RDATA value and returns the next safe
    /// wave plus candidate/features learned from the record.
    pub fn ingest_record(
        &mut self,
        owner: &str,
        record_type: RecordType,
        value: &str,
    ) -> PolicyDelta {
        let mut delta = PolicyDelta::default();
        let Some(owner) = normalize_query_name(owner) else {
            delta.unsupported_terms.insert(owner.to_owned());
            return delta;
        };
        if !query_name_in_scope(&owner, &self.root_domain) {
            return delta;
        }

        match record_type {
            RecordType::PTR => self.ingest_ptr(&owner, value, &mut delta),
            RecordType::SRV => {
                if let Some(target) = dns_fields(value).last() {
                    classify_reference(
                        &owner,
                        target,
                        ExternalFeatureKind::SrvTarget,
                        &self.root_domain,
                        &mut delta,
                    );
                }
            }
            RecordType::NAPTR => {
                let fields = dns_fields(value);
                if let Some(replacement) = fields.get(5) {
                    classify_reference(
                        &owner,
                        replacement,
                        ExternalFeatureKind::NaptrReplacement,
                        &self.root_domain,
                        &mut delta,
                    );
                }
                if let Some(regexp) = fields.get(4) {
                    classify_embedded_references(
                        &owner,
                        regexp,
                        ExternalFeatureKind::UriTarget,
                        &self.root_domain,
                        &mut delta,
                    );
                }
            }
            URI_RECORD_TYPE => {
                let fields = dns_fields(value);
                if fields.len() >= 3 {
                    classify_embedded_references(
                        &owner,
                        &fields[2..].join(" "),
                        ExternalFeatureKind::UriTarget,
                        &self.root_domain,
                        &mut delta,
                    );
                }
            }
            RecordType::TXT => {
                let value = normalize_txt_value(value);
                if value
                    .split_ascii_whitespace()
                    .next()
                    .is_some_and(|version| version.eq_ignore_ascii_case("v=spf1"))
                {
                    let mut spf_delta = self.spf.expand(&owner, &value);
                    let queries = std::mem::take(&mut spf_delta.queries);
                    delta.merge_non_queries(spf_delta);
                    for query in queries {
                        self.push_query(&mut delta, query.name, query.record_type, query.purpose);
                    }
                } else {
                    classify_embedded_references(
                        &owner,
                        &value,
                        ExternalFeatureKind::TxtReference,
                        &self.root_domain,
                        &mut delta,
                    );
                }
            }
            _ => {}
        }
        delta
    }

    fn ingest_ptr(&mut self, owner: &str, value: &str, delta: &mut PolicyDelta) {
        let Some(target) = normalize_query_name(value) else {
            delta.unsupported_terms.insert(value.to_owned());
            return;
        };
        let is_browse_owner = owner.starts_with("_services._dns-sd._udp.");
        if !query_name_in_scope(&target, &self.root_domain) {
            delta.external_features.insert(ExternalFeature {
                owner: owner.to_owned(),
                value: target,
                kind: if is_browse_owner {
                    ExternalFeatureKind::DnsSdService
                } else {
                    ExternalFeatureKind::DnsSdInstance
                },
            });
            return;
        }

        if is_browse_owner {
            if self.service_types.len() >= self.limits.max_dns_sd_service_types {
                delta.limits_hit.insert(PlanLimit::DnsSdServiceBudget);
                return;
            }
            if self.service_types.insert(target.clone()) {
                self.push_query(delta, target, RecordType::PTR, QueryPurpose::DnsSdService);
            }
        } else if self.service_types.contains(owner) {
            if self.service_instances.len() >= self.limits.max_dns_sd_instances {
                delta.limits_hit.insert(PlanLimit::DnsSdInstanceBudget);
                return;
            }
            if self.service_instances.insert(target.clone()) {
                for record_type in [RecordType::SRV, RecordType::TXT] {
                    self.push_query(
                        delta,
                        target.clone(),
                        record_type,
                        QueryPurpose::DnsSdInstance,
                    );
                }
            }
        } else {
            classify_reference(
                owner,
                &target,
                ExternalFeatureKind::DnsSdInstance,
                &self.root_domain,
                delta,
            );
        }
    }

    fn push_query(
        &mut self,
        delta: &mut PolicyDelta,
        name: String,
        record_type: RecordType,
        purpose: QueryPurpose,
    ) {
        let Some(name) = normalize_query_name(&name) else {
            delta.unsupported_terms.insert(name);
            return;
        };
        if !query_name_in_scope(&name, &self.root_domain) {
            return;
        }
        let key = (name.clone(), record_type.to_string());
        if self.planned_queries.contains(&key) {
            return;
        }
        if self.planned_queries.len() >= self.limits.max_queries {
            delta.limits_hit.insert(PlanLimit::QueryBudget);
            return;
        }
        self.planned_queries.insert(key);
        delta.queries.push(PolicyQuery {
            name,
            record_type,
            purpose,
        });
    }
}

fn normalize_query_name(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('"').trim_end_matches('.');
    if value.is_empty() || value == "." {
        return None;
    }
    let name = Name::from_ascii(value).ok()?;
    let normalized = name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
    (normalized.len() <= 253).then_some(normalized)
}

fn query_name_in_scope(name: &str, root_domain: &str) -> bool {
    name == root_domain || name.ends_with(&format!(".{root_domain}"))
}

fn classify_reference(
    owner: &str,
    value: &str,
    kind: ExternalFeatureKind,
    root_domain: &str,
    delta: &mut PolicyDelta,
) {
    let Some(target) = normalize_query_name(value) else {
        return;
    };
    if query_name_in_scope(&target, root_domain) {
        if let Some(name) = normalize_observed_name(&target, root_domain) {
            delta.in_scope_names.insert(name);
        }
    } else {
        delta.external_features.insert(ExternalFeature {
            owner: owner.to_owned(),
            value: target,
            kind,
        });
    }
}

fn classify_embedded_references(
    owner: &str,
    value: &str,
    kind: ExternalFeatureKind,
    root_domain: &str,
    delta: &mut PolicyDelta,
) {
    for token in value.split(|character: char| {
        character.is_ascii_whitespace()
            || matches!(
                character,
                '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | '!'
            )
    }) {
        let token = token.trim_matches(|character: char| matches!(character, '.' | ':' | '='));
        if token.is_empty() {
            continue;
        }
        // Policy records commonly use `key=URI` fields (BIMI, DMARC and
        // TLS-RPT). Strip the field name only when `=` precedes a URI scheme.
        let token = match (token.find('='), token.find("://")) {
            (Some(equal), Some(scheme)) if equal < scheme => &token[equal + 1..],
            (Some(equal), None) => &token[equal + 1..],
            _ => token,
        };
        if let Ok(url) = url::Url::parse(token)
            && let Some(host) = url.host_str()
        {
            classify_reference(owner, host, kind, root_domain, delta);
            continue;
        }
        if let Some((_, mail_domain)) = token.rsplit_once('@') {
            classify_reference(owner, mail_domain, kind, root_domain, delta);
            continue;
        }
        classify_reference(owner, token, kind, root_domain, delta);
    }
}

/// Presentation-format DNS fields with quoted strings kept as single fields.
fn dns_fields(value: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            current.push(character);
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if character.is_ascii_whitespace() && !quoted {
            if !current.is_empty() {
                fields.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if !current.is_empty() {
        fields.push(current);
    }
    fields
}

fn normalize_txt_value(value: &str) -> String {
    if value.contains('"') {
        dns_fields(value).join("")
    } else {
        value.trim().to_owned()
    }
}

fn deduplicate_queries(queries: &mut Vec<PolicyQuery>) {
    let mut seen = BTreeSet::new();
    queries.retain(|query| seen.insert((query.name.clone(), query.record_type.to_string())));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_exists(delta: &PolicyDelta, name: &str, record_type: RecordType) -> bool {
        delta
            .queries
            .iter()
            .any(|query| query.name == name && query.record_type == record_type)
    }

    #[test]
    fn initial_plan_is_bounded_and_contains_policy_names() {
        let limits = PolicyLimits {
            max_queries: 12,
            max_zones: 2,
            ..PolicyLimits::default()
        };
        let mut planner = PolicyPlanner::new("example.com", limits).unwrap();
        let delta = planner.initial_plan([
            "b.example.com",
            "a.example.com",
            "outside.test",
            "c.example.com",
        ]);

        assert_eq!(delta.queries.len(), 12);
        assert!(delta.limits_hit.contains(&PlanLimit::ZoneBudget));
        assert!(delta.limits_hit.contains(&PlanLimit::QueryBudget));
        assert!(query_exists(
            &delta,
            "_services._dns-sd._udp.example.com",
            RecordType::PTR
        ));
        assert!(query_exists(&delta, "_dmarc.example.com", RecordType::TXT));
        assert!(delta.in_scope_names.contains("mta-sts.example.com"));
        assert!(
            delta
                .queries
                .iter()
                .all(|query| query_name_in_scope(&query.name, "example.com"))
        );
    }

    #[test]
    fn dns_sd_browse_is_multistage_and_deduplicated() {
        let mut planner = PolicyPlanner::new("example.com", PolicyLimits::default()).unwrap();
        let _ = planner.initial_plan(["example.com"]);
        let service = planner.ingest_record(
            "_services._dns-sd._udp.example.com",
            RecordType::PTR,
            "_http._tcp.example.com.",
        );
        assert!(query_exists(
            &service,
            "_http._tcp.example.com",
            RecordType::PTR
        ));

        let duplicate = planner.ingest_record(
            "_services._dns-sd._udp.example.com",
            RecordType::PTR,
            "_http._tcp.example.com.",
        );
        assert!(duplicate.queries.is_empty());

        let instance = planner.ingest_record(
            "_http._tcp.example.com",
            RecordType::PTR,
            "web-1._http._tcp.example.com.",
        );
        assert!(query_exists(
            &instance,
            "web-1._http._tcp.example.com",
            RecordType::SRV
        ));
        assert!(query_exists(
            &instance,
            "web-1._http._tcp.example.com",
            RecordType::TXT
        ));

        let target = planner.ingest_record(
            "web-1._http._tcp.example.com",
            RecordType::SRV,
            "0 10 443 api.example.com.",
        );
        assert_eq!(
            target.in_scope_names,
            BTreeSet::from(["api.example.com".into()])
        );
    }

    #[test]
    fn external_dns_sd_targets_are_features_never_queries() {
        let mut planner = PolicyPlanner::new("example.com", PolicyLimits::default()).unwrap();
        let _ = planner.initial_plan(["example.com"]);
        let delta = planner.ingest_record(
            "_services._dns-sd._udp.example.com",
            RecordType::PTR,
            "_http._tcp.vendor.net.",
        );
        assert!(delta.queries.is_empty());
        assert_eq!(delta.external_features.len(), 1);
        assert_eq!(
            delta.external_features.iter().next().unwrap().value,
            "_http._tcp.vendor.net"
        );
    }

    #[test]
    fn spf_is_deterministic_scoped_and_counts_logical_lookups() {
        let mut planner = SpfPlanner::new("example.com", 6, 10).unwrap();
        let delta = planner.expand(
            "example.com",
            "v=spf1 a:mail.example.com/24 mx include:_spf.example.com include:_spf.vendor.net exists:probe.example.com -all",
        );

        assert_eq!(planner.lookups_used(), 5);
        assert_eq!(delta.queries.len(), 5); // A+AAAA, MX, TXT, A.
        assert!(query_exists(&delta, "mail.example.com", RecordType::A));
        assert!(query_exists(&delta, "mail.example.com", RecordType::AAAA));
        assert!(query_exists(&delta, "example.com", RecordType::MX));
        assert!(query_exists(&delta, "_spf.example.com", RecordType::TXT));
        assert!(query_exists(&delta, "probe.example.com", RecordType::A));
        assert!(
            delta
                .queries
                .iter()
                .all(|query| !query.name.ends_with("vendor.net"))
        );
        assert!(delta.external_features.iter().any(|feature| {
            feature.kind == ExternalFeatureKind::SpfInclude && feature.value == "_spf.vendor.net"
        }));
    }

    #[test]
    fn spf_stops_at_ten_and_detects_recursive_loops() {
        let mut planner = SpfPlanner::new("example.com", 6, 99).unwrap();
        let terms = (0..12)
            .map(|index| format!("exists:x{index}.example.com"))
            .collect::<Vec<_>>()
            .join(" ");
        let limited = planner.expand("example.com", &format!("v=spf1 {terms} -all"));
        assert_eq!(planner.lookups_used(), SPF_DNS_LOOKUP_LIMIT);
        assert_eq!(limited.queries.len(), SPF_DNS_LOOKUP_LIMIT);
        assert!(limited.limits_hit.contains(&PlanLimit::SpfLookupBudget));

        let mut looping = SpfPlanner::new("example.com", 6, 10).unwrap();
        let first = looping.expand("example.com", "v=spf1 include:a.example.com -all");
        assert!(query_exists(&first, "a.example.com", RecordType::TXT));
        let loop_result = looping.expand("a.example.com", "v=spf1 include:example.com -all");
        assert!(loop_result.queries.is_empty());
        assert!(loop_result.loops.contains("example.com"));
    }

    #[test]
    fn spf_depth_and_macros_are_bounded_without_guessing() {
        let mut planner = SpfPlanner::new("example.com", 0, 10).unwrap();
        let depth = planner.expand("example.com", "v=spf1 include:a.example.com -all");
        assert!(depth.queries.is_empty());
        assert!(depth.limits_hit.contains(&PlanLimit::SpfDepth));

        let mut planner = SpfPlanner::new("example.com", 6, 10).unwrap();
        let dynamic = planner.expand("example.com", "v=spf1 exists:%{i}.probe.example.com -all");
        assert!(dynamic.queries.is_empty());
        assert!(
            dynamic
                .unsupported_terms
                .contains("exists:%{i}.probe.example.com")
        );
    }

    #[test]
    fn naptr_uri_and_policy_txt_extract_only_scoped_hostnames() {
        let mut planner = PolicyPlanner::new("example.com", PolicyLimits::default()).unwrap();
        let naptr = planner.ingest_record(
            "example.com",
            RecordType::NAPTR,
            "100 10 \"U\" \"E2U+https\" \"\" api.example.com.",
        );
        assert!(naptr.in_scope_names.contains("api.example.com"));

        let uri = planner.ingest_record(
            "example.com",
            URI_RECORD_TYPE,
            "10 1 \"https://auth.example.com/login\"",
        );
        assert!(uri.in_scope_names.contains("auth.example.com"));

        let bimi = planner.ingest_record(
            "default._bimi.example.com",
            RecordType::TXT,
            "v=BIMI1; l=https://assets.example.com/logo.svg; a=https://authority.vendor.net/vmc.pem",
        );
        assert!(bimi.in_scope_names.contains("assets.example.com"));
        assert!(bimi.external_features.iter().any(|feature| {
            feature.kind == ExternalFeatureKind::TxtReference
                && feature.value == "authority.vendor.net"
        }));
        assert!(bimi.queries.is_empty());
    }

    #[test]
    fn mail_policy_names_are_exact_and_stable() {
        let names = mail_policy_names("Example.COM.").unwrap();
        assert_eq!(names.dmarc, "_dmarc.example.com");
        assert_eq!(names.mta_sts_dns, "_mta-sts.example.com");
        assert_eq!(names.mta_sts_host, "mta-sts.example.com");
        assert_eq!(names.tls_reporting, "_smtp._tls.example.com");
        assert_eq!(names.bimi_default, "default._bimi.example.com");
    }
}
