use super::wire::*;
use super::*;

#[derive(Debug)]
pub struct DnsQueryResult {
    pub owner: String,
    pub query_type: RecordType,
    pub records: Vec<DnsRecord>,
}

#[derive(Debug, Clone)]
pub enum DnsResolutionOutcome {
    Positive(ResolvedHost),
    Negative { fqdn: String },
    Indeterminate { fqdn: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WildcardProbeOutcome {
    Wildcard(BTreeSet<String>),
    Normal,
    Indeterminate,
}

impl DnsResolutionOutcome {
    pub fn fqdn(&self) -> &str {
        match self {
            Self::Positive(answer) => &answer.fqdn,
            Self::Negative { fqdn } | Self::Indeterminate { fqdn } => fqdn,
        }
    }

    pub const fn answer(&self) -> Option<&ResolvedHost> {
        match self {
            Self::Positive(answer) => Some(answer),
            Self::Negative { .. } | Self::Indeterminate { .. } => None,
        }
    }
}

#[derive(Debug)]
pub(super) enum RecordLookupOutcome {
    Positive(Vec<DnsRecord>),
    Negative,
    Indeterminate,
}

pub(super) fn merge_record_lookup_outcomes(
    first: RecordLookupOutcome,
    second: RecordLookupOutcome,
) -> RecordLookupOutcome {
    match (first, second) {
        (RecordLookupOutcome::Positive(mut records), RecordLookupOutcome::Positive(more)) => {
            records.extend(more);
            records.sort_by(|left, right| {
                (&left.record_type, &left.value).cmp(&(&right.record_type, &right.value))
            });
            records.dedup_by(|left, right| {
                left.record_type == right.record_type && left.value == right.value
            });
            RecordLookupOutcome::Positive(records)
        }
        (RecordLookupOutcome::Positive(records), _)
        | (_, RecordLookupOutcome::Positive(records)) => RecordLookupOutcome::Positive(records),
        (RecordLookupOutcome::Negative, RecordLookupOutcome::Negative) => {
            RecordLookupOutcome::Negative
        }
        _ => RecordLookupOutcome::Indeterminate,
    }
}

/// Poll both address families together. A validated positive establishes that
/// the owner is live, so the other family can be cancelled immediately. A
/// negative remains deliberately strict and is returned only after both
/// families independently report NXDOMAIN. Fresh generated candidates use a
/// separate A-only quorum before reaching this conservative path.
pub(super) async fn first_positive_or_both<A, Aaaa>(a: A, aaaa: Aaaa) -> RecordLookupOutcome
where
    A: std::future::Future<Output = RecordLookupOutcome>,
    Aaaa: std::future::Future<Output = RecordLookupOutcome>,
{
    tokio::pin!(a);
    tokio::pin!(aaaa);
    tokio::select! {
        a = &mut a => {
            if matches!(&a, RecordLookupOutcome::Positive(_)) {
                a
            } else {
                merge_record_lookup_outcomes(a, aaaa.await)
            }
        }
        aaaa = &mut aaaa => {
            if matches!(&aaaa, RecordLookupOutcome::Positive(_)) {
                aaaa
            } else {
                merge_record_lookup_outcomes(a.await, aaaa)
            }
        }
    }
}

pub(super) async fn first_true_or_both<A, B>(first: A, second: B) -> bool
where
    A: std::future::Future<Output = bool>,
    B: std::future::Future<Output = bool>,
{
    tokio::pin!(first);
    tokio::pin!(second);
    tokio::select! {
        confirmed = &mut first => {
            if confirmed {
                true
            } else {
                second.await
            }
        }
        confirmed = &mut second => {
            if confirmed {
                true
            } else {
                first.await
            }
        }
    }
}

pub(super) fn positive_consensus(
    fqdn: &str,
    positives: Vec<Vec<DnsRecord>>,
) -> DnsResolutionOutcome {
    let resolver_count = positives.len().min(u16::MAX as usize) as u16;
    let mut records = positives.into_iter().flatten().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        (&left.record_type, &left.value).cmp(&(&right.record_type, &right.value))
    });
    records
        .dedup_by(|left, right| left.record_type == right.record_type && left.value == right.value);
    DnsResolutionOutcome::Positive(ResolvedHost {
        fqdn: fqdn.to_owned(),
        records,
        from_cache: false,
        last_verified_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64),
        authoritative_validation: false,
        resolver_count,
    })
}

pub(super) fn positive_quorum(resolver_count: usize) -> usize {
    match resolver_count {
        0 | 1 => 1,
        2 | 3 => 2,
        count => count / 2 + 1,
    }
}

pub(super) async fn collect_consensus_results<S>(
    fqdn: &str,
    required: usize,
    results: S,
) -> DnsResolutionOutcome
where
    S: Stream<Item = RecordLookupOutcome>,
{
    tokio::pin!(results);
    let mut positives = Vec::new();
    let mut negatives = 0_usize;
    let mut indeterminate = 0_usize;
    while let Some(result) = results.next().await {
        match result {
            RecordLookupOutcome::Positive(records) => {
                positives.push(records);
                if positives.len() >= required {
                    // Dropping the stream cancels slower resolver queries once a
                    // positive quorum has already established a live answer.
                    return positive_consensus(fqdn, positives);
                }
            }
            RecordLookupOutcome::Negative => negatives += 1,
            RecordLookupOutcome::Indeterminate => indeterminate += 1,
        }
    }
    if positives.is_empty() && negatives >= required && indeterminate == 0 {
        DnsResolutionOutcome::Negative {
            fqdn: fqdn.to_owned(),
        }
    } else {
        DnsResolutionOutcome::Indeterminate {
            fqdn: fqdn.to_owned(),
        }
    }
}

pub(super) fn classify_host_lookup(
    fqdn: &str,
    outcome: RecordLookupOutcome,
) -> DnsResolutionOutcome {
    match outcome {
        RecordLookupOutcome::Positive(records) => positive_consensus(fqdn, vec![records]),
        RecordLookupOutcome::Negative => DnsResolutionOutcome::Negative {
            fqdn: fqdn.to_owned(),
        },
        RecordLookupOutcome::Indeterminate => DnsResolutionOutcome::Indeterminate {
            fqdn: fqdn.to_owned(),
        },
    }
}

pub(super) async fn authoritative_servers_cached<F, Fut>(
    cache: &tokio::sync::Mutex<HashMap<String, AuthoritativeServerCell>>,
    domain: &str,
    loader: F,
) -> Result<AuthoritativeServers>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<AuthoritativeServers>>,
{
    let key = domain.trim_end_matches('.').to_ascii_lowercase();
    let cell = {
        let mut cache = cache.lock().await;
        if !cache.contains_key(&key) && cache.len() >= MAX_AUTHORITATIVE_SERVER_CACHE_ENTRIES {
            // This cache is an optimization, not persistent evidence. Keeping
            // one cell for every speculative child zone lets a hostile/deep
            // candidate set consume memory for the whole scan. Prefer evicting
            // a completed empty lookup, otherwise evict one arbitrary old cell;
            // any in-flight user retains its own Arc safely.
            let evicted = cache
                .iter()
                .find_map(|(cached_key, cell)| {
                    cell.get()
                        .is_some_and(AuthoritativeServers::is_empty)
                        .then(|| cached_key.clone())
                })
                .or_else(|| cache.keys().next().cloned());
            if let Some(evicted) = evicted {
                cache.remove(&evicted);
            }
        }
        cache
            .entry(key.clone())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone()
    };
    cell.get_or_try_init(|| loader(key)).await.cloned()
}

pub(super) fn classify_wildcard_samples(
    non_empty: Vec<BTreeSet<String>>,
    negatives: usize,
    total_samples: usize,
) -> WildcardProbeOutcome {
    if !non_empty.is_empty() && negatives > 0 {
        return WildcardProbeOutcome::Indeterminate;
    }
    if non_empty.len() >= 3 {
        let mut samples = non_empty.into_iter();
        let mut signature = samples.next().unwrap_or_default();
        for sample in samples {
            signature.retain(|record| sample.contains(record));
        }
        if signature.is_empty() {
            WildcardProbeOutcome::Indeterminate
        } else {
            WildcardProbeOutcome::Wildcard(signature)
        }
    } else if non_empty.is_empty() && negatives >= 3 && negatives == total_samples {
        WildcardProbeOutcome::Normal
    } else {
        WildcardProbeOutcome::Indeterminate
    }
}

/// Return a result only when the samples already satisfy the strict wildcard
/// classifier. An indeterminate first stage must collect more evidence: it can
/// represent timeouts, a rotating wildcard, or a mix of positive and negative
/// answers, and must never be shortened into a normal zone.
pub(super) fn conclusive_wildcard_outcome(
    non_empty: &[BTreeSet<String>],
    negatives: usize,
) -> Option<WildcardProbeOutcome> {
    match classify_wildcard_samples(non_empty.to_vec(), negatives, 3) {
        outcome @ (WildcardProbeOutcome::Wildcard(_) | WildcardProbeOutcome::Normal) => {
            Some(outcome)
        }
        WildcardProbeOutcome::Indeterminate => None,
    }
}

pub(super) fn authoritative_zone_candidates(fqdn: &str, root_domain: &str) -> Vec<String> {
    let labels = fqdn.trim_end_matches('.').split('.').collect::<Vec<_>>();
    let root_labels = root_domain.trim_end_matches('.').split('.').count();
    if root_labels == 0 || labels.len() < root_labels {
        return Vec::new();
    }
    let first_parent = usize::from(labels.len() > root_labels);
    let root_start = labels.len() - root_labels;
    let mut starts = (first_parent..=root_start)
        .take(MAX_AUTHORITATIVE_ZONE_CANDIDATES.saturating_sub(1))
        .collect::<Vec<_>>();
    if !starts.contains(&root_start) {
        starts.push(root_start);
    }
    starts
        .into_iter()
        .map(|start| labels[start..].join("."))
        .collect()
}

pub(super) fn normalized_dns_name(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

/// Keep only records reachable from the original question owner. DNS answer
/// sections may contain a CNAME chain, but unrelated records must never turn a
/// candidate into a positive result. The reachability pass is independent from
/// answer ordering and also handles multi-hop and cyclic CNAME responses.
pub(super) fn records_for_query(
    answers: &[Record],
    query_name: &Name,
    record_type: RecordType,
) -> Vec<DnsRecord> {
    let mut reachable = BTreeSet::from([normalized_dns_name(&query_name.to_utf8())]);
    loop {
        let mut changed = false;
        for record in answers {
            if record.record_type() != RecordType::CNAME
                || !reachable.contains(&normalized_dns_name(&record.name().to_utf8()))
            {
                continue;
            }
            changed |= reachable.insert(normalized_dns_name(&record.data().to_string()));
        }
        if !changed {
            break;
        }
    }

    answers
        .iter()
        .filter(|record| {
            reachable.contains(&normalized_dns_name(&record.name().to_utf8()))
                && (record.record_type() == record_type
                    || record.record_type() == RecordType::CNAME)
        })
        .map(|record| DnsRecord {
            record_type: record.record_type().to_string(),
            value: record.data().to_string().trim_end_matches('.').to_owned(),
            ttl: record.ttl(),
        })
        .collect()
}

pub(super) fn response_records(response: &Message, record_type: RecordType) -> Vec<DnsRecord> {
    response
        .queries()
        .first()
        .map(|query| records_for_query(response.answers(), query.name(), record_type))
        .unwrap_or_default()
}

pub(super) fn base32hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut output = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

pub(super) fn nsec_synthesis(
    owner: &str,
    next_name: &str,
    bitmap: &BTreeSet<u16>,
) -> DenialSynthesis {
    if bitmap.contains(&TYPE_NXNAME) {
        return DenialSynthesis::Compact;
    }
    let owner = owner.trim_end_matches('.').to_ascii_lowercase();
    let next = next_name.trim_end_matches('.').to_ascii_lowercase();
    if next == format!("\\000.{owner}") {
        // Older compact responders are ambiguous without RFC 9824 NXNAME.
        DenialSynthesis::Unknown
    } else {
        DenialSynthesis::Conventional
    }
}

pub(super) fn dnssec_input_from_authorities(
    qname: &str,
    qtype: RecordType,
    authorities: &[Record],
) -> DnssecProofInput {
    let mut input = DnssecProofInput {
        qname: qname.to_owned(),
        qtype: u16::from(qtype),
        ..DnssecProofInput::default()
    };
    let parsed_qname = Name::from_str(&format!("{}.", qname.trim_end_matches('.'))).ok();
    for record in authorities {
        let RData::DNSSEC(data) = record.data() else {
            continue;
        };
        match data {
            DNSSECRData::NSEC(nsec) => {
                let owner = record.name().to_utf8();
                let next_name = nsec.next_domain_name().to_utf8();
                let type_bitmap = nsec.type_bit_maps().map(u16::from).collect::<BTreeSet<_>>();
                input.nsec.push(NsecProof {
                    synthesis: nsec_synthesis(&owner, &next_name, &type_bitmap),
                    owner,
                    next_name,
                    type_bitmap,
                    signature_validated: record.proof.is_secure(),
                });
            }
            DNSSECRData::NSEC3(nsec3) => {
                let Some(qname_hash) = parsed_qname.as_ref().and_then(|name| {
                    nsec3
                        .hash_algorithm()
                        .hash(nsec3.salt(), name, nsec3.iterations())
                        .ok()
                        .map(|hash| base32hex(hash.as_ref()))
                }) else {
                    continue;
                };
                let owner_hash = record
                    .name()
                    .to_utf8()
                    .split('.')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_uppercase();
                let next_hash = base32hex(nsec3.next_hashed_owner_name());
                let type_bitmap = nsec3
                    .type_bit_maps()
                    .map(u16::from)
                    .collect::<BTreeSet<_>>();
                input.nsec3.push(Nsec3Proof {
                    owner_hash,
                    next_hash,
                    qname_hash,
                    type_bitmap: type_bitmap.clone(),
                    signature_validated: record.proof.is_secure(),
                    opt_out: nsec3.opt_out(),
                    synthesis: if type_bitmap.contains(&TYPE_NXNAME) {
                        DenialSynthesis::Compact
                    } else {
                        // A hashed online interval cannot be distinguished from
                        // a precomputed chain without additional zone context.
                        DenialSynthesis::Unknown
                    },
                });
            }
            _ => {}
        }
    }
    input
}

pub(super) fn is_definitive_nxdomain(response: &Message) -> bool {
    !response.truncated()
        && response.response_code() == ResponseCode::NXDomain
        && response.answers().is_empty()
}

pub(super) fn classify_address_response(
    response: Result<Message>,
    record_type: RecordType,
) -> RecordLookupOutcome {
    let Ok(response) = response else {
        return RecordLookupOutcome::Indeterminate;
    };
    if response.truncated() {
        return RecordLookupOutcome::Indeterminate;
    }
    let records = response_records(&response, record_type);
    if !records.is_empty() {
        RecordLookupOutcome::Positive(records)
    } else if is_definitive_nxdomain(&response) {
        RecordLookupOutcome::Negative
    } else {
        RecordLookupOutcome::Indeterminate
    }
}

pub(super) fn authoritative_response_confirms(
    response: Result<Message>,
    record_type: RecordType,
) -> bool {
    response.is_ok_and(|response| {
        response.authoritative()
            && !response.truncated()
            && !response_records(&response, record_type).is_empty()
    })
}
