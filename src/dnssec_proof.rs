//! Pure DNSSEC owner-existence and denial-proof classification.
//!
//! This module deliberately does **not** parse packets or validate signatures. The
//! transport layer must validate the DNSSEC chain and then set
//! `signature_validated` on the corresponding evidence. Keeping that boundary
//! explicit prevents an RRSIG merely being present (or its Labels field matching
//! the QNAME) from being mistaken for proof that an owner exists.
//!
//! The classifier implements the safety-relevant semantics from RFC 4034/5155,
//! RFC 8198, and RFC 9824:
//!
//! - NXNAME (type 128) in a validated NSEC/NSEC3 bitmap is a compact proof that
//!   the queried name does not exist.
//! - Compact denial is exact-name evidence and is never eligible for aggressive
//!   range caching.
//! - Conventional validated NSEC/NSEC3 intervals can prove denial and can be
//!   used for aggressive range caching (except NSEC3 Opt-Out coverage).
//! - An authenticated Empty Non-Terminal (ENT) NODATA result is only a traversal
//!   hint. Fellaga must never publish it as a live owner.
//! - RRSIG Labels equality is recorded only as a diagnostic warning; by itself it
//!   never changes the owner state.
//!
//! # Transport integration still required
//!
//! The DNS transport must retain Authority-section NSEC/NSEC3 records and their
//! complete type bitmaps (including unknown type 128), cryptographically validate
//! each RRset, identify Compact versus Conventional synthesis when NXNAME is not
//! present, compute the QNAME NSEC3 hash with the record's own parameters, and
//! identify authenticated ENT NODATA. Do not derive `signature_validated` from the
//! AD bit alone.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

/// Synthetic RR type allocated by RFC 9824 to distinguish nonexistent names.
pub const TYPE_NXNAME: u16 = 128;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_NSEC3: u16 = 50;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DenialSynthesis {
    /// A precomputed/conventional denial chain whose interval is reusable.
    Conventional,
    /// An online, exact-name Compact Answer as described by RFC 9824.
    Compact,
    /// The transport could not safely distinguish the two forms.
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NsecProof {
    pub owner: String,
    pub next_name: String,
    #[serde(default)]
    pub type_bitmap: BTreeSet<u16>,
    /// True only after cryptographic RRset and chain validation.
    #[serde(default)]
    pub signature_validated: bool,
    #[serde(default)]
    pub synthesis: DenialSynthesis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Nsec3Proof {
    /// Base32hex owner hash label, without the zone suffix.
    pub owner_hash: String,
    /// Base32hex next-owner hash label.
    pub next_hash: String,
    /// QNAME hash computed using this record's algorithm, iterations, and salt.
    pub qname_hash: String,
    #[serde(default)]
    pub type_bitmap: BTreeSet<u16>,
    /// True only after cryptographic RRset and chain validation.
    #[serde(default)]
    pub signature_validated: bool,
    /// The Opt-Out bit from the NSEC3 record.
    #[serde(default)]
    pub opt_out: bool,
    #[serde(default)]
    pub synthesis: DenialSynthesis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DnssecProofInput {
    pub qname: String,
    pub qtype: u16,
    /// A positive RRset at the exact QNAME, already DNSSEC-validated and already
    /// established not to be a wildcard expansion.
    #[serde(default)]
    pub validated_exact_positive_answer: bool,
    /// A transport diagnostic only. This flag is intentionally never accepted as
    /// owner-existence evidence.
    #[serde(default)]
    pub rrsig_labels_equal: bool,
    /// The transport has cryptographically established that this NODATA response
    /// represents an Empty Non-Terminal. ENTs exist in DNS tree semantics but are
    /// deliberately not promoted to live enumeration findings.
    #[serde(default)]
    pub validated_ent_nodata: bool,
    #[serde(default)]
    pub nsec: Vec<NsecProof>,
    #[serde(default)]
    pub nsec3: Vec<Nsec3Proof>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DnssecOwnerState {
    Exists,
    DoesNotExist,
    EmptyNonTerminal,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DnssecProofKind {
    ValidatedPositiveAnswer,
    NxnameNsec,
    NxnameNsec3,
    NsecExactOwner,
    NsecRangeDenial,
    Nsec3ExactOwner,
    Nsec3RangeDenial,
    EmptyNonTerminal,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AggressiveCacheEligibility {
    /// The proof must not synthesize negative answers for other lookups.
    #[default]
    Never,
    /// A conventional exact-owner NODATA proof may be reused only for this owner.
    ExactName,
    /// A conventional NSEC/NSEC3 interval can synthesize covered negative answers.
    Range,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DnssecProofWarning {
    InvalidQname,
    UnvalidatedEvidenceIgnored,
    RrsigLabelsEqualityIgnored,
    AmbiguousCompactNodata,
    Nsec3OptOutCoverageIgnored,
    InvalidNsecInterval,
    InvalidNsec3Hash,
    ConflictingValidatedProofs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DnssecProofAssessment {
    pub state: DnssecOwnerState,
    #[serde(default)]
    pub proofs: BTreeSet<DnssecProofKind>,
    #[serde(default)]
    pub warnings: BTreeSet<DnssecProofWarning>,
    /// Safe to expose as a live, exact owner. This is always false for ENTs.
    #[serde(default)]
    pub live_eligible: bool,
    /// Safe to enqueue as a parent/path traversal hint, but not as a live owner.
    #[serde(default)]
    pub traversal_hint: bool,
    #[serde(default)]
    pub aggressive_cache: AggressiveCacheEligibility,
    /// At least one validated Compact Answer participated in the assessment.
    #[serde(default)]
    pub compact_denial_seen: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofInputError {
    InvalidDnsName,
    InvalidNsec3Hash,
    MismatchedNsec3HashLength,
}

impl fmt::Display for ProofInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDnsName => "invalid DNS presentation name",
            Self::InvalidNsec3Hash => "invalid NSEC3 base32hex hash",
            Self::MismatchedNsec3HashLength => "NSEC3 hashes have different lengths",
        })
    }
}

impl Error for ProofInputError {}

#[derive(Debug, Clone, Copy)]
struct Candidate {
    state: DnssecOwnerState,
    kind: DnssecProofKind,
    cache: AggressiveCacheEligibility,
}

struct NormalizedNsec3Hashes {
    owner: Vec<u8>,
    next: Vec<u8>,
    qname: Vec<u8>,
}

/// Classify validated DNSSEC evidence without performing any I/O.
pub fn classify_dnssec_proof(input: &DnssecProofInput) -> DnssecProofAssessment {
    let mut assessment = DnssecProofAssessment::default();
    let qname = match parse_presentation_name(&input.qname) {
        Ok(name) => name,
        Err(_) => {
            assessment.warnings.insert(DnssecProofWarning::InvalidQname);
            return assessment;
        }
    };

    if input.rrsig_labels_equal {
        assessment
            .warnings
            .insert(DnssecProofWarning::RrsigLabelsEqualityIgnored);
    }

    let mut candidates = Vec::new();
    if input.validated_exact_positive_answer {
        candidates.push(Candidate {
            state: DnssecOwnerState::Exists,
            kind: DnssecProofKind::ValidatedPositiveAnswer,
            cache: AggressiveCacheEligibility::Never,
        });
    }
    if input.validated_ent_nodata {
        candidates.push(Candidate {
            state: DnssecOwnerState::EmptyNonTerminal,
            kind: DnssecProofKind::EmptyNonTerminal,
            cache: AggressiveCacheEligibility::Never,
        });
    }

    for proof in &input.nsec {
        classify_nsec(
            &qname,
            input.qtype,
            input.validated_ent_nodata,
            proof,
            &mut candidates,
            &mut assessment,
        );
    }
    for proof in &input.nsec3 {
        classify_nsec3(
            input.qtype,
            input.validated_ent_nodata,
            proof,
            &mut candidates,
            &mut assessment,
        );
    }

    for candidate in &candidates {
        assessment.proofs.insert(candidate.kind);
    }
    let states = candidates
        .iter()
        .map(|candidate| candidate.state)
        .collect::<BTreeSet<_>>();
    if states.len() > 1 {
        assessment.state = DnssecOwnerState::Inconclusive;
        assessment.live_eligible = false;
        assessment.traversal_hint = false;
        assessment.aggressive_cache = AggressiveCacheEligibility::Never;
        assessment
            .warnings
            .insert(DnssecProofWarning::ConflictingValidatedProofs);
        return assessment;
    }

    let Some(state) = states.first().copied() else {
        return assessment;
    };
    assessment.state = state;
    assessment.live_eligible = state == DnssecOwnerState::Exists;
    assessment.traversal_hint = state == DnssecOwnerState::EmptyNonTerminal;
    assessment.aggressive_cache = candidates
        .iter()
        .filter(|candidate| candidate.state == state)
        .map(|candidate| candidate.cache)
        .max()
        .unwrap_or_default();
    assessment
}

fn classify_nsec(
    qname: &[Vec<u8>],
    qtype: u16,
    validated_ent_nodata: bool,
    proof: &NsecProof,
    candidates: &mut Vec<Candidate>,
    assessment: &mut DnssecProofAssessment,
) {
    if !proof.signature_validated {
        assessment
            .warnings
            .insert(DnssecProofWarning::UnvalidatedEvidenceIgnored);
        return;
    }
    let owner = match parse_presentation_name(&proof.owner) {
        Ok(owner) => owner,
        Err(_) => {
            assessment
                .warnings
                .insert(DnssecProofWarning::InvalidNsecInterval);
            return;
        }
    };
    let exact = canonical_name_cmp(&owner, qname) == Ordering::Equal;
    let nxname = proof.type_bitmap.contains(&TYPE_NXNAME);
    let compact = nxname || proof.synthesis == DenialSynthesis::Compact;
    assessment.compact_denial_seen |= compact;

    if exact && nxname {
        candidates.push(Candidate {
            state: DnssecOwnerState::DoesNotExist,
            kind: DnssecProofKind::NxnameNsec,
            cache: AggressiveCacheEligibility::Never,
        });
        return;
    }

    if exact {
        // An authenticated ENT has no terminal owner RRset to publish. Its exact
        // denial record supports traversal only; the dedicated ENT candidate
        // above owns the classification.
        if validated_ent_nodata {
            return;
        }
        match proof.synthesis {
            DenialSynthesis::Conventional => candidates.push(Candidate {
                state: DnssecOwnerState::Exists,
                kind: DnssecProofKind::NsecExactOwner,
                cache: exact_nodata_cache(qtype, &proof.type_bitmap),
            }),
            DenialSynthesis::Compact => {
                // Without the authenticated NXNAME distinguisher, a compact
                // nonexistent response and ENT NODATA can be indistinguishable.
                assessment
                    .warnings
                    .insert(DnssecProofWarning::AmbiguousCompactNodata);
            }
            DenialSynthesis::Unknown => {
                if bitmap_has_owner_data(&proof.type_bitmap) {
                    candidates.push(Candidate {
                        state: DnssecOwnerState::Exists,
                        kind: DnssecProofKind::NsecExactOwner,
                        cache: AggressiveCacheEligibility::Never,
                    });
                } else {
                    assessment
                        .warnings
                        .insert(DnssecProofWarning::AmbiguousCompactNodata);
                }
            }
        }
        return;
    }

    if proof.synthesis != DenialSynthesis::Conventional {
        return;
    }
    match nsec_interval_covers_parsed(&owner, &proof.next_name, qname) {
        Ok(true) => candidates.push(Candidate {
            state: DnssecOwnerState::DoesNotExist,
            kind: DnssecProofKind::NsecRangeDenial,
            cache: AggressiveCacheEligibility::Range,
        }),
        Ok(false) => {}
        Err(_) => {
            assessment
                .warnings
                .insert(DnssecProofWarning::InvalidNsecInterval);
        }
    }
}

fn classify_nsec3(
    qtype: u16,
    validated_ent_nodata: bool,
    proof: &Nsec3Proof,
    candidates: &mut Vec<Candidate>,
    assessment: &mut DnssecProofAssessment,
) {
    if !proof.signature_validated {
        assessment
            .warnings
            .insert(DnssecProofWarning::UnvalidatedEvidenceIgnored);
        return;
    }
    let hashes = match normalized_nsec3_hashes(proof) {
        Ok(hashes) => hashes,
        Err(_) => {
            assessment
                .warnings
                .insert(DnssecProofWarning::InvalidNsec3Hash);
            return;
        }
    };
    let exact = hashes.owner == hashes.qname;
    let nxname = proof.type_bitmap.contains(&TYPE_NXNAME);
    let compact = nxname || proof.synthesis == DenialSynthesis::Compact;
    assessment.compact_denial_seen |= compact;

    if exact && nxname {
        candidates.push(Candidate {
            state: DnssecOwnerState::DoesNotExist,
            kind: DnssecProofKind::NxnameNsec3,
            cache: AggressiveCacheEligibility::Never,
        });
        return;
    }

    if exact {
        if validated_ent_nodata {
            return;
        }
        match proof.synthesis {
            DenialSynthesis::Conventional => candidates.push(Candidate {
                state: DnssecOwnerState::Exists,
                kind: DnssecProofKind::Nsec3ExactOwner,
                cache: exact_nodata_cache(qtype, &proof.type_bitmap),
            }),
            DenialSynthesis::Compact => {
                assessment
                    .warnings
                    .insert(DnssecProofWarning::AmbiguousCompactNodata);
            }
            DenialSynthesis::Unknown => {
                if bitmap_has_owner_data(&proof.type_bitmap) {
                    candidates.push(Candidate {
                        state: DnssecOwnerState::Exists,
                        kind: DnssecProofKind::Nsec3ExactOwner,
                        cache: AggressiveCacheEligibility::Never,
                    });
                } else {
                    assessment
                        .warnings
                        .insert(DnssecProofWarning::AmbiguousCompactNodata);
                }
            }
        }
        return;
    }

    if proof.synthesis != DenialSynthesis::Conventional {
        return;
    }
    if !hash_interval_covers(&hashes.owner, &hashes.next, &hashes.qname) {
        return;
    }
    if proof.opt_out {
        assessment
            .warnings
            .insert(DnssecProofWarning::Nsec3OptOutCoverageIgnored);
        return;
    }
    candidates.push(Candidate {
        state: DnssecOwnerState::DoesNotExist,
        kind: DnssecProofKind::Nsec3RangeDenial,
        cache: AggressiveCacheEligibility::Range,
    });
}

fn bitmap_has_owner_data(bitmap: &BTreeSet<u16>) -> bool {
    bitmap.iter().any(|record_type| {
        !matches!(
            *record_type,
            TYPE_RRSIG | TYPE_NSEC | TYPE_NSEC3 | TYPE_NXNAME
        )
    })
}

fn exact_nodata_cache(qtype: u16, bitmap: &BTreeSet<u16>) -> AggressiveCacheEligibility {
    if bitmap.contains(&qtype) {
        AggressiveCacheEligibility::Never
    } else {
        AggressiveCacheEligibility::ExactName
    }
}

/// Return whether a conventional NSEC interval covers `qname`.
///
/// The owner itself is excluded. Wrap-around intervals are handled according to
/// canonical DNS name ordering from RFC 4034.
pub fn nsec_interval_covers(
    owner: &str,
    next_name: &str,
    qname: &str,
) -> Result<bool, ProofInputError> {
    let owner = parse_presentation_name(owner)?;
    let qname = parse_presentation_name(qname)?;
    nsec_interval_covers_parsed(&owner, next_name, &qname)
}

fn nsec_interval_covers_parsed(
    owner: &[Vec<u8>],
    next_name: &str,
    qname: &[Vec<u8>],
) -> Result<bool, ProofInputError> {
    let next = parse_presentation_name(next_name)?;
    let owner_to_next = canonical_name_cmp(owner, &next);
    let owner_to_qname = canonical_name_cmp(owner, qname);
    if owner_to_qname == Ordering::Equal {
        return Ok(false);
    }
    let qname_to_next = canonical_name_cmp(qname, &next);
    Ok(match owner_to_next {
        Ordering::Less => owner_to_qname == Ordering::Less && qname_to_next == Ordering::Less,
        Ordering::Greater => owner_to_qname == Ordering::Less || qname_to_next == Ordering::Less,
        // Equal endpoints represent the complete canonical ring, excluding owner.
        Ordering::Equal => true,
    })
}

/// Return whether a conventional NSEC3 hash interval covers `qname_hash`.
pub fn nsec3_interval_covers(
    owner_hash: &str,
    next_hash: &str,
    qname_hash: &str,
) -> Result<bool, ProofInputError> {
    let owner = normalize_nsec3_hash(owner_hash)?;
    let next = normalize_nsec3_hash(next_hash)?;
    let qname = normalize_nsec3_hash(qname_hash)?;
    if owner.len() != next.len() || owner.len() != qname.len() {
        return Err(ProofInputError::MismatchedNsec3HashLength);
    }
    Ok(hash_interval_covers(&owner, &next, &qname))
}

fn normalized_nsec3_hashes(proof: &Nsec3Proof) -> Result<NormalizedNsec3Hashes, ProofInputError> {
    let owner = normalize_nsec3_hash(&proof.owner_hash)?;
    let next = normalize_nsec3_hash(&proof.next_hash)?;
    let qname = normalize_nsec3_hash(&proof.qname_hash)?;
    if owner.len() != next.len() || owner.len() != qname.len() {
        return Err(ProofInputError::MismatchedNsec3HashLength);
    }
    Ok(NormalizedNsec3Hashes { owner, next, qname })
}

fn normalize_nsec3_hash(hash: &str) -> Result<Vec<u8>, ProofInputError> {
    if hash.is_empty() {
        return Err(ProofInputError::InvalidNsec3Hash);
    }
    let normalized = hash
        .bytes()
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<_>>();
    if normalized
        .iter()
        .any(|byte| !matches!(*byte, b'0'..=b'9' | b'A'..=b'V'))
    {
        return Err(ProofInputError::InvalidNsec3Hash);
    }
    Ok(normalized)
}

fn hash_interval_covers(owner: &[u8], next: &[u8], qname: &[u8]) -> bool {
    if owner == qname {
        return false;
    }
    match owner.cmp(next) {
        Ordering::Less => owner < qname && qname < next,
        Ordering::Greater => owner < qname || qname < next,
        Ordering::Equal => true,
    }
}

fn canonical_name_cmp(left: &[Vec<u8>], right: &[Vec<u8>]) -> Ordering {
    let mut left_labels = left.iter().rev();
    let mut right_labels = right.iter().rev();
    loop {
        match (left_labels.next(), right_labels.next()) {
            (Some(left), Some(right)) => match left.cmp(right) {
                Ordering::Equal => {}
                ordering => return ordering,
            },
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Parse a DNS presentation name, including `\\DDD` octet escapes, into labels.
fn parse_presentation_name(name: &str) -> Result<Vec<Vec<u8>>, ProofInputError> {
    let bytes = name.as_bytes();
    if bytes == b"." {
        return Ok(Vec::new());
    }
    let end = if bytes.last() == Some(&b'.') {
        bytes.len().saturating_sub(1)
    } else {
        bytes.len()
    };
    if end == 0 {
        return Err(ProofInputError::InvalidDnsName);
    }

    let mut labels = Vec::new();
    let mut label = Vec::new();
    let mut cursor = 0;
    while cursor < end {
        match bytes[cursor] {
            b'.' => {
                push_label(&mut labels, &mut label)?;
                cursor += 1;
            }
            b'\\' => {
                cursor += 1;
                if cursor >= end {
                    return Err(ProofInputError::InvalidDnsName);
                }
                if cursor + 2 < end
                    && bytes[cursor].is_ascii_digit()
                    && bytes[cursor + 1].is_ascii_digit()
                    && bytes[cursor + 2].is_ascii_digit()
                {
                    let value = u16::from(bytes[cursor] - b'0') * 100
                        + u16::from(bytes[cursor + 1] - b'0') * 10
                        + u16::from(bytes[cursor + 2] - b'0');
                    if value > u16::from(u8::MAX) {
                        return Err(ProofInputError::InvalidDnsName);
                    }
                    label.push(value as u8);
                    cursor += 3;
                } else {
                    label.push(bytes[cursor].to_ascii_lowercase());
                    cursor += 1;
                }
            }
            byte => {
                label.push(byte.to_ascii_lowercase());
                cursor += 1;
            }
        }
        if label.len() > 63 {
            return Err(ProofInputError::InvalidDnsName);
        }
    }
    push_label(&mut labels, &mut label)?;
    let wire_length = labels.iter().map(|label| label.len() + 1).sum::<usize>() + 1;
    if wire_length > 255 {
        return Err(ProofInputError::InvalidDnsName);
    }
    Ok(labels)
}

fn push_label(labels: &mut Vec<Vec<u8>>, label: &mut Vec<u8>) -> Result<(), ProofInputError> {
    if label.is_empty() || label.len() > 63 {
        return Err(ProofInputError::InvalidDnsName);
    }
    labels.push(std::mem::take(label));
    Ok(())
}
