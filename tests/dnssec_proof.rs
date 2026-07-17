#[path = "../src/dnssec_proof.rs"]
mod dnssec_proof;

use dnssec_proof::{
    AggressiveCacheEligibility, DenialSynthesis, DnssecOwnerState, DnssecProofInput,
    DnssecProofKind, DnssecProofWarning, Nsec3Proof, NsecProof, TYPE_NSEC, TYPE_NXNAME, TYPE_RRSIG,
    classify_dnssec_proof, nsec_interval_covers, nsec3_interval_covers,
};
use std::collections::BTreeSet;

fn bitmap(values: &[u16]) -> BTreeSet<u16> {
    values.iter().copied().collect()
}

fn conventional_nsec(owner: &str, next_name: &str) -> NsecProof {
    NsecProof {
        owner: owner.to_owned(),
        next_name: next_name.to_owned(),
        type_bitmap: bitmap(&[TYPE_RRSIG, TYPE_NSEC]),
        signature_validated: true,
        synthesis: DenialSynthesis::Conventional,
    }
}

#[test]
fn validated_nsec_nxname_is_exact_nonexistence_never_range_cache() {
    let input = DnssecProofInput {
        qname: "missing.example.com".to_owned(),
        qtype: 1,
        nsec: vec![NsecProof {
            owner: "missing.example.com.".to_owned(),
            next_name: "\\000.missing.example.com.".to_owned(),
            type_bitmap: bitmap(&[TYPE_RRSIG, TYPE_NSEC, TYPE_NXNAME]),
            signature_validated: true,
            synthesis: DenialSynthesis::Compact,
        }],
        ..DnssecProofInput::default()
    };

    let result = classify_dnssec_proof(&input);
    assert_eq!(result.state, DnssecOwnerState::DoesNotExist);
    assert!(result.proofs.contains(&DnssecProofKind::NxnameNsec));
    assert!(result.compact_denial_seen);
    assert!(!result.live_eligible);
    assert_eq!(result.aggressive_cache, AggressiveCacheEligibility::Never);
}

#[test]
fn unvalidated_nxname_is_ignored() {
    let input = DnssecProofInput {
        qname: "missing.example.com".to_owned(),
        qtype: 1,
        nsec: vec![NsecProof {
            owner: "missing.example.com".to_owned(),
            next_name: "\\000.missing.example.com".to_owned(),
            type_bitmap: bitmap(&[TYPE_NXNAME]),
            signature_validated: false,
            synthesis: DenialSynthesis::Compact,
        }],
        ..DnssecProofInput::default()
    };

    let result = classify_dnssec_proof(&input);
    assert_eq!(result.state, DnssecOwnerState::Inconclusive);
    assert!(
        result
            .warnings
            .contains(&DnssecProofWarning::UnvalidatedEvidenceIgnored)
    );
    assert!(!result.compact_denial_seen);
}

#[test]
fn rrsig_labels_equality_alone_never_proves_owner() {
    let result = classify_dnssec_proof(&DnssecProofInput {
        qname: "maybe.example.com".to_owned(),
        qtype: 1,
        rrsig_labels_equal: true,
        ..DnssecProofInput::default()
    });

    assert_eq!(result.state, DnssecOwnerState::Inconclusive);
    assert!(!result.live_eligible);
    assert!(
        result
            .warnings
            .contains(&DnssecProofWarning::RrsigLabelsEqualityIgnored)
    );
}

#[test]
fn conventional_nsec_exact_owner_proves_existence() {
    let result = classify_dnssec_proof(&DnssecProofInput {
        qname: "mail.example.com".to_owned(),
        qtype: 1,
        nsec: vec![conventional_nsec("MAIL.EXAMPLE.COM.", "next.example.com.")],
        ..DnssecProofInput::default()
    });

    assert_eq!(result.state, DnssecOwnerState::Exists);
    assert!(result.live_eligible);
    assert_eq!(
        result.aggressive_cache,
        AggressiveCacheEligibility::ExactName
    );
}

#[test]
fn conventional_nsec_interval_denial_is_range_cacheable() {
    let result = classify_dnssec_proof(&DnssecProofInput {
        qname: "m.example.com".to_owned(),
        qtype: 1,
        nsec: vec![conventional_nsec("a.example.com", "z.example.com")],
        ..DnssecProofInput::default()
    });

    assert_eq!(result.state, DnssecOwnerState::DoesNotExist);
    assert!(result.proofs.contains(&DnssecProofKind::NsecRangeDenial));
    assert_eq!(result.aggressive_cache, AggressiveCacheEligibility::Range);
}

#[test]
fn nsec_canonical_order_handles_wrap_and_escaped_octets() {
    assert!(nsec_interval_covers("z.example", "b.example", "zz.example").unwrap());
    assert!(nsec_interval_covers("z.example", "b.example", "a.example").unwrap());
    assert!(!nsec_interval_covers("z.example", "b.example", "m.example").unwrap());
    // RFC 9824's leading zero label is the immediate canonical successor, so
    // the compact interval contains no reusable range.
    assert!(
        !nsec_interval_covers(
            "missing.example",
            "\\000.missing.example",
            "missing\\000.example"
        )
        .unwrap()
    );
}

#[test]
fn ambiguous_compact_nodata_is_not_promoted() {
    let result = classify_dnssec_proof(&DnssecProofInput {
        qname: "maybe.example.com".to_owned(),
        qtype: 1,
        nsec: vec![NsecProof {
            owner: "maybe.example.com".to_owned(),
            next_name: "\\000.maybe.example.com".to_owned(),
            type_bitmap: bitmap(&[TYPE_RRSIG, TYPE_NSEC]),
            signature_validated: true,
            synthesis: DenialSynthesis::Compact,
        }],
        ..DnssecProofInput::default()
    });

    assert_eq!(result.state, DnssecOwnerState::Inconclusive);
    assert_eq!(result.aggressive_cache, AggressiveCacheEligibility::Never);
    assert!(
        result
            .warnings
            .contains(&DnssecProofWarning::AmbiguousCompactNodata)
    );
}

#[test]
fn ent_nodata_is_traversal_only_and_never_live() {
    let result = classify_dnssec_proof(&DnssecProofInput {
        qname: "branch.example.com".to_owned(),
        qtype: 1,
        validated_ent_nodata: true,
        nsec: vec![conventional_nsec("branch.example.com", "next.example.com")],
        ..DnssecProofInput::default()
    });

    assert_eq!(result.state, DnssecOwnerState::EmptyNonTerminal);
    assert!(result.traversal_hint);
    assert!(!result.live_eligible);
    assert_eq!(result.aggressive_cache, AggressiveCacheEligibility::Never);
}

#[test]
fn exact_owner_with_queried_type_is_not_negative_cache_evidence() {
    let mut proof = conventional_nsec("mail.example", "next.example");
    proof.type_bitmap.insert(1);
    let result = classify_dnssec_proof(&DnssecProofInput {
        qname: "mail.example".to_owned(),
        qtype: 1,
        nsec: vec![proof],
        ..DnssecProofInput::default()
    });

    assert_eq!(result.state, DnssecOwnerState::Exists);
    assert_eq!(result.aggressive_cache, AggressiveCacheEligibility::Never);
}

#[test]
fn conventional_nsec3_exact_and_range_are_classified() {
    let exact = classify_dnssec_proof(&DnssecProofInput {
        qname: "exact.example".to_owned(),
        qtype: 1,
        nsec3: vec![Nsec3Proof {
            owner_hash: "A000".to_owned(),
            next_hash: "F000".to_owned(),
            qname_hash: "a000".to_owned(),
            type_bitmap: bitmap(&[1, TYPE_RRSIG]),
            signature_validated: true,
            opt_out: false,
            synthesis: DenialSynthesis::Conventional,
        }],
        ..DnssecProofInput::default()
    });
    assert_eq!(exact.state, DnssecOwnerState::Exists);
    assert!(exact.proofs.contains(&DnssecProofKind::Nsec3ExactOwner));

    let denied = classify_dnssec_proof(&DnssecProofInput {
        qname: "denied.example".to_owned(),
        qtype: 1,
        nsec3: vec![Nsec3Proof {
            owner_hash: "A000".to_owned(),
            next_hash: "F000".to_owned(),
            qname_hash: "B000".to_owned(),
            type_bitmap: bitmap(&[TYPE_RRSIG]),
            signature_validated: true,
            opt_out: false,
            synthesis: DenialSynthesis::Conventional,
        }],
        ..DnssecProofInput::default()
    });
    assert_eq!(denied.state, DnssecOwnerState::DoesNotExist);
    assert_eq!(denied.aggressive_cache, AggressiveCacheEligibility::Range);
}

#[test]
fn nsec3_opt_out_range_does_not_prove_nonexistence() {
    let result = classify_dnssec_proof(&DnssecProofInput {
        qname: "delegation.example".to_owned(),
        qtype: 1,
        nsec3: vec![Nsec3Proof {
            owner_hash: "A000".to_owned(),
            next_hash: "F000".to_owned(),
            qname_hash: "B000".to_owned(),
            type_bitmap: BTreeSet::new(),
            signature_validated: true,
            opt_out: true,
            synthesis: DenialSynthesis::Conventional,
        }],
        ..DnssecProofInput::default()
    });

    assert_eq!(result.state, DnssecOwnerState::Inconclusive);
    assert!(
        result
            .warnings
            .contains(&DnssecProofWarning::Nsec3OptOutCoverageIgnored)
    );
}

#[test]
fn validated_nsec3_nxname_never_enters_aggressive_cache() {
    let result = classify_dnssec_proof(&DnssecProofInput {
        qname: "missing.example".to_owned(),
        qtype: 1,
        nsec3: vec![Nsec3Proof {
            owner_hash: "A000".to_owned(),
            next_hash: "A001".to_owned(),
            qname_hash: "A000".to_owned(),
            type_bitmap: bitmap(&[TYPE_NXNAME]),
            signature_validated: true,
            opt_out: false,
            synthesis: DenialSynthesis::Compact,
        }],
        ..DnssecProofInput::default()
    });

    assert_eq!(result.state, DnssecOwnerState::DoesNotExist);
    assert!(result.proofs.contains(&DnssecProofKind::NxnameNsec3));
    assert_eq!(result.aggressive_cache, AggressiveCacheEligibility::Never);
}

#[test]
fn contradictory_validated_proofs_fail_closed() {
    let result = classify_dnssec_proof(&DnssecProofInput {
        qname: "conflict.example".to_owned(),
        qtype: 1,
        validated_exact_positive_answer: true,
        nsec: vec![NsecProof {
            owner: "conflict.example".to_owned(),
            next_name: "\\000.conflict.example".to_owned(),
            type_bitmap: bitmap(&[TYPE_NXNAME]),
            signature_validated: true,
            synthesis: DenialSynthesis::Compact,
        }],
        ..DnssecProofInput::default()
    });

    assert_eq!(result.state, DnssecOwnerState::Inconclusive);
    assert!(!result.live_eligible);
    assert_eq!(result.aggressive_cache, AggressiveCacheEligibility::Never);
    assert!(
        result
            .warnings
            .contains(&DnssecProofWarning::ConflictingValidatedProofs)
    );
}

#[test]
fn nsec3_interval_validation_rejects_bad_or_mismatched_hashes() {
    assert!(nsec3_interval_covers("A000", "F000", "B000").unwrap());
    assert!(nsec3_interval_covers("V000", "2000", "0000").unwrap());
    assert!(nsec3_interval_covers("A000", "F000", "W000").is_err());
    assert!(nsec3_interval_covers("A000", "F00", "B000").is_err());
}

#[test]
fn assessment_is_json_roundtrip_safe() {
    let result = classify_dnssec_proof(&DnssecProofInput {
        qname: "mail.example".to_owned(),
        qtype: 1,
        validated_exact_positive_answer: true,
        ..DnssecProofInput::default()
    });
    let encoded = serde_json::to_string(&result).unwrap();
    let decoded = serde_json::from_str(&encoded).unwrap();
    assert_eq!(result, decoded);
}
