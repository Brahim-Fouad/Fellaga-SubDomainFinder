use crate::model::{ConfidenceAssessment, EvidenceFamily, ObservationState};
use std::collections::BTreeSet;

pub fn evidence_family(source: &str) -> Option<EvidenceFamily> {
    let source = source.to_ascii_lowercase();
    if source == "authoritative-validation"
        || source.starts_with("axfr:")
        || source.starts_with("dnssec-nsec:")
    {
        return Some(EvidenceFamily::Authoritative);
    }
    if source == "dns"
        || source == "refresh"
        || source.starts_with("refresh:wildcard")
        || source.starts_with("dns-wave-")
        || source.starts_with("dns-recursive")
        || source.starts_with("dns-graph:")
    {
        return Some(EvidenceFamily::LiveDns);
    }
    if source.starts_with("tls-cert:") {
        return Some(EvidenceFamily::CertificateTransparency);
    }
    if source.starts_with("web:") {
        return Some(EvidenceFamily::WebCrawl);
    }

    if let Some(passive_source) = source.strip_prefix("passive:") {
        let connector = passive_source.split(':').next().unwrap_or_default();
        if matches!(connector, "ct-direct" | "google-ct") {
            return Some(EvidenceFamily::CertificateTransparency);
        }
        return crate::passive::passive_source_evidence_family(connector);
    }
    None
}

pub fn evidence_families(sources: &BTreeSet<String>) -> BTreeSet<EvidenceFamily> {
    sources
        .iter()
        .filter_map(|source| evidence_family(source))
        .collect()
}

pub fn assess_with_state(
    sources: &BTreeSet<String>,
    wildcard: bool,
    state: ObservationState,
) -> ConfidenceAssessment {
    assess_with_context(sources, wildcard, state, state == ObservationState::Live)
}

pub fn assess_with_context(
    sources: &BTreeSet<String>,
    wildcard: bool,
    state: ObservationState,
    observed_this_scan: bool,
) -> ConfidenceAssessment {
    let mut score = 30_i32;
    let mut reasons = Vec::new();
    match state {
        ObservationState::Live => {
            if observed_this_scan {
                score += 15;
                reasons.push("réponse DNS observée pendant ce scan".to_owned());
            } else {
                score += 8;
                reasons.push("validation DNS en cache encore fraîche".to_owned());
            }
        }
        ObservationState::Historical => {
            score -= 5;
            reasons
                .push("réponse DNS positive historique, non revalidée pendant ce scan".to_owned());
        }
        ObservationState::Unverified => {
            score -= 15;
            reasons.push("nom découvert mais pas encore validé par DNS".to_owned());
        }
    }

    let families = evidence_families(sources);
    let corroborating = families
        .iter()
        .filter(|family| **family != EvidenceFamily::LiveDns)
        .count();
    if corroborating > 0 {
        score += (corroborating.min(3) * 10) as i32;
        reasons.push(format!(
            "{} famille(s) de preuves indépendante(s)",
            corroborating
        ));
    }

    if families.contains(&EvidenceFamily::Authoritative) {
        score += 25;
        reasons.push("preuve issue de la zone autoritaire".to_owned());
    }
    if families.contains(&EvidenceFamily::CertificateTransparency) {
        score += 10;
        reasons.push("preuve Certificate Transparency ou certificat TLS".to_owned());
    }
    if families.contains(&EvidenceFamily::WebArchive) {
        score += 8;
        reasons.push("référence dans une archive Web".to_owned());
    }
    if families.contains(&EvidenceFamily::WebCrawl) {
        score += 8;
        reasons.push("référence Web ou JavaScript".to_owned());
    }
    if families.contains(&EvidenceFamily::PassiveDns) {
        score += 10;
        reasons.push("observation DNS passive".to_owned());
    }

    if wildcard {
        score -= 35;
        reasons.push("correspond à une signature wildcard".to_owned());
    } else {
        score += 10;
        reasons.push("ne correspond pas au wildcard connu".to_owned());
    }

    let score = score.clamp(0, 100) as u8;
    let label = match score {
        85..=100 => "confirmé",
        65..=84 => "fort",
        45..=64 => "probable",
        _ => "faible",
    }
    .to_owned();
    ConfidenceAssessment {
        score,
        label,
        reasons,
    }
}

pub fn assess(
    sources: &BTreeSet<String>,
    wildcard: bool,
    from_cache: bool,
) -> ConfidenceAssessment {
    let state = if from_cache {
        ObservationState::Historical
    } else {
        ObservationState::Live
    };
    assess_with_state(sources, wildcard, state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlated_ct_providers_count_as_one_family() {
        let ct = BTreeSet::from([
            "passive:crtsh".to_owned(),
            "passive:certspotter".to_owned(),
            "passive:ct-direct".to_owned(),
        ]);
        assert_eq!(
            evidence_families(&ct),
            BTreeSet::from([EvidenceFamily::CertificateTransparency])
        );

        let diverse = BTreeSet::from([
            "passive:crtsh".to_owned(),
            "passive:wayback".to_owned(),
            "passive:securitytrails".to_owned(),
        ]);
        assert!(
            assess_with_state(&diverse, false, ObservationState::Live).score
                > assess_with_state(&ct, false, ObservationState::Live).score
        );
    }

    #[test]
    fn targeted_connectors_use_independent_evidence_families() {
        assert_eq!(
            evidence_family("passive:binaryedge"),
            Some(EvidenceFamily::PassiveDns)
        );
        assert_eq!(
            evidence_family("passive:merklemap"),
            Some(EvidenceFamily::CertificateTransparency)
        );
        assert_eq!(
            evidence_family("passive:driftnet"),
            Some(EvidenceFamily::Aggregator)
        );
        assert_eq!(
            evidence_family("passive:brave"),
            Some(EvidenceFamily::WebCrawl)
        );
        assert_eq!(
            evidence_family("passive:shodanct"),
            Some(EvidenceFamily::CertificateTransparency)
        );
        assert_eq!(
            evidence_family("passive:digitorus"),
            Some(EvidenceFamily::CertificateTransparency)
        );
        assert_eq!(
            evidence_family("passive:censys"),
            Some(EvidenceFamily::CertificateTransparency)
        );
        assert_eq!(
            evidence_family("passive:thc"),
            Some(EvidenceFamily::PassiveDns)
        );
        assert_eq!(
            evidence_family("passive:dnsdb"),
            Some(EvidenceFamily::PassiveDns)
        );
        assert_eq!(
            evidence_family("passive:submd"),
            Some(EvidenceFamily::Aggregator)
        );
        assert_eq!(
            evidence_family("passive:waybackarchive"),
            Some(EvidenceFamily::WebArchive)
        );
        assert_eq!(
            evidence_family("passive:postman"),
            Some(EvidenceFamily::CodeSearch)
        );
        assert_eq!(
            evidence_family("passive:viewdns"),
            Some(EvidenceFamily::PassiveDns)
        );
    }

    #[test]
    fn every_registered_connector_uses_its_typed_registry_family() {
        for status in crate::passive::source_statuses(&crate::passive::ApiKeyStore::default()) {
            let source = format!("passive:{}", status.name);
            let qualified = format!("{source}:cache");
            assert_eq!(
                evidence_family(&source),
                Some(status.metadata.evidence_family),
                "{}",
                status.name
            );
            assert_eq!(
                evidence_family(&qualified),
                Some(status.metadata.evidence_family),
                "{} qualified provenance",
                status.name
            );
        }
    }

    #[test]
    fn unknown_or_prefix_colliding_passive_names_have_no_evidence_family() {
        assert_eq!(evidence_family("passive:unknown-source"), None);
        assert_eq!(evidence_family("passive:crtsh-lookalike"), None);
        assert_eq!(evidence_family("passive:github-lookalike:cache"), None);
        assert_eq!(evidence_family("passive:"), None);
    }

    #[test]
    fn historical_and_wildcard_observations_are_downgraded() {
        let sources = BTreeSet::from([
            "passive:crtsh".to_owned(),
            "passive:urlscan".to_owned(),
            "web:https://www.example.com/".to_owned(),
        ]);
        let live = assess_with_state(&sources, false, ObservationState::Live);
        let historical = assess_with_state(&sources, false, ObservationState::Historical);
        let wildcard = assess_with_state(&sources, true, ObservationState::Live);
        assert!(historical.score < live.score);
        assert!(wildcard.score < live.score);
        assert!(
            historical
                .reasons
                .iter()
                .any(|reason| reason.contains("historique"))
        );
    }
}
