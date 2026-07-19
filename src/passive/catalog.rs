//! Compile-time catalog for passive discovery connectors.
//!
//! This module is deliberately independent from credentials, HTTP transport,
//! pagination persistence, and connector execution.  Keeping every static
//! source property in one place prevents scheduling, evidence, and transport
//! policy from drifting apart as connectors evolve.

use crate::model::EvidenceFamily;
use anyhow::{Result, bail};
use serde::Serialize;
use std::collections::BTreeSet;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct SourceMetadata {
    pub name: String,
    pub available: bool,
    pub unavailable_reason: Option<&'static str>,
    pub evidence_family: EvidenceFamily,
    pub pagination: PaginationCapability,
    pub recursive_children: bool,
    pub recursive_parents: bool,
    pub cost: &'static str,
    pub authentication: &'static str,
    pub rate_limit_per_minute: u32,
    pub experimental: bool,
    pub documented: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum SourceId {
    AnubisDb,
    ArquivoPt,
    Bevigil,
    BinaryEdge,
    Brave,
    BuiltWith,
    Censys,
    CertificateDetails,
    CertSpotter,
    Chaos,
    CommonCrawl,
    Circl,
    CrtSh,
    DriftNet,
    FullHunt,
    Github,
    Gitlab,
    HackerTarget,
    IntelX,
    LeakIx,
    MerkleMap,
    Netlas,
    Otx,
    SecurityTrails,
    Shodan,
    ShrewdEye,
    SubdomainCenter,
    SubdomainApp,
    Urlscan,
    VirusTotal,
    ViewDns,
    WhoisXml,
    Wayback,
    AlienVault,
    Anubis,
    BufferOver,
    C99,
    Chinaz,
    DigitalYama,
    Digitorus,
    DnsDb,
    DnsDumpster,
    DnsRepo,
    DomainsProject,
    Fofa,
    HudsonRock,
    Onyphe,
    Postman,
    Profundis,
    PugRecon,
    Quake,
    RapidDns,
    ReconCloud,
    Reconeer,
    RedHuntLabs,
    Riddler,
    Robtex,
    RseCloud,
    ShodanCt,
    SiteDossier,
    SubMd,
    Thc,
    ThreatBook,
    ThreatCrowd,
    ThreatMiner,
    WaybackArchive,
    WhoisXmlApi,
    WindVane,
    ZoomEyeApi,
}

impl SourceId {
    pub(super) const fn implementation(self) -> Self {
        match self {
            Self::CertificateDetails => Self::Digitorus,
            Self::Otx => Self::AlienVault,
            Self::Wayback => Self::WaybackArchive,
            Self::WhoisXml => Self::WhoisXmlApi,
            implementation => implementation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaginationCapability {
    None,
    Numeric,
    FixedOffset,
    OpaqueReplay,
    StreamingReplay,
    AsyncPolling,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SourceDefinition {
    pub(super) id: SourceId,
    pub(super) name: &'static str,
    pub(super) evidence_family: EvidenceFamily,
    pub(super) pagination: PaginationCapability,
    pub(super) requires_key: bool,
    pub(super) key_environment: Option<&'static str>,
    pub(super) environment_names: &'static [&'static str],
    pub(super) key_aliases: &'static [&'static str],
    pub(super) automatic: bool,
}

impl SourceId {
    pub(super) const fn evidence_family(self) -> EvidenceFamily {
        match self {
            Self::Censys
            | Self::CertificateDetails
            | Self::CertSpotter
            | Self::CrtSh
            | Self::Digitorus
            | Self::MerkleMap
            | Self::ShodanCt => EvidenceFamily::CertificateTransparency,
            Self::Otx
            | Self::AlienVault
            | Self::Bevigil
            | Self::BinaryEdge
            | Self::BufferOver
            | Self::C99
            | Self::Chaos
            | Self::Circl
            | Self::DnsDb
            | Self::DnsDumpster
            | Self::DnsRepo
            | Self::FullHunt
            | Self::LeakIx
            | Self::Netlas
            | Self::Onyphe
            | Self::Robtex
            | Self::RseCloud
            | Self::SecurityTrails
            | Self::Shodan
            | Self::Thc
            | Self::ThreatBook
            | Self::ViewDns
            | Self::VirusTotal
            | Self::WhoisXml
            | Self::WhoisXmlApi => EvidenceFamily::PassiveDns,
            Self::ArquivoPt | Self::Wayback | Self::WaybackArchive => EvidenceFamily::WebArchive,
            Self::Brave | Self::CommonCrawl | Self::Urlscan => EvidenceFamily::WebCrawl,
            Self::Github | Self::Gitlab | Self::Postman => EvidenceFamily::CodeSearch,
            Self::AnubisDb
            | Self::BuiltWith
            | Self::DriftNet
            | Self::HackerTarget
            | Self::IntelX
            | Self::SubdomainCenter
            | Self::SubdomainApp
            | Self::Anubis
            | Self::Chinaz
            | Self::DigitalYama
            | Self::DomainsProject
            | Self::Fofa
            | Self::HudsonRock
            | Self::Profundis
            | Self::PugRecon
            | Self::Quake
            | Self::RapidDns
            | Self::ReconCloud
            | Self::Reconeer
            | Self::RedHuntLabs
            | Self::Riddler
            | Self::ShrewdEye
            | Self::SiteDossier
            | Self::SubMd
            | Self::ThreatCrowd
            | Self::ThreatMiner
            | Self::WindVane
            | Self::ZoomEyeApi => EvidenceFamily::Aggregator,
        }
    }
}

macro_rules! define_sources {
    ($(
        $variant:ident {
            name: $name:literal,
            pagination: $pagination:expr,
            requires_key: $requires_key:literal,
            key_environment: $key_environment:expr,
            environment_names: $environment_names:expr,
            key_aliases: $key_aliases:expr,
            automatic: $automatic:literal
        }
    ),+ $(,)?) => {
        impl SourceId {
            pub(super) const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub(super) const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name),+
                }
            }

            pub(super) const fn definition(self) -> SourceDefinition {
                match self {
                    $(Self::$variant => SourceDefinition {
                        id: self,
                        name: $name,
                        evidence_family: self.evidence_family(),
                        pagination: $pagination,
                        requires_key: $requires_key,
                        key_environment: $key_environment,
                        environment_names: $environment_names,
                        key_aliases: $key_aliases,
                        automatic: $automatic,
                    }),+
                }
            }

            pub(super) fn parse(name: &str) -> Option<Self> {
                match name {
                    $($name => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        pub(super) const SOURCE_DEFINITIONS: &[SourceDefinition] = &[
            $(SourceId::$variant.definition()),+
        ];
    };
}

define_sources! {
    AnubisDb { name: "anubisdb", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    ArquivoPt { name: "arquivopt", pagination: PaginationCapability::StreamingReplay, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    Bevigil { name: "bevigil", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("BEVIGIL_API_KEY"), environment_names: &["BEVIGIL_API_KEY"], key_aliases: &[], automatic: true },
    BinaryEdge { name: "binaryedge", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("BINARYEDGE_API_KEY"), environment_names: &["BINARYEDGE_API_KEY"], key_aliases: &[], automatic: false },
    Brave { name: "brave", pagination: PaginationCapability::FixedOffset, requires_key: true, key_environment: Some("BRAVE_SEARCH_API_KEY"), environment_names: &["BRAVE_SEARCH_API_KEY"], key_aliases: &[], automatic: true },
    BuiltWith { name: "builtwith", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("BUILTWITH_API_KEY"), environment_names: &["BUILTWITH_API_KEY"], key_aliases: &[], automatic: true },
    Censys { name: "censys", pagination: PaginationCapability::OpaqueReplay, requires_key: true, key_environment: Some("CENSYS_API_KEY"), environment_names: &["CENSYS_API_KEY"], key_aliases: &[], automatic: true },
    CertificateDetails { name: "certificatedetails", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: false },
    CertSpotter { name: "certspotter", pagination: PaginationCapability::OpaqueReplay, requires_key: false, key_environment: Some("CERTSPOTTER_API_TOKEN"), environment_names: &["CERTSPOTTER_API_TOKEN", "CERTSPOTTER_API_KEY"], key_aliases: &[], automatic: true },
    Chaos { name: "chaos", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("PDCP_API_KEY"), environment_names: &["PDCP_API_KEY", "CHAOS_API_KEY"], key_aliases: &[], automatic: true },
    CommonCrawl { name: "commoncrawl", pagination: PaginationCapability::Numeric, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    Circl { name: "circl", pagination: PaginationCapability::StreamingReplay, requires_key: true, key_environment: Some("CIRCL_PDNS_CREDENTIALS"), environment_names: &["CIRCL_PDNS_CREDENTIALS"], key_aliases: &[], automatic: true },
    CrtSh { name: "crtsh", pagination: PaginationCapability::StreamingReplay, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    DriftNet { name: "driftnet", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("DRIFTNET_API_KEY"), environment_names: &["DRIFTNET_API_KEY"], key_aliases: &[], automatic: true },
    FullHunt { name: "fullhunt", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("FULLHUNT_API_KEY"), environment_names: &["FULLHUNT_API_KEY"], key_aliases: &[], automatic: true },
    Github { name: "github", pagination: PaginationCapability::OpaqueReplay, requires_key: true, key_environment: Some("GITHUB_TOKEN"), environment_names: &["GITHUB_TOKEN", "GITHUB_TOKENS"], key_aliases: &[], automatic: true },
    Gitlab { name: "gitlab", pagination: PaginationCapability::OpaqueReplay, requires_key: true, key_environment: Some("GITLAB_TOKEN"), environment_names: &["GITLAB_TOKEN"], key_aliases: &[], automatic: true },
    HackerTarget { name: "hackertarget", pagination: PaginationCapability::None, requires_key: false, key_environment: Some("HACKERTARGET_API_KEY"), environment_names: &["HACKERTARGET_API_KEY"], key_aliases: &[], automatic: true },
    IntelX { name: "intelx", pagination: PaginationCapability::AsyncPolling, requires_key: true, key_environment: Some("INTELX_API_KEY"), environment_names: &["INTELX_API_KEY"], key_aliases: &[], automatic: true },
    LeakIx { name: "leakix", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("LEAKIX_API_KEY"), environment_names: &["LEAKIX_API_KEY"], key_aliases: &[], automatic: true },
    MerkleMap { name: "merklemap", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("MERKLEMAP_API_TOKEN"), environment_names: &["MERKLEMAP_API_TOKEN", "MERKLEMAP_API_KEY"], key_aliases: &[], automatic: true },
    Netlas { name: "netlas", pagination: PaginationCapability::StreamingReplay, requires_key: true, key_environment: Some("NETLAS_API_KEY"), environment_names: &["NETLAS_API_KEY"], key_aliases: &[], automatic: true },
    Otx { name: "otx", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("OTX_API_KEY"), environment_names: &["OTX_API_KEY", "X_OTX_API_KEY"], key_aliases: &["alienvault"], automatic: false },
    SecurityTrails { name: "securitytrails", pagination: PaginationCapability::OpaqueReplay, requires_key: true, key_environment: Some("SECURITYTRAILS_API_KEY"), environment_names: &["SECURITYTRAILS_API_KEY"], key_aliases: &[], automatic: true },
    Shodan { name: "shodan", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("SHODAN_API_KEY"), environment_names: &["SHODAN_API_KEY"], key_aliases: &[], automatic: true },
    ShrewdEye { name: "shrewdeye", pagination: PaginationCapability::StreamingReplay, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    SubdomainCenter { name: "subdomaincenter", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    SubdomainApp { name: "subdomainapp", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    Urlscan { name: "urlscan", pagination: PaginationCapability::OpaqueReplay, requires_key: false, key_environment: Some("URLSCAN_API_KEY"), environment_names: &["URLSCAN_API_KEY"], key_aliases: &[], automatic: true },
    VirusTotal { name: "virustotal", pagination: PaginationCapability::OpaqueReplay, requires_key: true, key_environment: Some("VIRUSTOTAL_API_KEY"), environment_names: &["VIRUSTOTAL_API_KEY"], key_aliases: &[], automatic: true },
    ViewDns { name: "viewdns", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("VIEWDNS_API_KEY"), environment_names: &["VIEWDNS_API_KEY"], key_aliases: &[], automatic: true },
    WhoisXml { name: "whoisxml", pagination: PaginationCapability::OpaqueReplay, requires_key: true, key_environment: Some("WHOISXML_API_KEY"), environment_names: &["WHOISXML_API_KEY"], key_aliases: &["whoisxmlapi"], automatic: false },
    Wayback { name: "wayback", pagination: PaginationCapability::OpaqueReplay, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: false },
    AlienVault { name: "alienvault", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("ALIENVAULT_API_KEY"), environment_names: &["ALIENVAULT_API_KEY", "OTX_API_KEY", "X_OTX_API_KEY"], key_aliases: &["otx"], automatic: true },
    Anubis { name: "anubis", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    BufferOver { name: "bufferover", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("BUFFEROVER_API_KEY"), environment_names: &["BUFFEROVER_API_KEY"], key_aliases: &[], automatic: true },
    C99 { name: "c99", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("C99_API_KEY"), environment_names: &["C99_API_KEY"], key_aliases: &[], automatic: true },
    Chinaz { name: "chinaz", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("CHINAZ_API_KEY"), environment_names: &["CHINAZ_API_KEY"], key_aliases: &[], automatic: true },
    DigitalYama { name: "digitalyama", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("DIGITALYAMA_API_KEY"), environment_names: &["DIGITALYAMA_API_KEY"], key_aliases: &[], automatic: true },
    Digitorus { name: "digitorus", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    DnsDb { name: "dnsdb", pagination: PaginationCapability::FixedOffset, requires_key: true, key_environment: Some("DNSDB_API_KEY"), environment_names: &["DNSDB_API_KEY"], key_aliases: &[], automatic: true },
    DnsDumpster { name: "dnsdumpster", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("DNSDUMPSTER_API_KEY"), environment_names: &["DNSDUMPSTER_API_KEY"], key_aliases: &[], automatic: true },
    DnsRepo { name: "dnsrepo", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("DNSREPO_API_KEY"), environment_names: &["DNSREPO_API_KEY"], key_aliases: &[], automatic: true },
    DomainsProject { name: "domainsproject", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("DOMAINSPROJECT_API_KEY"), environment_names: &["DOMAINSPROJECT_API_KEY"], key_aliases: &[], automatic: true },
    Fofa { name: "fofa", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("FOFA_API_KEY"), environment_names: &["FOFA_API_KEY"], key_aliases: &[], automatic: true },
    HudsonRock { name: "hudsonrock", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    Onyphe { name: "onyphe", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("ONYPHE_API_KEY"), environment_names: &["ONYPHE_API_KEY"], key_aliases: &[], automatic: true },
    Postman { name: "postman", pagination: PaginationCapability::OpaqueReplay, requires_key: false, key_environment: Some("POSTMAN_API_KEY"), environment_names: &["POSTMAN_API_KEY"], key_aliases: &[], automatic: true },
    Profundis { name: "profundis", pagination: PaginationCapability::StreamingReplay, requires_key: true, key_environment: Some("PROFUNDIS_API_KEY"), environment_names: &["PROFUNDIS_API_KEY"], key_aliases: &[], automatic: true },
    PugRecon { name: "pugrecon", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("PUGRECON_API_KEY"), environment_names: &["PUGRECON_API_KEY"], key_aliases: &[], automatic: true },
    Quake { name: "quake", pagination: PaginationCapability::FixedOffset, requires_key: true, key_environment: Some("QUAKE_API_KEY"), environment_names: &["QUAKE_API_KEY"], key_aliases: &[], automatic: true },
    RapidDns { name: "rapiddns", pagination: PaginationCapability::Numeric, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    ReconCloud { name: "reconcloud", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    Reconeer { name: "reconeer", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("RECONEER_API_KEY"), environment_names: &["RECONEER_API_KEY"], key_aliases: &[], automatic: true },
    RedHuntLabs { name: "redhuntlabs", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("REDHUNTLABS_API_KEY"), environment_names: &["REDHUNTLABS_API_KEY"], key_aliases: &[], automatic: true },
    Riddler { name: "riddler", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    Robtex { name: "robtex", pagination: PaginationCapability::StreamingReplay, requires_key: true, key_environment: Some("ROBTEX_API_KEY"), environment_names: &["ROBTEX_API_KEY"], key_aliases: &[], automatic: true },
    RseCloud { name: "rsecloud", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("RSECLOUD_API_KEY"), environment_names: &["RSECLOUD_API_KEY"], key_aliases: &[], automatic: true },
    ShodanCt { name: "shodanct", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    SiteDossier { name: "sitedossier", pagination: PaginationCapability::OpaqueReplay, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    SubMd { name: "submd", pagination: PaginationCapability::StreamingReplay, requires_key: false, key_environment: Some("SUBMD_API_KEY"), environment_names: &["SUBMD_API_KEY"], key_aliases: &[], automatic: true },
    Thc { name: "thc", pagination: PaginationCapability::OpaqueReplay, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    ThreatBook { name: "threatbook", pagination: PaginationCapability::None, requires_key: true, key_environment: Some("THREATBOOK_API_KEY"), environment_names: &["THREATBOOK_API_KEY"], key_aliases: &[], automatic: true },
    ThreatCrowd { name: "threatcrowd", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    ThreatMiner { name: "threatminer", pagination: PaginationCapability::None, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    WaybackArchive { name: "waybackarchive", pagination: PaginationCapability::OpaqueReplay, requires_key: false, key_environment: None, environment_names: &[], key_aliases: &[], automatic: true },
    WhoisXmlApi { name: "whoisxmlapi", pagination: PaginationCapability::OpaqueReplay, requires_key: true, key_environment: Some("WHOISXMLAPI_API_KEY"), environment_names: &["WHOISXMLAPI_API_KEY", "WHOISXML_API_KEY"], key_aliases: &["whoisxml"], automatic: true },
    WindVane { name: "windvane", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("WINDVANE_API_KEY"), environment_names: &["WINDVANE_API_KEY"], key_aliases: &[], automatic: true },
    ZoomEyeApi { name: "zoomeyeapi", pagination: PaginationCapability::Numeric, requires_key: true, key_environment: Some("ZOOMEYEAPI_API_KEY"), environment_names: &["ZOOMEYEAPI_API_KEY", "ZOOMEYE_API_KEY"], key_aliases: &[], automatic: true },
}

pub(super) fn definition(source: &str) -> Option<SourceDefinition> {
    SourceId::parse(source).map(SourceId::definition)
}

pub(super) fn environment_names(source: &str) -> &'static [&'static str] {
    definition(source)
        .map(|entry| entry.environment_names)
        .unwrap_or_default()
}

fn source_unavailable_reason(source: &str) -> Option<&'static str> {
    match source {
        "binaryedge" => Some("provider service retired on 2025-03-31"),
        _ => None,
    }
}

/// Returns the compile-time evidence classification for a registered passive
/// connector. Unknown names are rejected instead of being treated as a generic
/// aggregator.
pub fn passive_source_evidence_family(name: &str) -> Option<EvidenceFamily> {
    definition(name).map(|entry| entry.evidence_family)
}

fn source_metadata_from_definition(entry: SourceDefinition) -> SourceMetadata {
    let name = entry.name;
    let evidence_family = entry.evidence_family;
    let experimental = matches!(
        name,
        "anubis"
            | "anubisdb"
            | "certificatedetails"
            | "digitorus"
            | "driftnet"
            | "hudsonrock"
            | "rapiddns"
            | "reconcloud"
            | "reconeer"
            | "riddler"
            | "shrewdeye"
            | "sitedossier"
            | "subdomainapp"
            | "subdomaincenter"
            | "threatcrowd"
            | "threatminer"
    );
    let requires_key = entry.requires_key;
    let unavailable_reason = source_unavailable_reason(name);
    let authentication = if requires_key {
        "required"
    } else if entry.key_environment.is_some() {
        "optional"
    } else {
        "none"
    };
    let cost = match name {
        "arquivopt" | "commoncrawl" | "dnsdb" | "github" | "gitlab" | "netlas" | "postman"
        | "robtex" | "shrewdeye" | "submd" | "thc" | "urlscan" | "wayback" | "waybackarchive" => {
            "high"
        }
        "crtsh" | "certspotter" | "virustotal" | "shodan" | "censys" | "whoisxml"
        | "whoisxmlapi" | "binaryedge" | "brave" | "merklemap" => "medium",
        _ => "low",
    };
    let rate_limit_per_minute = match name {
        "crtsh" => 6,
        "certspotter" => 12,
        "hackertarget" => 5,
        "commoncrawl" | "wayback" | "waybackarchive" => 10,
        "arquivopt" | "shrewdeye" => 5,
        "hudsonrock" | "rapiddns" | "reconcloud" | "riddler" | "sitedossier" | "threatcrowd"
        | "threatminer" => 5,
        "submd" => 60,
        // The public endpoint caps responses well below the requested 1,000
        // records. Five bounded page requests per second are needed to drain
        // large zones inside the passive phase without increasing concurrency.
        "thc" => 300,
        "urlscan" => 12,
        "binaryedge" | "brave" | "merklemap" => 20,
        _ if requires_key => 30,
        _ => 20,
    };
    SourceMetadata {
        name: name.to_owned(),
        available: unavailable_reason.is_none(),
        unavailable_reason,
        evidence_family,
        pagination: entry.pagination,
        // Match the recursive capabilities declared by the audited provider
        // connectors. The scanner still applies zone-yield ranking, global
        // connector budgets, and suffix filtering before querying child zones.
        // Parent lookup remains available to evidence families that can cover
        // a target which is itself a delegated sub-zone; scanner-side scope
        // filtering discards sibling names.
        recursive_children: unavailable_reason.is_none()
            && matches!(
                name,
                "alienvault"
                    | "otx"
                    | "bufferover"
                    | "certspotter"
                    | "crtsh"
                    | "digitorus"
                    | "certificatedetails"
                    | "dnsdb"
                    | "driftnet"
                    | "hackertarget"
                    | "leakix"
                    | "merklemap"
                    | "reconcloud"
                    | "securitytrails"
                    | "shodanct"
                    | "urlscan"
                    | "viewdns"
                    | "virustotal"
            ),
        recursive_parents: unavailable_reason.is_none()
            && matches!(
                evidence_family,
                EvidenceFamily::CertificateTransparency
                    | EvidenceFamily::PassiveDns
                    | EvidenceFamily::WebArchive
            ),
        cost,
        authentication,
        rate_limit_per_minute,
        experimental,
        documented: !matches!(
            name,
            "certificatedetails"
                | "digitorus"
                | "hudsonrock"
                | "rapiddns"
                | "reconcloud"
                | "riddler"
                | "shodanct"
                | "sitedossier"
                | "subdomainapp"
                | "subdomaincenter"
                | "threatcrowd"
                | "threatminer"
        ),
    }
}

/// Looks up connector metadata without inventing capabilities for an unknown
/// name. Callers that accept user-controlled source identifiers should prefer
/// this API.
pub fn try_source_metadata(name: &str) -> Option<SourceMetadata> {
    definition(name).map(source_metadata_from_definition)
}

/// Returns metadata for a connector while preserving the historical infallible
/// API. Unknown names are represented as unavailable, non-recursive entries;
/// they can never become eligible for automatic or explicit scheduling.
pub fn source_metadata(name: &str) -> SourceMetadata {
    try_source_metadata(name).unwrap_or_else(|| SourceMetadata {
        name: name.to_owned(),
        available: false,
        unavailable_reason: Some("source is not registered"),
        evidence_family: EvidenceFamily::Aggregator,
        pagination: PaginationCapability::None,
        recursive_children: false,
        recursive_parents: false,
        cost: "unknown",
        authentication: "unknown",
        rate_limit_per_minute: 0,
        experimental: false,
        documented: false,
    })
}

/// Returns metadata for every registered source, including compatibility
/// aliases, in the stable catalog order used by `sources --check`.
pub fn all_source_metadata() -> Vec<SourceMetadata> {
    SOURCE_DEFINITIONS
        .iter()
        .copied()
        .map(source_metadata_from_definition)
        .collect()
}

/// Returns every unique connector implementation, including key-gated and
/// experimental entries. Compatibility aliases remain valid when selected
/// explicitly but are omitted here to avoid duplicate provider requests.
pub fn all_unique_sources() -> Vec<String> {
    let mut seen = BTreeSet::new();
    SourceId::ALL
        .iter()
        .copied()
        .filter_map(|source| {
            let implementation = source.implementation();
            (seen.insert(implementation) && source_metadata(implementation.as_str()).available)
                .then(|| implementation.as_str().to_owned())
        })
        .collect()
}

pub fn validate_sources(sources: &[String]) -> Result<()> {
    for source in sources {
        if definition(source).is_none() {
            bail!("source passive inconnue: {source}");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePolicy {
    pub timeout: Duration,
    /// Maximum wall-clock time for the entire connector, including pagination,
    /// throttling and retries. This prevents one degraded provider from holding
    /// the whole passive phase indefinitely.
    pub total_timeout: Duration,
    pub attempts: usize,
    pub base_backoff: Duration,
}

pub fn source_policy(source: &str) -> SourcePolicy {
    match source {
        "crtsh" => SourcePolicy {
            timeout: Duration::from_secs(25),
            total_timeout: Duration::from_secs(35),
            attempts: 3,
            base_backoff: Duration::from_millis(750),
        },
        "commoncrawl" | "arquivopt" => SourcePolicy {
            timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(45),
            attempts: 2,
            base_backoff: Duration::from_secs(1),
        },
        "wayback" | "waybackarchive" => SourcePolicy {
            timeout: Duration::from_secs(45),
            total_timeout: Duration::from_secs(45),
            attempts: 1,
            base_backoff: Duration::from_secs(1),
        },
        "submd" => SourcePolicy {
            timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(45),
            attempts: 2,
            base_backoff: Duration::from_millis(750),
        },
        "shrewdeye" => SourcePolicy {
            timeout: Duration::from_secs(20),
            total_timeout: Duration::from_secs(30),
            attempts: 2,
            base_backoff: Duration::from_secs(1),
        },
        "shodan-internetdb" => SourcePolicy {
            timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(20),
            attempts: 1,
            base_backoff: Duration::from_secs(1),
        },
        "thc" => SourcePolicy {
            timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(75),
            attempts: 2,
            base_backoff: Duration::from_millis(750),
        },
        "hudsonrock" | "rapiddns" | "reconcloud" | "reconeer" | "riddler" | "shodanct"
        | "sitedossier" | "threatcrowd" | "threatminer" => SourcePolicy {
            timeout: Duration::from_secs(15),
            total_timeout: Duration::from_secs(30),
            attempts: 2,
            base_backoff: Duration::from_millis(500),
        },
        "alienvault" | "otx" => SourcePolicy {
            timeout: Duration::from_secs(20),
            total_timeout: Duration::from_secs(25),
            attempts: 2,
            base_backoff: Duration::from_secs(1),
        },
        "brave" => SourcePolicy {
            timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(35),
            attempts: 2,
            base_backoff: Duration::from_millis(500),
        },
        "binaryedge" | "merklemap" => SourcePolicy {
            timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(20),
            attempts: 2,
            base_backoff: Duration::from_millis(500),
        },
        "certspotter" | "urlscan" | "virustotal" | "shodan" | "censys" | "github" | "gitlab"
        | "postman" => SourcePolicy {
            timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(45),
            attempts: 2,
            base_backoff: Duration::from_secs(1),
        },
        _ => SourcePolicy {
            timeout: Duration::from_secs(20),
            total_timeout: Duration::from_secs(30),
            attempts: 2,
            base_backoff: Duration::from_millis(500),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_names_and_ids_are_unique_and_round_trip() {
        let names = SOURCE_DEFINITIONS
            .iter()
            .map(|definition| definition.name)
            .collect::<BTreeSet<_>>();
        let ids = SOURCE_DEFINITIONS
            .iter()
            .map(|definition| definition.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), SOURCE_DEFINITIONS.len());
        assert_eq!(ids.len(), SOURCE_DEFINITIONS.len());
        assert_eq!(SourceId::ALL.len(), SOURCE_DEFINITIONS.len());
        for source in SourceId::ALL.iter().copied() {
            let definition = source.definition();
            assert_eq!(SourceId::parse(definition.name), Some(source));
            assert_eq!(definition.id, source);
            assert_eq!(definition.evidence_family, source.evidence_family());
            assert_eq!(source_metadata(definition.name).name, definition.name);
        }
    }

    #[test]
    fn compatibility_aliases_share_execution_and_static_policy() {
        for (canonical, alias) in [
            (SourceId::AlienVault, SourceId::Otx),
            (SourceId::Digitorus, SourceId::CertificateDetails),
            (SourceId::WaybackArchive, SourceId::Wayback),
            (SourceId::WhoisXmlApi, SourceId::WhoisXml),
        ] {
            assert_eq!(alias.implementation(), canonical);
            assert_eq!(
                source_policy(alias.as_str()),
                source_policy(canonical.as_str())
            );
            assert_eq!(
                source_metadata(alias.as_str()).pagination,
                source_metadata(canonical.as_str()).pagination
            );
        }
    }
}
