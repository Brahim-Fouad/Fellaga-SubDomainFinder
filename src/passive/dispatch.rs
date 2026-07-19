//! Typed dispatch from catalog source IDs to connector implementations.

use super::catalog::SourceId;
use super::config::ApiKeyStore;
use super::providers::{
    anubisdb, certspotter, commoncrawl, crtsh, hackertarget, netlas, securitytrails, subdomainapp,
    urlscan, virustotal, wayback, whoisxml,
};
use super::{extra, keyed_sources, public_sources};
use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::time::Duration;

pub(super) async fn fetch(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let source_id = SourceId::parse(source)
        .ok_or_else(|| anyhow::anyhow!("source passive inconnue: {source}"))?;
    match source_id {
        SourceId::CrtSh => crtsh(domain, timeout).await,
        SourceId::CertSpotter => certspotter(domain, timeout, keys).await,
        SourceId::HackerTarget => hackertarget(domain, timeout, keys).await,
        SourceId::CommonCrawl => commoncrawl(domain, timeout).await,
        SourceId::Wayback | SourceId::WaybackArchive => wayback(domain, timeout).await,
        SourceId::Urlscan => urlscan(domain, timeout, keys).await,
        SourceId::Anubis => public_sources::anubis(domain, timeout).await,
        SourceId::AnubisDb => anubisdb(domain, timeout).await,
        SourceId::ArquivoPt => public_sources::arquivopt(domain, timeout).await,
        SourceId::SubdomainApp => subdomainapp(domain, timeout).await,
        SourceId::VirusTotal => virustotal(domain, timeout, keys).await,
        SourceId::WhoisXml | SourceId::WhoisXmlApi => whoisxml(domain, timeout, keys).await,
        SourceId::SecurityTrails => securitytrails(domain, timeout, keys).await,
        SourceId::Bevigil => extra::bevigil(domain, timeout, keys).await,
        SourceId::BinaryEdge => {
            bail!("BinaryEdge: provider service retired on 2025-03-31; no request was sent")
        }
        SourceId::Brave => extra::brave(domain, timeout, keys).await,
        SourceId::BuiltWith => extra::builtwith(domain, timeout, keys).await,
        SourceId::Censys => extra::censys(domain, timeout, keys).await,
        SourceId::Circl => extra::circl(domain, timeout, keys).await,
        SourceId::CertificateDetails | SourceId::Digitorus => {
            extra::certificate_details(domain, timeout).await
        }
        SourceId::Chaos => extra::chaos(domain, timeout, keys).await,
        SourceId::DriftNet => {
            let token = keys.pick("driftnet")?;
            extra::driftnet(domain, timeout, &token).await
        }
        SourceId::FullHunt => extra::fullhunt(domain, timeout, keys).await,
        SourceId::Github => extra::github(domain, timeout, keys).await,
        SourceId::Gitlab => extra::gitlab(domain, timeout, keys).await,
        SourceId::IntelX => extra::intelx(domain, timeout, keys).await,
        SourceId::LeakIx => extra::leakix(domain, timeout, keys).await,
        SourceId::MerkleMap => extra::merklemap(domain, timeout, keys).await,
        SourceId::Netlas => netlas(domain, timeout, keys).await,
        SourceId::AlienVault | SourceId::Otx => extra::otx(domain, timeout, keys).await,
        SourceId::Shodan => extra::shodan(domain, timeout, keys).await,
        SourceId::SubdomainCenter => extra::subdomain_center(domain, timeout).await,
        SourceId::BufferOver => keyed_sources::bufferover(domain, timeout, keys).await,
        SourceId::C99 => keyed_sources::c99(domain, timeout, keys).await,
        SourceId::Chinaz => keyed_sources::chinaz(domain, timeout, keys).await,
        SourceId::DigitalYama => keyed_sources::digitalyama(domain, timeout, keys).await,
        SourceId::DnsDb => keyed_sources::dnsdb(domain, timeout, keys).await,
        SourceId::DnsDumpster => keyed_sources::dnsdumpster(domain, timeout, keys).await,
        SourceId::DnsRepo => keyed_sources::dnsrepo(domain, timeout, keys).await,
        SourceId::DomainsProject => keyed_sources::domainsproject(domain, timeout, keys).await,
        SourceId::Fofa => keyed_sources::fofa(domain, timeout, keys).await,
        SourceId::HudsonRock => public_sources::hudsonrock(domain, timeout).await,
        SourceId::Onyphe => keyed_sources::onyphe(domain, timeout, keys).await,
        SourceId::Postman => extra::postman(domain, timeout, keys).await,
        SourceId::Profundis => keyed_sources::profundis(domain, timeout, keys).await,
        SourceId::PugRecon => keyed_sources::pugrecon(domain, timeout, keys).await,
        SourceId::Quake => keyed_sources::quake(domain, timeout, keys).await,
        SourceId::RapidDns => public_sources::rapiddns(domain, timeout).await,
        SourceId::ReconCloud => public_sources::reconcloud(domain, timeout).await,
        SourceId::Reconeer => public_sources::reconeer(domain, timeout, keys).await,
        SourceId::RedHuntLabs => keyed_sources::redhuntlabs(domain, timeout, keys).await,
        SourceId::Riddler => public_sources::riddler(domain, timeout).await,
        SourceId::Robtex => keyed_sources::robtex(domain, timeout, keys).await,
        SourceId::RseCloud => keyed_sources::rsecloud(domain, timeout, keys).await,
        SourceId::ShodanCt => public_sources::shodanct(domain, timeout).await,
        SourceId::ShrewdEye => public_sources::shrewdeye(domain, timeout).await,
        SourceId::SiteDossier => public_sources::sitedossier(domain, timeout).await,
        SourceId::SubMd => public_sources::submd(domain, timeout, keys).await,
        SourceId::Thc => public_sources::thc(domain, timeout).await,
        SourceId::ThreatBook => keyed_sources::threatbook(domain, timeout, keys).await,
        SourceId::ThreatCrowd => public_sources::threatcrowd(domain, timeout).await,
        SourceId::ThreatMiner => public_sources::threatminer(domain, timeout).await,
        SourceId::ViewDns => keyed_sources::viewdns(domain, timeout, keys).await,
        SourceId::WindVane => keyed_sources::windvane(domain, timeout, keys).await,
        SourceId::ZoomEyeApi => keyed_sources::zoomeyeapi(domain, timeout, keys).await,
    }
}
