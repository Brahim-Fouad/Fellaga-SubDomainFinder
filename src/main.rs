use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use fellaga_core::candidate::{default_mutation_rules, load_mutation_rules};
use fellaga_core::db::Database;
use fellaga_core::dns::DnsEngine;
use fellaga_core::model::{AxfrStatus, Finding, ScanResult};
use fellaga_core::passive::{
    ApiKeyStore, automatic_sources_for_profile, source_statuses, validate_sources,
};
use fellaga_core::scanner::{ProgressEvent, ScanOptions, Scanner, refresh_inventory};
use fellaga_core::{passive, scanner, util};
use futures_util::{StreamExt, stream};
use std::collections::BTreeSet;
use std::io::{IsTerminal, Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "fellaga",
    version,
    about = "Énumérateur de sous-domaines Rust, rapide et auto-apprenant"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Base SQLite (sinon FELLAGA_DB ou XDG_DATA_HOME)"
    )]
    db: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        help = "Configuration JSON des clés API (sinon FELLAGA_CONFIG ou XDG_CONFIG_HOME)"
    )]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Énumère les sous-domaines et tente automatiquement AXFR.
    Scan(Box<ScanArgs>),
    /// Liste l'inventaire conservé dans SQLite.
    List(ListArgs),
    /// Revalide tous les sous-domaines connus et rafraîchit le cache.
    Refresh(RefreshArgs),
    /// Affiche l'historique des scans.
    History(HistoryArgs),
    /// Affiche les statistiques d'apprentissage et de cache.
    Stats,
    /// Entretien du cache SQLite.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Affiche la base de connaissance permanente locale.
    Knowledge(KnowledgeArgs),
    /// Liste toutes les sources et leur état d'activation automatique.
    Sources(SourcesArgs),
    /// Explique pourquoi un nom est connu et quand il a été validé.
    Explain(ExplainArgs),
    /// Teste et classe les résolveurs DNS avant un scan intensif.
    Resolvers {
        #[command(subcommand)]
        action: ResolverAction,
    },
    /// Importe des noms produits par d'autres énumérateurs sans les déclarer live.
    Import(ImportArgs),
    /// Exporte l'inventaire local permanent.
    Export(ExportArgs),
}

#[derive(Debug, Args)]
struct DnsArgs {
    #[arg(short = 'c', long, default_value_t = 500)]
    concurrency: usize,
    #[arg(long, default_value_t = 2.0)]
    timeout: f64,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Résolveurs DNS, ex. 1.1.1.1,8.8.8.8"
    )]
    resolvers: Vec<IpAddr>,
    #[arg(
        long,
        default_value_t = 0,
        help = "Limite DNS en requêtes/s; 0 = sans limite artificielle"
    )]
    dns_rate_limit: u64,
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "1.1.1.1,8.8.8.8,9.9.9.9",
        help = "Résolveurs indépendants utilisés pour le consensus final"
    )]
    trusted_resolvers: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum ScanProfile {
    Deep,
    Balanced,
    Passive,
    Turbo,
}

#[derive(Debug, Clone, Copy)]
struct ProfileDefaults {
    max_words: usize,
    max_passive: usize,
    depth: usize,
    recursive_words: usize,
    recursive_hosts: usize,
    pipeline_rounds: usize,
    pipeline_budget: usize,
    tls_hosts: usize,
    graph_hosts: usize,
    ptr_ips: usize,
    nsec_max_names: usize,
    ct_logs: usize,
    ct_entries: usize,
    ct_backfill: usize,
    web_hosts: usize,
    web_assets: usize,
}

impl ScanProfile {
    const fn defaults(self) -> ProfileDefaults {
        match self {
            Self::Deep => ProfileDefaults {
                max_words: 1_000_000,
                max_passive: 250_000,
                depth: 5,
                recursive_words: 10_000,
                recursive_hosts: 2_000,
                pipeline_rounds: 10,
                pipeline_budget: 1_000_000,
                tls_hosts: 1_000,
                graph_hosts: 5_000,
                ptr_ips: 512,
                nsec_max_names: 100_000,
                ct_logs: 8,
                ct_entries: 4_096,
                ct_backfill: 4_096,
                web_hosts: 1_000,
                web_assets: 20,
            },
            Self::Balanced => ProfileDefaults {
                max_words: 5_000,
                max_passive: 10_000,
                depth: 3,
                recursive_words: 100,
                recursive_hosts: 50,
                pipeline_rounds: 2,
                pipeline_budget: 5_000,
                tls_hosts: 100,
                graph_hosts: 250,
                ptr_ips: 64,
                nsec_max_names: 10_000,
                ct_logs: 2,
                ct_entries: 256,
                ct_backfill: 256,
                web_hosts: 30,
                web_assets: 5,
            },
            Self::Passive => ProfileDefaults {
                max_words: 0,
                max_passive: 250_000,
                depth: 1,
                recursive_words: 1,
                recursive_hosts: 1,
                pipeline_rounds: 1,
                pipeline_budget: 250_000,
                tls_hosts: 1,
                graph_hosts: 1,
                ptr_ips: 1,
                nsec_max_names: 1,
                ct_logs: 8,
                ct_entries: 4_096,
                ct_backfill: 4_096,
                web_hosts: 1,
                web_assets: 1,
            },
            Self::Turbo => ProfileDefaults {
                max_words: 1_000_000,
                max_passive: 50_000,
                depth: 3,
                recursive_words: 5_000,
                recursive_hosts: 1_000,
                pipeline_rounds: 4,
                pipeline_budget: 250_000,
                tls_hosts: 100,
                graph_hosts: 500,
                ptr_ips: 128,
                nsec_max_names: 10_000,
                ct_logs: 2,
                ct_entries: 512,
                ct_backfill: 512,
                web_hosts: 50,
                web_assets: 5,
            },
        }
    }
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,
    #[arg(short = 'l', long, help = "Fichier de domaines, un par ligne")]
    targets_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ScanProfile::Deep)]
    profile: ScanProfile,
    #[arg(long, default_value_t = 2, help = "Domaines traités en parallèle")]
    domain_concurrency: usize,
    #[command(flatten)]
    dns: DnsArgs,
    #[arg(short = 'w', long)]
    wordlist: Option<PathBuf>,
    #[arg(
        long,
        help = "DSL de mutations: score:nom:pattern avec {{word}}, {{parent}}, {{env}}, {{region}}, {{cloud}}, {{n}}"
    )]
    mutations: Option<PathBuf>,
    #[arg(long)]
    max_words: Option<usize>,
    #[arg(long)]
    no_passive: bool,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Sources passives à utiliser; vide = sélection automatique"
    )]
    passive_sources: Vec<String>,
    #[arg(long, value_delimiter = ',', help = "Sources à exclure")]
    exclude_sources: Vec<String>,
    #[arg(long, help = "Tente aussi les sources dont la clé API est absente")]
    all_sources: bool,
    #[arg(long, default_value_t = 24)]
    passive_refresh_hours: u64,
    #[arg(long)]
    max_passive: Option<usize>,
    #[arg(long)]
    passive_only: bool,
    #[arg(long, help = "Désactive la tentative AXFR automatique")]
    no_axfr: bool,
    #[arg(long, default_value_t = 8.0)]
    axfr_timeout: f64,
    #[arg(long, help = "Ignore le cache même s'il est encore frais")]
    refresh_cache: bool,
    #[arg(
        long,
        default_value_t = 24,
        help = "Âge maximal en heures pour considérer une validation en cache comme live"
    )]
    verification_max_age: u64,
    #[arg(
        long,
        help = "N'affiche que les noms dont la validation DNS est encore live"
    )]
    only_live: bool,
    #[arg(
        long,
        default_value_t = 86_400,
        help = "Conservé pour compatibilité; les réponses positives sont permanentes"
    )]
    ttl_cap: u32,
    #[arg(long, default_value_t = 300)]
    negative_ttl: u32,
    #[arg(long)]
    include_wildcard: bool,
    #[arg(
        long,
        default_value_t = 6,
        help = "Délai de rafraîchissement du profil wildcard; SOA évite les nouvelles sondes"
    )]
    wildcard_refresh_hours: u64,
    #[arg(long, help = "Profondeur DNS active maximale, de 1 à 5")]
    depth: Option<usize>,
    #[arg(long)]
    recursive_words: Option<usize>,
    #[arg(long)]
    recursive_hosts: Option<usize>,
    #[arg(long, help = "Désactive les vagues et arrêts adaptatifs")]
    no_adaptive: bool,
    #[arg(long, help = "Désactive les boucles d'enrichissement événementielles")]
    no_pipeline: bool,
    #[arg(long, help = "Tours maximum du pipeline événementiel")]
    pipeline_rounds: Option<usize>,
    #[arg(long, help = "Budget global de nouveaux événements")]
    pipeline_budget: Option<usize>,
    #[arg(
        long,
        help = "Désactive l'extraction des noms depuis les certificats TLS"
    )]
    no_tls: bool,
    #[arg(
        long,
        default_value_t = 443,
        help = "Port utilisé pour l'inspection TLS"
    )]
    tls_port: u16,
    #[arg(
        long,
        default_value_t = 3.0,
        help = "Timeout TLS par endpoint en secondes"
    )]
    tls_timeout: f64,
    #[arg(
        long,
        default_value_t = 24,
        help = "Délai avant une nouvelle inspection TLS; les anciens noms restent conservés"
    )]
    tls_refresh_hours: u64,
    #[arg(long, help = "Nombre maximal d'endpoints TLS inspectés")]
    tls_hosts: Option<usize>,
    #[arg(long, default_value_t = 16, help = "Handshakes TLS simultanés")]
    tls_concurrency: usize,
    #[arg(
        long,
        help = "Désactive le graphe DNS MX/NS/SOA/TXT/CAA/SRV/HTTPS/SVCB"
    )]
    no_dns_graph: bool,
    #[arg(long, help = "Hôtes confirmés enrichis dans le graphe DNS")]
    graph_hosts: Option<usize>,
    #[arg(long, help = "Désactive les requêtes de découverte SRV")]
    no_service_discovery: bool,
    #[arg(long, help = "Désactive les pivots PTR sur les IP déjà confirmées")]
    no_ptr: bool,
    #[arg(long, help = "Nombre maximal d'IP interrogées en PTR")]
    ptr_ips: Option<usize>,
    #[arg(long, help = "Désactive la détection et le parcours DNSSEC NSEC")]
    no_nsec: bool,
    #[arg(
        long,
        default_value_t = 3.0,
        help = "Timeout par requête NSEC en secondes"
    )]
    nsec_timeout: f64,
    #[arg(
        long,
        default_value_t = 24,
        help = "Délai de rafraîchissement du cache NSEC"
    )]
    nsec_refresh_hours: u64,
    #[arg(long, help = "Noms NSEC maximum par zone")]
    nsec_max_names: Option<usize>,
    #[arg(
        long,
        help = "Désactive la surveillance incrémentale directe des journaux CT"
    )]
    no_ct_monitor: bool,
    #[arg(long, default_value_t = 8.0, help = "Timeout des API CT en secondes")]
    ct_timeout: f64,
    #[arg(long, help = "Journaux CT inspectés par scan")]
    ct_logs: Option<usize>,
    #[arg(long, help = "Entrées nouvelles lues par journal CT")]
    ct_entries: Option<usize>,
    #[arg(long, help = "Entrées CT reprises au premier passage")]
    ct_backfill: Option<usize>,
    #[arg(
        long,
        help = "Désactive l'extraction HTTP, HTML, JavaScript et source maps"
    )]
    no_web: bool,
    #[arg(long, help = "Nombre maximal d'hôtes web inspectés")]
    web_hosts: Option<usize>,
    #[arg(
        long,
        default_value_t = 5.0,
        help = "Timeout HTTP par requête en secondes"
    )]
    web_timeout: f64,
    #[arg(
        long,
        default_value_t = 24,
        help = "Délai de rafraîchissement du cache web"
    )]
    web_refresh_hours: u64,
    #[arg(long, default_value_t = 8, help = "Hôtes web inspectés simultanément")]
    web_concurrency: usize,
    #[arg(
        long,
        default_value_t = 524_288,
        help = "Octets lus au maximum par ressource web"
    )]
    web_max_bytes: usize,
    #[arg(long, help = "Assets JS/JSON/source map suivis par hôte")]
    web_assets: Option<usize>,
    #[arg(
        long,
        default_value_t = 0,
        help = "Durée globale maximale en secondes; 0 = aucune limite"
    )]
    max_runtime: u64,
    #[arg(
        long,
        default_value_t = 30,
        help = "Intervalle des checkpoints persistants en secondes"
    )]
    checkpoint_every: u64,
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "latest",
        help = "Reprend un scan; sans valeur utilise le dernier checkpoint"
    )]
    resume: Option<String>,
    #[arg(
        long,
        help = "Désactive le consensus final des résolveurs de confiance"
    )]
    no_trusted_validation: bool,
    #[arg(long)]
    json: bool,
    #[arg(long, help = "Un objet JSON compact par domaine")]
    jsonl: bool,
    #[arg(long, help = "Émet chaque finding en JSONL dès sa validation")]
    stream_jsonl: bool,
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
    #[arg(long, help = "Un fichier de résultat par domaine")]
    output_dir: Option<PathBuf>,
    #[arg(short, long, visible_alias = "silent")]
    quiet: bool,
}

#[derive(Debug, Args)]
struct ListArgs {
    #[arg(long)]
    domain: Option<String>,
    #[arg(
        long,
        hide = true,
        help = "Compatibilité: tous les états sont déjà inclus"
    )]
    all: bool,
    #[arg(long, help = "Limite l'inventaire aux validations live")]
    only_live: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RefreshArgs {
    target: String,
    #[command(flatten)]
    dns: DnsArgs,
    #[arg(
        long,
        default_value_t = 86_400,
        help = "Conservé pour compatibilité; les réponses positives sont permanentes"
    )]
    ttl_cap: u32,
    #[arg(long, default_value_t = 300)]
    negative_ttl: u32,
}

#[derive(Debug, Args)]
struct HistoryArgs {
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Debug, Subcommand)]
enum CacheAction {
    /// Supprime uniquement les entrées expirées.
    Prune,
}

#[derive(Debug, Args)]
struct KnowledgeArgs {
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

#[derive(Debug, Args)]
struct SourcesArgs {
    #[arg(long)]
    json: bool,
    #[arg(
        long,
        help = "Teste les contrats HTTP et l'accessibilité des connecteurs"
    )]
    check: bool,
    #[arg(
        long,
        default_value = "example.com",
        help = "Domaine utilisé par --check"
    )]
    target: String,
    #[arg(long, default_value_t = 20.0, help = "Timeout par connecteur")]
    timeout: f64,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    fqdn: String,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum ResolverAction {
    Test(ResolverTestArgs),
    /// Mesure le transport DNS natif contre un serveur local contrôlé.
    Benchmark(ResolverBenchmarkArgs),
}

#[derive(Debug, Args)]
struct ResolverTestArgs {
    #[arg(value_delimiter = ',', help = "IP des résolveurs à tester")]
    resolvers: Vec<IpAddr>,
    #[arg(long, default_value_t = 3.0)]
    timeout: f64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ResolverBenchmarkArgs {
    #[arg(long, default_value_t = 100_000)]
    queries: usize,
    #[arg(long, default_value_t = 2_000)]
    concurrency: usize,
    #[arg(long, default_value_t = 2.0)]
    timeout: f64,
    #[arg(long)]
    json: bool,
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ImportFormat {
    Auto,
    Subfinder,
    Amass,
    Bbot,
    Massdns,
}

#[derive(Debug, Args)]
struct ImportArgs {
    domain: String,
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = ImportFormat::Auto)]
    format: ImportFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExportFormat {
    Jsonl,
    Csv,
}

#[derive(Debug, Args)]
struct ExportArgs {
    #[arg(long)]
    domain: Option<String>,
    #[arg(long)]
    only_live: bool,
    #[arg(long, value_enum, default_value_t = ExportFormat::Jsonl)]
    format: ExportFormat,
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

fn compact_error(error: &str, limit: usize) -> String {
    let compact = error.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut shortened = compact.chars().take(limit).collect::<String>();
    if compact.chars().count() > limit {
        shortened.push('…');
    }
    shortened
}

fn wait_label(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}")
    } else {
        format!("{minutes}m")
    }
}

fn default_database_path() -> PathBuf {
    if let Some(path) = std::env::var_os("FELLAGA_DB") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join("fellaga/fellaga.db");
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/share/fellaga/fellaga.db")
}

fn collect_targets(args: &ScanArgs) -> Result<Vec<String>> {
    let mut raw = args.targets.clone();
    if let Some(path) = &args.targets_file {
        if !path.is_file() {
            bail!("fichier de cibles introuvable: {}", path.display());
        }
        raw.extend(
            std::fs::read_to_string(path)?
                .lines()
                .map(ToOwned::to_owned),
        );
    }
    let read_stdin = raw.iter().any(|target| target.trim() == "-")
        || (raw.is_empty() && !std::io::stdin().is_terminal());
    raw.retain(|target| target.trim() != "-");
    if read_stdin {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input)?;
        raw.extend(input.lines().map(ToOwned::to_owned));
    }
    let mut targets = BTreeSet::new();
    for line in raw {
        let value = line.split('#').next().unwrap_or_default();
        for target in value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            targets.insert(util::normalize_domain(target)?);
        }
    }
    if targets.is_empty() {
        bail!("aucune cible: fournissez TARGET, --targets-file ou des domaines sur stdin");
    }
    Ok(targets.into_iter().collect())
}

fn make_dns(args: &DnsArgs) -> Result<DnsEngine> {
    if args.timeout <= 0.0 || !args.timeout.is_finite() {
        bail!("--timeout doit être un nombre positif");
    }
    DnsEngine::new_with_rate(
        args.concurrency,
        Duration::from_secs_f64(args.timeout),
        &args.resolvers,
        args.dns_rate_limit,
    )
}

fn finding_line(finding: &Finding) -> String {
    let records = finding
        .records
        .iter()
        .map(|record| format!("{}={}", record.record_type, record.value))
        .collect::<Vec<_>>()
        .join(" ");
    let sources = finding
        .sources
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let cache = if finding.from_cache { " cache" } else { "" };
    let wildcard = if finding.wildcard { " wildcard" } else { "" };
    format!(
        "[+] {:<45} {:<42} [{} {} | {}] ({sources}{cache}{wildcard})",
        finding.fqdn, records, finding.confidence.label, finding.confidence.score, finding.state
    )
}

struct ConsoleProgress {
    interactive: bool,
    json_output: bool,
    line_active: bool,
    last_log_bucket: Option<(String, usize)>,
}

impl ConsoleProgress {
    fn new(json_output: bool) -> Self {
        Self {
            interactive: std::io::stderr().is_terminal(),
            json_output,
            line_active: false,
            last_log_bucket: None,
        }
    }

    fn clear_progress_line(&mut self) {
        if self.interactive && self.line_active {
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
        self.line_active = false;
    }

    fn write_streamed(&mut self, line: &str) {
        self.clear_progress_line();
        if self.json_output {
            eprintln!("{line}");
        } else {
            println!("{line}");
            let _ = std::io::stdout().flush();
        }
    }

    fn handle(&mut self, event: ProgressEvent) {
        match event {
            ProgressEvent::Started { scan_id, domain } => {
                self.clear_progress_line();
                eprintln!("[>] Scan #{scan_id} démarré pour {domain}");
            }
            ProgressEvent::Phase { name, detail } => {
                self.clear_progress_line();
                self.last_log_bucket = None;
                eprintln!("[>] {name}: {detail}");
            }
            ProgressEvent::PassiveSource {
                source,
                status,
                names,
            } => {
                self.clear_progress_line();
                eprintln!("[P] {source}: {names} nom(s) ({status})");
            }
            ProgressEvent::AxfrAttempt(attempt) => {
                let line = if attempt.status == AxfrStatus::Success {
                    format!(
                        "[AXFR] SUCCÈS {} ({}) : {} enregistrements, {} noms",
                        attempt.nameserver,
                        attempt.address,
                        attempt.records.len(),
                        attempt.names.len()
                    )
                } else {
                    format!(
                        "[AXFR] refus/échec {} ({}) : {}",
                        attempt.nameserver,
                        attempt.address,
                        attempt.error.as_deref().unwrap_or("réponse vide")
                    )
                };
                self.write_streamed(&line);
            }
            ProgressEvent::TlsCertificates {
                endpoints,
                network,
                successes,
                failures,
                cache_hits,
                names,
                duration_ms,
            } => {
                self.clear_progress_line();
                eprintln!(
                    "[TLS] {endpoints} endpoint(s), {network} réseau, {successes} succès, {failures} échec(s), {cache_hits} cache, {names} nom(s), {:.1}s",
                    duration_ms as f64 / 1_000.0
                );
            }
            ProgressEvent::DnsGraph {
                queries,
                edges,
                names,
                child_zones,
                services,
                duration_ms,
            } => {
                self.clear_progress_line();
                eprintln!(
                    "[DNS+] {queries} requête(s), {edges} relation(s), {names} nom(s), {child_zones} zone(s) enfant, {services} service(s), {:.1}s",
                    duration_ms as f64 / 1_000.0
                );
            }
            ProgressEvent::WebDiscovery {
                hosts,
                requests,
                cache_hits,
                failures,
                names,
                duration_ms,
            } => {
                self.clear_progress_line();
                eprintln!(
                    "[WEB] {hosts} hôte(s), {requests} requête(s), {cache_hits} cache, {failures} échec(s), {names} nom(s), {:.1}s",
                    duration_ms as f64 / 1_000.0
                );
            }
            ProgressEvent::Dnssec {
                zones,
                walked,
                protected,
                queries,
                names,
            } => {
                self.clear_progress_line();
                eprintln!(
                    "[NSEC] {zones} zone(s), {walked} parcourue(s), {protected} protégée(s), {queries} requête(s), {names} nom(s)"
                );
            }
            ProgressEvent::CtMonitor {
                logs,
                entries,
                failures,
                names,
                duration_ms,
            } => {
                self.clear_progress_line();
                eprintln!(
                    "[CT] {logs} journal(aux), {entries} entrée(s), {failures} échec(s), {names} nom(s) cumulé(s), {:.1}s",
                    duration_ms as f64 / 1_000.0
                );
            }
            ProgressEvent::DnsProgress {
                phase,
                processed,
                total,
                found,
                cache_hits,
                rate,
                elapsed_ms,
            } => {
                let percent = processed
                    .saturating_mul(100)
                    .checked_div(total)
                    .unwrap_or(100);
                if !self.interactive {
                    let bucket = percent / 10;
                    let already_logged = self.last_log_bucket.as_ref().is_some_and(
                        |(previous_phase, previous_bucket)| {
                            previous_phase == &phase && *previous_bucket == bucket
                        },
                    );
                    if already_logged && processed != total {
                        return;
                    }
                    self.last_log_bucket = Some((phase.clone(), bucket));
                }
                let filled = percent.min(100) * 20 / 100;
                let bar = format!("{}{}", "█".repeat(filled), "░".repeat(20 - filled));
                let line = format!(
                    "[~] {phase:<14} [{bar}] {percent:>3}% {processed}/{total} | +{found} | cache {cache_hits} | {rate:.0}/s | {:.1}s",
                    elapsed_ms as f64 / 1_000.0
                );
                if self.interactive {
                    eprint!("\r\x1b[2K{line}");
                    let _ = std::io::stderr().flush();
                    self.line_active = true;
                } else {
                    eprintln!("{line}");
                }
            }
            ProgressEvent::Finding(finding) => self.write_streamed(&finding_line(&finding)),
            ProgressEvent::Warning(warning) => {
                self.clear_progress_line();
                eprintln!("[!] {warning}");
            }
            ProgressEvent::Complete => self.clear_progress_line(),
        }
    }
}

fn print_scan_summary(result: &ScanResult) {
    println!(
        "\nScan #{}: {} trouvés / {} candidats, {} cache hits, {} ms",
        result.scan_id,
        result.findings.len(),
        result.candidates,
        result.cache_hits,
        result.duration_ms
    );
    if result.wildcard_detected {
        println!("[!] DNS wildcard détecté; faux positifs filtrés.");
    }
    if !result.tls_certificates.is_empty() {
        let names = result
            .tls_certificates
            .iter()
            .flat_map(|certificate| certificate.names.iter())
            .collect::<BTreeSet<_>>()
            .len();
        println!(
            "[TLS] {} certificat(s) observé(s), {} nom(s) SAN/CN en périmètre.",
            result.tls_certificates.len(),
            names
        );
    }
    if !result.dns_edges.is_empty() {
        println!(
            "[DNS+] {} relation(s), {} zone(s) enfant, {} endpoint(s) de service.",
            result.dns_edges.len(),
            result.child_zones.len(),
            result.service_endpoints.len()
        );
    }
    if !result.web_observations.is_empty() {
        let names = result
            .web_observations
            .iter()
            .flat_map(|observation| observation.names.iter())
            .collect::<BTreeSet<_>>()
            .len();
        println!(
            "[WEB] {} ressource(s) observée(s), {} nom(s) en périmètre.",
            result.web_observations.len(),
            names
        );
    }
    if !result.dnssec_walks.is_empty() {
        let names = result
            .dnssec_walks
            .iter()
            .flat_map(|walk| walk.names.iter())
            .collect::<BTreeSet<_>>()
            .len();
        println!(
            "[NSEC] {} zone(s) examinée(s), {} nom(s) conservé(s).",
            result.dnssec_walks.len(),
            names
        );
    }
    if result.ct_monitor.logs_checked > 0 || !result.ct_monitor.names.is_empty() {
        println!(
            "[CT] {} entrée(s) analysée(s), {} nom(s) indexé(s) globalement, {} nom(s) cumulé(s).",
            result.ct_monitor.entries_processed,
            result.ct_monitor.globally_indexed_names,
            result.ct_monitor.names.len()
        );
    }
    if result.pipeline.rounds > 0 || result.pipeline.events_enqueued > 0 {
        println!(
            "[PIPE] {} tour(s), {} événement(s), {} doublon(s) évité(s), {} nom(s) validé(s).",
            result.pipeline.rounds,
            result.pipeline.events_enqueued,
            result.pipeline.duplicates_suppressed,
            result.pipeline.names_validated
        );
    }
    if !result.resolver_metrics.is_empty() {
        let requests = result
            .resolver_metrics
            .iter()
            .map(|metric| metric.requests)
            .sum::<u64>();
        println!(
            "[DNS] {} résolveur(s) profilé(s), {} requête(s) mesurée(s).",
            result.resolver_metrics.len(),
            requests
        );
    }
}

fn write_scan(path: &PathBuf, result: &ScanResult, json_output: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if json_output
        || path
            .extension()
            .is_some_and(|extension| extension == "json")
    {
        std::fs::write(path, serde_json::to_string_pretty(result)? + "\n")?;
    } else {
        let text = result
            .findings
            .iter()
            .map(|finding| finding.fqdn.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            path,
            text + if result.findings.is_empty() { "" } else { "\n" },
        )?;
    }
    Ok(())
}

fn write_scan_results(
    path: &PathBuf,
    results: &[ScanResult],
    json_output: bool,
    jsonl: bool,
) -> Result<()> {
    if results.len() == 1 && !jsonl {
        return write_scan(path, &results[0], json_output);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = if jsonl {
        results
            .iter()
            .map(serde_json::to_string)
            .collect::<serde_json::Result<Vec<_>>>()?
            .join("\n")
    } else if json_output
        || path
            .extension()
            .is_some_and(|extension| extension == "json")
    {
        serde_json::to_string_pretty(results)?
    } else {
        results
            .iter()
            .flat_map(|result| result.findings.iter().map(|finding| finding.fqdn.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join("\n")
    };
    let newline = if text.is_empty() { "" } else { "\n" };
    std::fs::write(path, text + newline)?;
    Ok(())
}

fn collect_names_from_json(value: &serde_json::Value, names: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_names_from_json(value, names);
            }
        }
        serde_json::Value::Object(object) => {
            for key in ["name", "host", "fqdn", "hostname"] {
                if let Some(value) = object.get(key).and_then(serde_json::Value::as_str) {
                    names.push(value.to_owned());
                }
            }
            if let Some(data) = object.get("data") {
                match data {
                    serde_json::Value::String(value) => names.push(value.clone()),
                    _ => collect_names_from_json(data, names),
                }
            }
            for key in ["results", "hosts", "subdomains", "names", "events"] {
                if let Some(value) = object.get(key) {
                    collect_names_from_json(value, names);
                }
            }
        }
        serde_json::Value::String(value) => names.push(value.clone()),
        _ => {}
    }
}

fn parse_import_names(content: &str, format: ImportFormat, domain: &str) -> BTreeSet<String> {
    let mut raw_names = Vec::new();
    if matches!(
        format,
        ImportFormat::Amass | ImportFormat::Bbot | ImportFormat::Auto
    ) && let Ok(value) = serde_json::from_str::<serde_json::Value>(content)
    {
        collect_names_from_json(&value, &mut raw_names);
    } else {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !matches!(format, ImportFormat::Massdns)
                && let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
            {
                collect_names_from_json(&value, &mut raw_names);
                continue;
            }
            if let Some(name) = line.split_whitespace().next() {
                raw_names.push(name.to_owned());
            }
        }
    }
    raw_names
        .into_iter()
        .filter_map(|name| util::normalize_observed_name(&name, domain))
        .collect()
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let database_path = cli.db.unwrap_or_else(default_database_path);
    let config_path = cli.config.unwrap_or_else(passive::default_config_path);
    let api_keys = ApiKeyStore::load_or_create(&config_path)?;
    match cli.command {
        Command::Scan(args) => {
            if let Some(path) = &args.wordlist
                && !path.is_file()
            {
                bail!("wordlist introuvable: {}", path.display());
            }
            if let Some(path) = &args.mutations
                && !path.is_file()
            {
                bail!("DSL de mutations introuvable: {}", path.display());
            }
            let mutation_rules = if let Some(path) = &args.mutations {
                load_mutation_rules(path)?
            } else {
                default_mutation_rules()
            };
            let defaults = args.profile.defaults();
            let max_words = args.max_words.unwrap_or(defaults.max_words);
            let max_passive = args.max_passive.unwrap_or(defaults.max_passive);
            let depth = args.depth.unwrap_or(defaults.depth);
            let recursive_words = args.recursive_words.unwrap_or(defaults.recursive_words);
            let recursive_hosts = args.recursive_hosts.unwrap_or(defaults.recursive_hosts);
            let pipeline_rounds = args.pipeline_rounds.unwrap_or(defaults.pipeline_rounds);
            let pipeline_budget = args.pipeline_budget.unwrap_or(defaults.pipeline_budget);
            let tls_hosts = args.tls_hosts.unwrap_or(defaults.tls_hosts);
            let graph_hosts = args.graph_hosts.unwrap_or(defaults.graph_hosts);
            let ptr_ips = args.ptr_ips.unwrap_or(defaults.ptr_ips);
            let nsec_max_names = args.nsec_max_names.unwrap_or(defaults.nsec_max_names);
            let ct_logs = args.ct_logs.unwrap_or(defaults.ct_logs);
            let ct_entries = args.ct_entries.unwrap_or(defaults.ct_entries);
            let ct_backfill = args.ct_backfill.unwrap_or(defaults.ct_backfill);
            let web_hosts = args.web_hosts.unwrap_or(defaults.web_hosts);
            let web_assets = args.web_assets.unwrap_or(defaults.web_assets);
            let profile_passive = args.profile == ScanProfile::Passive;
            let passive_only = args.passive_only || profile_passive;

            if !passive_only && max_words == 0 {
                bail!("--max-words doit être supérieur à zéro hors profil passif");
            }
            if !(1..=5).contains(&depth) {
                bail!("--depth doit être compris entre 1 et 5");
            }
            if recursive_words == 0 || recursive_hosts == 0 {
                bail!("--recursive-words et --recursive-hosts doivent être supérieurs à zéro");
            }
            if max_passive == 0 {
                bail!("--max-passive doit être supérieur à zéro");
            }
            if args.domain_concurrency == 0 {
                bail!("--domain-concurrency doit être supérieur à zéro");
            }
            if args.axfr_timeout <= 0.0 || !args.axfr_timeout.is_finite() {
                bail!("--axfr-timeout doit être un nombre positif");
            }
            if args.tls_timeout <= 0.0 || !args.tls_timeout.is_finite() {
                bail!("--tls-timeout doit être un nombre positif");
            }
            if args.tls_port == 0 {
                bail!("--tls-port doit être supérieur à zéro");
            }
            if tls_hosts == 0 || args.tls_concurrency == 0 {
                bail!("--tls-hosts et --tls-concurrency doivent être supérieurs à zéro");
            }
            if graph_hosts == 0 {
                bail!("--graph-hosts doit être supérieur à zéro");
            }
            if pipeline_rounds == 0 || pipeline_budget == 0 {
                bail!("--pipeline-rounds et --pipeline-budget doivent être supérieurs à zéro");
            }
            if ptr_ips == 0 {
                bail!("--ptr-ips doit être supérieur à zéro");
            }
            if nsec_max_names == 0 {
                bail!("--nsec-max-names doit être supérieur à zéro");
            }
            if args.nsec_timeout <= 0.0 || !args.nsec_timeout.is_finite() {
                bail!("--nsec-timeout doit être un nombre positif");
            }
            if ct_logs == 0 || ct_entries == 0 || ct_backfill == 0 {
                bail!("--ct-logs, --ct-entries et --ct-backfill doivent être supérieurs à zéro");
            }
            if args.ct_timeout <= 0.0 || !args.ct_timeout.is_finite() {
                bail!("--ct-timeout doit être un nombre positif");
            }
            if web_hosts == 0 || args.web_concurrency == 0 || args.web_max_bytes == 0 {
                bail!(
                    "--web-hosts, --web-concurrency et --web-max-bytes doivent être supérieurs à zéro"
                );
            }
            if args.web_timeout <= 0.0 || !args.web_timeout.is_finite() {
                bail!("--web-timeout doit être un nombre positif");
            }
            if [args.json, args.jsonl, args.stream_jsonl]
                .into_iter()
                .filter(|enabled| *enabled)
                .count()
                > 1
            {
                bail!("--json, --jsonl et --stream-jsonl sont mutuellement exclusifs");
            }
            if args.no_passive && passive_only {
                bail!("--no-passive et --passive-only sont incompatibles");
            }
            if args.checkpoint_every == 0 {
                bail!("--checkpoint-every doit être supérieur à zéro");
            }
            let targets = collect_targets(&args)?;
            validate_sources(&args.passive_sources)?;
            validate_sources(&args.exclude_sources)?;
            let mut passive_sources = if args.all_sources {
                source_statuses(&api_keys)
                    .into_iter()
                    .map(|source| source.name)
                    .collect::<Vec<_>>()
            } else if args.passive_sources.is_empty() {
                automatic_sources_for_profile(&api_keys, args.profile == ScanProfile::Deep)
            } else {
                args.passive_sources.clone()
            };
            let automatic_source_selection = args.passive_sources.is_empty() && !args.all_sources;
            let excluded = args
                .exclude_sources
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            passive_sources.retain(|source| !excluded.contains(source));
            passive_sources.sort();
            passive_sources.dedup();
            if !args.no_passive && passive_sources.is_empty() {
                bail!("aucune source passive sélectionnée");
            }
            let database = Database::open(&database_path)?;
            let dns = make_dns(&args.dns)?;
            dns.seed_metrics(&database.resolver_history()?);
            let trusted_dns = if args.no_trusted_validation {
                None
            } else {
                let trusted = DnsEngine::new_with_rate(
                    args.dns.concurrency.min(256),
                    Duration::from_secs_f64(args.dns.timeout),
                    &args.dns.trusted_resolvers,
                    args.dns.dns_rate_limit,
                )?;
                trusted.seed_metrics(&database.resolver_history()?);
                Some(trusted)
            };
            let options = ScanOptions {
                wordlist: args.wordlist.clone(),
                mutation_rules,
                max_words,
                passive: !args.no_passive,
                passive_sources,
                api_keys: api_keys.clone(),
                automatic_source_selection,
                passive_refresh: Duration::from_secs(
                    args.passive_refresh_hours.saturating_mul(3_600),
                ),
                max_passive,
                passive_only,
                axfr: !args.no_axfr && !profile_passive,
                axfr_timeout: Duration::from_secs_f64(args.axfr_timeout),
                refresh_cache: args.refresh_cache,
                verification_max_age: Duration::from_secs(
                    args.verification_max_age.saturating_mul(3_600),
                ),
                only_live: args.only_live,
                profile: format!("{:?}", args.profile).to_ascii_lowercase(),
                checkpoint_every: Duration::from_secs(args.checkpoint_every),
                resume: args.resume.clone(),
                ttl_cap: args.ttl_cap,
                negative_ttl: args.negative_ttl,
                include_wildcard: args.include_wildcard,
                wildcard_refresh: Duration::from_secs(
                    args.wildcard_refresh_hours.saturating_mul(3_600),
                ),
                recursive_depth: depth,
                recursive_words,
                recursive_hosts,
                adaptive: !args.no_adaptive && args.profile != ScanProfile::Deep,
                pipeline: !args.no_pipeline && !profile_passive,
                pipeline_rounds,
                pipeline_budget,
                tls_certificates: !args.no_tls && !profile_passive,
                tls_port: args.tls_port,
                tls_timeout: Duration::from_secs_f64(args.tls_timeout),
                tls_refresh: Duration::from_secs(args.tls_refresh_hours.saturating_mul(3_600)),
                tls_max_hosts: tls_hosts,
                tls_concurrency: args.tls_concurrency,
                dns_graph: !args.no_dns_graph && !profile_passive,
                graph_max_hosts: graph_hosts,
                service_discovery: !args.no_service_discovery && !profile_passive,
                ptr_pivot: !args.no_ptr && !profile_passive,
                ptr_max_ips: ptr_ips,
                dnssec_nsec: !args.no_nsec && !profile_passive,
                nsec_timeout: Duration::from_secs_f64(args.nsec_timeout),
                nsec_refresh: Duration::from_secs(args.nsec_refresh_hours.saturating_mul(3_600)),
                nsec_max_names,
                ct_monitor: !args.no_ct_monitor,
                ct_timeout: Duration::from_secs_f64(args.ct_timeout),
                ct_max_logs: ct_logs,
                ct_entries_per_log: ct_entries,
                ct_initial_backfill: ct_backfill,
                web_discovery: !args.no_web && !profile_passive,
                web_max_hosts: web_hosts,
                web_timeout: Duration::from_secs_f64(args.web_timeout),
                web_refresh: Duration::from_secs(args.web_refresh_hours.saturating_mul(3_600)),
                web_concurrency: args.web_concurrency,
                web_max_bytes: args.web_max_bytes,
                web_assets_per_host: web_assets,
            };
            let callback: Option<scanner::ProgressCallback> = if !args.quiet || args.stream_jsonl {
                let printer = Arc::new(Mutex::new(ConsoleProgress::new(
                    args.json || args.jsonl || args.stream_jsonl,
                )));
                let quiet = args.quiet;
                let stream_jsonl = args.stream_jsonl;
                Some(Arc::new(move |event| {
                    if stream_jsonl && let ProgressEvent::Finding(finding) = &event {
                        println!(
                            "{}",
                            serde_json::json!({"type": "finding", "finding": finding})
                        );
                        let _ = std::io::stdout().flush();
                    }
                    if !quiet && let Ok(mut printer) = printer.lock() {
                        printer.handle(event);
                    }
                }))
            } else {
                None
            };
            let max_runtime = (args.max_runtime > 0).then(|| Duration::from_secs(args.max_runtime));
            let domain_concurrency = args.domain_concurrency.min(targets.len()).max(1);
            let mut pending = stream::iter(targets)
                .map(|target| {
                    let database = database.clone();
                    let dns = dns.clone();
                    let options = options.clone();
                    let callback = callback.clone();
                    let trusted_dns = trusted_dns.clone();
                    async move {
                        let mut scanner = Scanner::new(database, dns, options);
                        if let Some(trusted_dns) = trusted_dns {
                            scanner = scanner.with_trusted_dns(trusted_dns);
                        }
                        if let Some(callback) = callback {
                            scanner = scanner.with_progress(callback);
                        }
                        if let Some(limit) = max_runtime {
                            tokio::time::timeout(limit, scanner.scan(&target))
                                .await
                                .map_err(|_| {
                                    anyhow::anyhow!(
                                        "durée globale maximale atteinte pour {target}; utilisez --resume latest"
                                    )
                                })?
                        } else {
                            scanner.scan(&target).await
                        }
                    }
                })
                .buffer_unordered(domain_concurrency);
            let mut results = Vec::new();
            while let Some(result) = pending.next().await {
                results.push(result?);
            }
            results.sort_by(|left, right| left.domain.cmp(&right.domain));
            if args.stream_jsonl {
                // Les findings ont déjà été émis par le callback temps réel.
            } else if args.jsonl {
                for result in &results {
                    println!("{}", serde_json::to_string(result)?);
                }
            } else if args.json {
                if results.len() == 1 {
                    println!("{}", serde_json::to_string_pretty(&results[0])?);
                } else {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                }
            } else if !args.quiet {
                for result in &results {
                    print_scan_summary(result);
                }
            }
            if let Some(path) = &args.output {
                write_scan_results(path, &results, args.json, args.jsonl)?;
            }
            if let Some(directory) = &args.output_dir {
                std::fs::create_dir_all(directory)?;
                for result in &results {
                    let extension = if args.json {
                        "json"
                    } else if args.jsonl {
                        "jsonl"
                    } else {
                        "txt"
                    };
                    let path = directory.join(format!("{}.{}", result.domain, extension));
                    write_scan_results(&path, std::slice::from_ref(result), args.json, args.jsonl)?;
                }
            }
        }
        Command::List(args) => {
            let database = Database::open(&database_path)?;
            let normalized = args
                .domain
                .as_deref()
                .map(util::normalize_domain)
                .transpose()?;
            let _ = args.all;
            let hosts = database.inventory(normalized.as_deref(), args.only_live)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&hosts)?);
            } else {
                for host in hosts {
                    println!(
                        "{}\t{}\t{}",
                        host.fqdn,
                        host.state,
                        host.last_verified_at
                            .map(|timestamp| timestamp.to_string())
                            .unwrap_or_else(|| "-".to_owned())
                    );
                }
            }
        }
        Command::Refresh(args) => {
            let database = Database::open(&database_path)?;
            let dns = make_dns(&args.dns)?;
            dns.seed_metrics(&database.resolver_history()?);
            let result = refresh_inventory(
                &database,
                &dns,
                &args.target,
                args.ttl_cap,
                args.negative_ttl,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::History(args) => {
            let database = Database::open(&database_path)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&database.history(args.limit)?)?
            );
        }
        Command::Stats => {
            let database = Database::open(&database_path)?;
            println!("{}", serde_json::to_string_pretty(&database.stats()?)?);
        }
        Command::Cache { action } => {
            let database = Database::open(&database_path)?;
            match action {
                CacheAction::Prune => {
                    println!("{} entrées expirées supprimées", database.prune_cache()?);
                }
            }
        }
        Command::Knowledge(args) => {
            let database = Database::open(&database_path)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&database.knowledge(args.limit)?)?
            );
        }
        Command::Sources(args) => {
            let statuses = source_statuses(&api_keys);
            let database = Database::open(&database_path)?;
            if args.check {
                if args.timeout <= 0.0 || !args.timeout.is_finite() {
                    bail!("--timeout doit être un nombre positif");
                }
                let target = util::normalize_domain(&args.target)?;
                let timeout = Duration::from_secs_f64(args.timeout);
                let checks = stream::iter(statuses.iter().cloned())
                    .map(|source| {
                        let api_keys = api_keys.clone();
                        let target = target.clone();
                        async move {
                            if source.requires_key && !source.configured {
                                return serde_json::json!({
                                    "name": source.name,
                                    "status": "skipped_missing_key",
                                    "names": 0,
                                    "duration_ms": 0,
                                    "metadata": source.metadata
                                });
                            }
                            let started = std::time::Instant::now();
                            match passive::fetch(&source.name, &target, timeout, &api_keys).await {
                                Ok(names) => serde_json::json!({
                                    "name": source.name,
                                    "status": if names.is_empty() { "empty" } else { "success" },
                                    "names": names.len(),
                                    "duration_ms": started.elapsed().as_millis(),
                                    "metadata": source.metadata
                                }),
                                Err(error) => serde_json::json!({
                                    "name": source.name,
                                    "status": "error",
                                    "names": 0,
                                    "duration_ms": started.elapsed().as_millis(),
                                    "error": format!("{error:#}"),
                                    "metadata": source.metadata
                                }),
                            }
                        }
                    })
                    .buffer_unordered(4)
                    .collect::<Vec<_>>()
                    .await;
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "target": target,
                            "checks": checks
                        }))?
                    );
                } else {
                    for check in checks {
                        println!(
                            "{:<22} {:<20} {:>6} nom(s) {:>7} ms{}",
                            check["name"].as_str().unwrap_or("?"),
                            check["status"].as_str().unwrap_or("?"),
                            check["names"].as_u64().unwrap_or_default(),
                            check["duration_ms"].as_u64().unwrap_or_default(),
                            check["error"]
                                .as_str()
                                .map(|error| format!(" — {}", compact_error(error, 120)))
                                .unwrap_or_default()
                        );
                    }
                }
                return Ok(());
            }
            let diagnostics = database.source_diagnostics(Duration::from_secs(24 * 3_600))?;
            if args.json {
                let sources = statuses
                    .into_iter()
                    .map(|source| {
                        let health = diagnostics.get(&source.name);
                        serde_json::json!({
                            "name": source.name,
                            "requires_key": source.requires_key,
                            "key_environment": source.key_environment,
                            "configured": source.configured,
                            "automatic": source.automatic,
                            "metadata": source.metadata,
                            "health": health
                        })
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "config": config_path,
                        "sources": sources
                    }))?
                );
            } else {
                println!("Configuration: {}", config_path.display());
                for source in statuses {
                    let diagnostic = diagnostics.get(&source.name);
                    let state = if let Some(wait) =
                        diagnostic.and_then(|diagnostic| diagnostic.retry_in_seconds)
                    {
                        format!("pause {}", wait_label(wait))
                    } else if source.automatic {
                        "auto".to_owned()
                    } else if source.requires_key {
                        "clé absente".to_owned()
                    } else {
                        "manuel".to_owned()
                    };
                    let key = source
                        .key_environment
                        .map(|variable| format!(" [{variable}]"))
                        .unwrap_or_default();
                    let metrics = diagnostic
                        .map(|diagnostic| {
                            format!(
                                " {}/{} succès, {} ms",
                                diagnostic.successes, diagnostic.requests, diagnostic.average_ms
                            )
                        })
                        .unwrap_or_default();
                    println!(
                        "{:<20} {:<14} {:<26}{}{}",
                        source.name, source.metadata.evidence_family, state, key, metrics
                    );
                    if let Some(error) = diagnostic.and_then(|value| value.last_error.as_deref()) {
                        println!("  dernière erreur: {}", compact_error(error, 140));
                    }
                }
            }
        }
        Command::Explain(args) => {
            let database = Database::open(&database_path)?;
            let fqdn = util::normalize_domain(&args.fqdn)?;
            let explanation = database.explain(&fqdn)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&explanation)?);
            } else if explanation["known"].as_bool() == Some(false) {
                println!("{fqdn}: inconnu de la base locale");
            } else {
                println!("{fqdn}");
                println!("  état: {}", explanation["inventory"]["state"]);
                println!(
                    "  dernière validation: {}",
                    explanation["inventory"]["last_verified_at"]
                );
                println!(
                    "  preuves: {} observation(s), {} validation(s) DNS, {} enregistrement(s)",
                    explanation["evidence"].as_array().map_or(0, Vec::len),
                    explanation["dns_verifications"]
                        .as_array()
                        .map_or(0, Vec::len),
                    explanation["dns_records"].as_array().map_or(0, Vec::len)
                );
                for evidence in explanation["evidence"].as_array().into_iter().flatten() {
                    println!(
                        "    - {} ({}, {} fois)",
                        evidence["source"], evidence["kind"], evidence["times_seen"]
                    );
                }
            }
        }
        Command::Resolvers { action } => match action {
            ResolverAction::Test(args) => {
                if args.timeout <= 0.0 || !args.timeout.is_finite() {
                    bail!("--timeout doit être un nombre positif");
                }
                let resolvers = if args.resolvers.is_empty() {
                    ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]
                        .into_iter()
                        .map(str::parse)
                        .collect::<std::result::Result<Vec<IpAddr>, _>>()?
                } else {
                    args.resolvers
                };
                let results =
                    DnsEngine::test_resolvers(&resolvers, Duration::from_secs_f64(args.timeout))
                        .await;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                } else {
                    for result in results {
                        println!(
                            "{:<15} {:<8} NX-hijack={} DNSSEC={} AD={} cohérent={} {}ms{}",
                            result.resolver,
                            if result.usable { "OK" } else { "REJET" },
                            result.hijacks_nxdomain,
                            result.dnssec_records,
                            result.validates_dnssec,
                            result.consistent,
                            result.average_ms,
                            result
                                .error
                                .map(|error| format!(" — {}", compact_error(&error, 100)))
                                .unwrap_or_default()
                        );
                    }
                }
            }
            ResolverAction::Benchmark(args) => {
                if args.timeout <= 0.0 || !args.timeout.is_finite() {
                    bail!("--timeout doit être un nombre positif");
                }
                let result = DnsEngine::benchmark_loopback(
                    args.queries,
                    args.concurrency,
                    Duration::from_secs_f64(args.timeout),
                )
                .await?;
                let serialized = serde_json::to_string_pretty(&result)?;
                if let Some(path) = args.output {
                    std::fs::write(path, format!("{serialized}\n"))?;
                }
                if args.json {
                    println!("{serialized}");
                } else {
                    println!(
                        "{:.0} req/s | {} complétées | {} échecs | perte {:.3}% | {} ms",
                        result.queries_per_second,
                        result.completed,
                        result.failures,
                        result.loss_rate * 100.0,
                        result.duration_ms
                    );
                }
            }
        },
        Command::Import(args) => {
            let domain = util::normalize_domain(&args.domain)?;
            let content = if args.input == std::path::Path::new("-") {
                let mut content = String::new();
                std::io::stdin().read_to_string(&mut content)?;
                content
            } else {
                std::fs::read_to_string(&args.input)?
            };
            let names = parse_import_names(&content, args.format, &domain);
            let source = format!("import:{:?}", args.format).to_ascii_lowercase();
            let database = Database::open(&database_path)?;
            let written = database.import_inventory(&domain, &names, &source)?;
            println!(
                "{} nom(s) importé(s) pour {} avec l'état unverified ({} écriture(s))",
                names.len(),
                domain,
                written
            );
        }
        Command::Export(args) => {
            let domain = args
                .domain
                .as_deref()
                .map(util::normalize_domain)
                .transpose()?;
            let database = Database::open(&database_path)?;
            let inventory = database.inventory(domain.as_deref(), args.only_live)?;
            let output = match args.format {
                ExportFormat::Jsonl => inventory
                    .iter()
                    .map(serde_json::to_string)
                    .collect::<serde_json::Result<Vec<_>>>()?
                    .join("\n"),
                ExportFormat::Csv => {
                    let mut rows = vec![
                        "fqdn,state,last_verified_at,first_seen,last_seen,times_seen,sources"
                            .to_owned(),
                    ];
                    rows.extend(inventory.iter().map(|entry| {
                        [
                            csv_field(&entry.fqdn),
                            entry.state.to_string(),
                            entry
                                .last_verified_at
                                .map(|value| value.to_string())
                                .unwrap_or_default(),
                            entry.first_seen.to_string(),
                            entry.last_seen.to_string(),
                            entry.times_seen.to_string(),
                            csv_field(&entry.sources.iter().cloned().collect::<Vec<_>>().join(";")),
                        ]
                        .join(",")
                    }));
                    rows.join("\n")
                }
            };
            if let Some(path) = args.output {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(path, output + if inventory.is_empty() { "" } else { "\n" })?;
            } else if !output.is_empty() {
                println!("{output}");
            }
        }
    }
    Ok(())
}
