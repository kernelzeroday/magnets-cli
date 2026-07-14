//! A small client for the Torznab protocol, used by self-hosted torrent indexers.
//!
//! The Shodan integration intentionally discovers only Bitmagnet's public
//! fingerprint. It then verifies `/torznab?t=caps` before issuing a search,
//! so arbitrary HTTP services from a Shodan result are never treated as an
//! indexer.

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use futures_util::{StreamExt, stream};
use quick_xml::{Reader, escape::unescape, events::Event};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    env,
    ffi::OsString,
    fs,
    io::IsTerminal,
    path::PathBuf,
    process::ExitCode,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{process::Command, time::timeout};

const USER_AGENT: &str = concat!("magnets/", env!("CARGO_PKG_VERSION"));
const DEFAULT_SHODAN_QUERY: &str = r#"http.title:"bitmagnet""#;
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";
const SEARCH_CACHE_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Parser)]
#[command(
    name = "magnets",
    version,
    about = "Search self-hosted Torznab-compatible torrent indexers",
    long_about = "Search any Torznab endpoint (for example Bitmagnet, Jackett, or another compatible indexer).\n\
\n\
Pass one or more full Torznab endpoint URLs with --indexer, set MAGNETS_INDEXERS\n\
to a comma-separated list, or use --shodan to discover publicly exposed\n\
Bitmagnet endpoints and verify them before search."
)]
struct Cli {
    /// Disable ANSI styling
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    /// Find public Bitmagnet Torznab endpoints using the local Shodan CLI
    Discover(DiscoverArgs),
    /// Search supplied Torznab endpoints concurrently
    Search(SearchArgs),
}

#[derive(Args, Clone)]
struct DiscoveryOptions {
    /// Shodan query to use (repeatable); defaults to Bitmagnet's title fingerprint
    #[arg(long = "shodan-query")]
    shodan_queries: Vec<String>,

    /// Maximum Shodan matches per query to inspect
    #[arg(long, default_value_t = 50)]
    shodan_limit: usize,

    /// Maximum simultaneous capability probes
    #[arg(long, default_value_t = 12)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Show rejected candidates and request failures
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Args)]
struct DiscoverArgs {
    #[command(flatten)]
    discovery: DiscoveryOptions,

    /// Emit machine-readable JSON
    #[arg(short, long)]
    json: bool,
}

#[derive(Args)]
struct SearchArgs {
    /// Search terms
    #[arg(required = true)]
    query: Vec<String>,

    /// Full Torznab endpoint URL; may be supplied more than once
    #[arg(short, long, visible_alias = "source")]
    indexer: Vec<String>,

    /// Discover public Bitmagnet endpoints with Shodan before searching
    #[arg(long)]
    shodan: bool,

    #[command(flatten)]
    discovery: DiscoveryOptions,

    /// Torznab API key added as the `apikey` parameter
    #[arg(long, env = "MAGNETS_API_KEY")]
    api_key: Option<String>,

    /// Maximum combined results to print
    #[arg(short = 'n', long, default_value_t = 20)]
    limit: usize,

    /// Concurrent endpoint count per fallback batch
    #[arg(long, default_value_t = 10)]
    fanout: usize,

    /// Number of results requested from each endpoint before combining them
    #[arg(long, default_value_t = 20)]
    per_source_limit: usize,

    /// Emit machine-readable JSON
    #[arg(short, long)]
    json: bool,
}

#[derive(Debug, Clone)]
struct Source {
    endpoint: Url,
    origin: String,
}

impl Source {
    fn label(&self) -> String {
        let host = self
            .endpoint
            .host_str()
            .map(str::to_string)
            .unwrap_or_else(|| self.endpoint.to_string());
        match self.endpoint.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }
}

#[derive(Debug, Serialize)]
struct DiscoveryResult {
    endpoint: String,
    origin: String,
    latency_ms: u128,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct Torrent {
    source: String,
    title: String,
    magnet: Option<String>,
    download: Option<String>,
    details: Option<String>,
    category: Option<String>,
    published: Option<String>,
    size_bytes: Option<u64>,
    seeders: Option<u64>,
    leechers: Option<u64>,
    grabs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CachedSearch {
    saved_at_secs: u64,
    torrents: Vec<Torrent>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = parse_cli();
    let color = color_enabled(cli.no_color);
    match run(cli, color).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{} {error:#}",
                paint(BOLD, &paint(RED, "error:", color), color)
            );
            ExitCode::FAILURE
        }
    }
}

/// Treat an unrecognised first positional argument as a search query. This
/// keeps `magnets fedora` as convenient as the older one-site CLIs while
/// retaining explicit `discover` and `search` subcommands.
fn parse_cli() -> Cli {
    let mut arguments: Vec<OsString> = env::args_os().collect();
    let first = arguments.get(1).and_then(|value| value.to_str());
    let is_command = matches!(first, Some("discover" | "search" | "help"));
    let is_global_option = first.is_some_and(|value| value.starts_with('-'));
    if first.is_some() && !is_command && !is_global_option {
        arguments.insert(1, OsString::from("search"));
    }
    Cli::parse_from(arguments)
}

async fn run(cli: Cli, color: bool) -> Result<()> {
    match cli.command {
        CommandKind::Discover(args) => {
            let client = build_client(args.discovery.timeout)?;
            let results = discover(&client, &args.discovery).await?;
            if let Some(path) = save_discovered_sources(&results)? {
                eprintln!(
                    "Saved {} verified endpoint(s) to {}",
                    results.len(),
                    path.display()
                );
            }
            if args.json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                print_discovery(&results, color);
            }
        }
        CommandKind::Search(args) => search(args, color).await?,
    }
    Ok(())
}

fn build_client(timeout_seconds: u64) -> Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(timeout_seconds))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("could not build HTTP client")
}

async fn search(args: SearchArgs, color: bool) -> Result<()> {
    validate_discovery_options(&args.discovery)?;
    if !(1..=100).contains(&args.limit) {
        bail!("--limit must be between 1 and 100");
    }
    if !(1..=100).contains(&args.per_source_limit) {
        bail!("--per-source-limit must be between 1 and 100");
    }
    if !(1..=100).contains(&args.fanout) {
        bail!("--fanout must be between 1 and 100");
    }
    let client = build_client(args.discovery.timeout)?;
    let mut sources = configured_sources(&args.indexer)?;

    if args.shodan {
        let discovered = discover(&client, &args.discovery).await?;
        if let Some(path) = save_discovered_sources(&discovered)? {
            eprintln!(
                "Saved {} verified endpoint(s) to {}",
                discovered.len(),
                path.display()
            );
        }
        sources.extend(discovered.into_iter().filter_map(|result| {
            Url::parse(&result.endpoint).ok().map(|endpoint| Source {
                endpoint,
                origin: result.origin,
            })
        }));
    }

    sources = deduplicate_sources(sources);
    if sources.is_empty() {
        bail!("provide --indexer <full Torznab URL>, set MAGNETS_INDEXERS, or add --shodan");
    }

    let query = args.query.join(" ");
    let api_key = args.api_key.as_deref();
    let mut torrents = Vec::new();
    let mut failures = Vec::new();

    // Public instances are often briefly overloaded or disappear. Search the
    // fastest batch first, then continue through the cached list only if that
    // batch produces no usable result.
    for batch in sources.chunks(args.fanout) {
        let searches =
            stream::iter(batch.iter().cloned().map(|source| {
                let client = client.clone();
                let query = query.clone();
                async move {
                    search_source(&client, source, &query, args.per_source_limit, api_key).await
                }
            }))
            .buffer_unordered(args.discovery.concurrency)
            .collect::<Vec<_>>()
            .await;

        for result in searches {
            match result {
                Ok(mut response) => torrents.append(&mut response),
                Err(error) => failures.push(error),
            }
        }
        if !torrents.is_empty() {
            break;
        }
    }

    if args.discovery.verbose {
        for failure in &failures {
            eprintln!("warning: {failure:#}");
        }
    }

    torrents.sort_by(|a, b| {
        b.seeders
            .cmp(&a.seeders)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.title.cmp(&b.title))
    });
    torrents.truncate(args.limit);

    if torrents.is_empty() {
        if let Some(cached) = load_cached_search(&query) {
            eprintln!(
                "warning: live indexers are unavailable; showing a cached result from the last {} minutes",
                SEARCH_CACHE_TTL.as_secs() / 60
            );
            if args.json {
                println!("{}", serde_json::to_string_pretty(&cached)?);
            } else {
                print_torrents(&cached, color);
            }
            return Ok(());
        }
        if failures.is_empty() {
            bail!("no results found for: {query}");
        }
        bail!("no indexer returned results for: {query} (use --verbose for request failures)");
    }

    if let Err(error) = save_cached_search(&query, &torrents)
        && args.discovery.verbose
    {
        eprintln!("warning: could not save search cache: {error:#}");
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&torrents)?);
    } else {
        print_torrents(&torrents, color);
    }
    Ok(())
}

fn configured_sources(indexers: &[String]) -> Result<Vec<Source>> {
    if !indexers.is_empty() {
        return parse_sources(indexers.to_vec(), "cli");
    }

    if let Some(value) = env::var_os("MAGNETS_INDEXERS") {
        let sources = value
            .to_string_lossy()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect();
        return parse_sources(sources, "environment");
    }

    parse_sources(load_discovered_sources()?, "discovery cache")
}

fn parse_sources(raw: Vec<String>, origin: &str) -> Result<Vec<Source>> {
    raw.into_iter()
        .map(|input| {
            let endpoint = Url::parse(&input).with_context(|| {
                format!("invalid indexer URL `{input}`; pass the full Torznab endpoint URL")
            })?;
            match endpoint.scheme() {
                "http" | "https" => Ok(Source {
                    endpoint,
                    origin: origin.to_string(),
                }),
                scheme => bail!("unsupported URL scheme `{scheme}` for `{input}`"),
            }
        })
        .collect()
}

fn discovered_sources_path() -> Option<PathBuf> {
    if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(path).join("magnets").join("indexers"));
    }
    env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/magnets/indexers"))
}

fn load_discovered_sources() -> Result<Vec<String>> {
    let Some(path) = discovered_sources_path() else {
        return Ok(Vec::new());
    };
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&path)
        .with_context(|| format!("could not read saved endpoints from {}", path.display()))?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn save_discovered_sources(results: &[DiscoveryResult]) -> Result<Option<PathBuf>> {
    if results.is_empty() {
        return Ok(None);
    }
    let Some(path) = discovered_sources_path() else {
        return Ok(None);
    };
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("discovery cache path has no parent"))?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "could not create discovery cache directory {}",
            parent.display()
        )
    })?;
    let content = results
        .iter()
        .map(|result| result.endpoint.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&path, format!("{content}\n"))
        .with_context(|| format!("could not save endpoints to {}", path.display()))?;
    Ok(Some(path))
}

fn search_cache_path(query: &str) -> Option<PathBuf> {
    let base = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(
        base.join("magnets")
            .join("searches")
            .join(format!("{:016x}.json", query_hash(query))),
    )
}

fn query_hash(query: &str) -> u64 {
    // A stable cache filename, not a security boundary.
    query
        .to_lowercase()
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

fn load_cached_search(query: &str) -> Option<Vec<Torrent>> {
    let path = search_cache_path(query)?;
    let content = fs::read_to_string(path).ok()?;
    let cached: CachedSearch = serde_json::from_str(&content).ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    if now.saturating_sub(cached.saved_at_secs) <= SEARCH_CACHE_TTL.as_secs() {
        Some(cached.torrents)
    } else {
        None
    }
}

fn save_cached_search(query: &str, torrents: &[Torrent]) -> Result<()> {
    let Some(path) = search_cache_path(query) else {
        return Ok(());
    };
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("search cache path has no parent"))?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "could not create search cache directory {}",
            parent.display()
        )
    })?;
    let saved_at_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let content = serde_json::to_string(&CachedSearch {
        saved_at_secs,
        torrents: torrents.to_vec(),
    })?;
    fs::write(&path, content)
        .with_context(|| format!("could not write search cache {}", path.display()))
}

async fn discover(client: &Client, options: &DiscoveryOptions) -> Result<Vec<DiscoveryResult>> {
    validate_discovery_options(options)?;
    let mut candidates = Vec::new();
    let queries = if options.shodan_queries.is_empty() {
        vec![DEFAULT_SHODAN_QUERY.to_string()]
    } else {
        options.shodan_queries.clone()
    };

    for query in queries {
        if options.verbose {
            eprintln!("shodan: {query}");
        }
        candidates.extend(discover_shodan(&query, options.shodan_limit).await?);
    }

    candidates = deduplicate_sources(candidates);
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let probes = stream::iter(candidates.into_iter().map(|source| {
        let client = client.clone();
        async move { probe_source(&client, source).await }
    }))
    .buffer_unordered(options.concurrency)
    .collect::<Vec<_>>()
    .await;

    let mut working = Vec::new();
    for probe in probes {
        match probe {
            Ok(result) => working.push(result),
            Err(error) if options.verbose => eprintln!("reject: {error:#}"),
            Err(_) => {}
        }
    }
    working.sort_by_key(|item| item.latency_ms);
    Ok(working)
}

fn validate_discovery_options(options: &DiscoveryOptions) -> Result<()> {
    if !(1..=1000).contains(&options.shodan_limit) {
        bail!("--shodan-limit must be between 1 and 1000");
    }
    if !(1..=100).contains(&options.concurrency) {
        bail!("--concurrency must be between 1 and 100");
    }
    if !(1..=120).contains(&options.timeout) {
        bail!("--timeout must be between 1 and 120 seconds");
    }
    Ok(())
}

async fn discover_shodan(query: &str, limit: usize) -> Result<Vec<Source>> {
    let output = timeout(
        Duration::from_secs(30),
        Command::new("shodan")
            .args([
                "search",
                "--fields",
                "ip_str,port",
                "--limit",
                &limit.to_string(),
                query,
            ])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("Shodan CLI timed out after 30 seconds"))?
    .context("could not run the Shodan CLI; install it and run `shodan init <API_KEY>`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!("Shodan CLI failed: {stderr}");
    }

    let mut sources = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut fields = line.split('\t').map(str::trim);
        let Some(host) = fields.next().filter(|value| !value.is_empty()) else {
            continue;
        };
        let Some(port) = fields.next().and_then(|value| value.parse::<u16>().ok()) else {
            continue;
        };
        if let Ok(endpoint) = Url::parse(&shodan_torznab_url(host, port)) {
            sources.push(Source {
                endpoint,
                origin: "shodan:bitmagnet".to_string(),
            });
        }
    }
    Ok(sources)
}

fn shodan_torznab_url(host: &str, port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match port {
        443 => format!("https://{host}/torznab"),
        80 => format!("http://{host}/torznab"),
        _ => format!("http://{host}:{port}/torznab"),
    }
}

async fn probe_source(client: &Client, source: Source) -> Result<DiscoveryResult> {
    let endpoint = torznab_url(&source.endpoint, [("t", "caps")], None)?;
    let started = Instant::now();
    let response = client
        .get(endpoint.clone())
        .send()
        .await
        .with_context(|| format!("{} did not respond", source.endpoint))?
        .error_for_status()
        .with_context(|| format!("{} returned an HTTP error", source.endpoint))?;
    let body = response
        .text()
        .await
        .with_context(|| format!("could not read response from {}", source.endpoint))?;
    if !is_caps_document(&body) {
        bail!("{} is not a Torznab endpoint", source.endpoint);
    }
    Ok(DiscoveryResult {
        endpoint: source.endpoint.to_string(),
        origin: source.origin,
        latency_ms: started.elapsed().as_millis(),
    })
}

async fn search_source(
    client: &Client,
    source: Source,
    query: &str,
    limit: usize,
    api_key: Option<&str>,
) -> Result<Vec<Torrent>> {
    let endpoint = torznab_url(
        &source.endpoint,
        [("t", "search"), ("q", query), ("limit", &limit.to_string())],
        api_key,
    )?;
    let response = client
        .get(endpoint)
        .send()
        .await
        .with_context(|| format!("{} did not respond", source.endpoint))?
        .error_for_status()
        .with_context(|| format!("{} returned an HTTP error", source.endpoint))?;
    let body = response
        .text()
        .await
        .with_context(|| format!("could not read response from {}", source.endpoint))?;
    if body.contains("<error") {
        bail!("{} returned a Torznab error", source.endpoint);
    }

    let mut results = parse_feed(&body)
        .with_context(|| format!("invalid Torznab XML from {}", source.endpoint))?;
    for result in &mut results {
        result.source = source.label();
    }
    Ok(results)
}

fn torznab_url<'a, const N: usize>(
    endpoint: &Url,
    pairs: [(&'a str, &'a str); N],
    api_key: Option<&str>,
) -> Result<Url> {
    let mut url = endpoint.clone();
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
        if let Some(key) = api_key {
            query.append_pair("apikey", key);
        }
    }
    Ok(url)
}

fn deduplicate_sources(sources: Vec<Source>) -> Vec<Source> {
    let mut seen = HashSet::new();
    sources
        .into_iter()
        .filter(|source| {
            seen.insert(
                source
                    .endpoint
                    .as_str()
                    .trim_end_matches('/')
                    .to_lowercase(),
            )
        })
        .collect()
}

fn is_caps_document(xml: &str) -> bool {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) | Ok(Event::Empty(event)) => {
                return local_name(event.name().as_ref()) == "caps";
            }
            Ok(Event::Decl(_) | Event::Comment(_) | Event::DocType(_) | Event::Text(_)) => {}
            Ok(Event::Eof) | Err(_) => return false,
            _ => {}
        }
    }
}

fn parse_feed(xml: &str) -> Result<Vec<Torrent>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut results = Vec::new();
    let mut current: Option<Torrent> = None;
    let mut field: Option<String> = None;

    loop {
        match reader.read_event()? {
            Event::Start(event) => {
                let name = local_name(event.name().as_ref()).to_string();
                if name == "item" {
                    current = Some(Torrent::default());
                    field = None;
                } else if let Some(item) = current.as_mut() {
                    if name == "enclosure" {
                        let attributes = attributes(&event)?;
                        if let Some(url) = attributes.get("url") {
                            set_link(item, url);
                        }
                        if item.size_bytes.is_none() {
                            item.size_bytes = attributes
                                .get("length")
                                .and_then(|value| value.parse().ok());
                        }
                        field = None;
                    } else if name == "attr" {
                        let attributes = attributes(&event)?;
                        set_torznab_attr(item, &attributes);
                        field = None;
                    } else {
                        field = Some(name);
                    }
                }
            }
            Event::Empty(event) => {
                if let Some(item) = current.as_mut() {
                    match local_name(event.name().as_ref()) {
                        "enclosure" => {
                            let attributes = attributes(&event)?;
                            if let Some(url) = attributes.get("url") {
                                set_link(item, url);
                            }
                            if item.size_bytes.is_none() {
                                item.size_bytes = attributes
                                    .get("length")
                                    .and_then(|value| value.parse().ok());
                            }
                        }
                        "attr" => set_torznab_attr(item, &attributes(&event)?),
                        _ => {}
                    }
                }
            }
            Event::Text(text) => {
                if let (Some(item), Some(name)) = (current.as_mut(), field.as_deref()) {
                    let value = decode_xml_text(text.as_ref())?;
                    set_text_field(item, name, value);
                }
            }
            Event::CData(text) => {
                if let (Some(item), Some(name)) = (current.as_mut(), field.as_deref()) {
                    let value = decode_xml_text(text.as_ref())?;
                    set_text_field(item, name, value);
                }
            }
            Event::End(event) => {
                let name = local_name(event.name().as_ref()).to_string();
                if name == "item" {
                    if let Some(item) = current.take().filter(|item| !item.title.is_empty()) {
                        results.push(item);
                    }
                    field = None;
                } else if field.as_deref() == Some(name.as_str()) {
                    field = None;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(results)
}

fn local_name(name: &[u8]) -> &str {
    std::str::from_utf8(name)
        .unwrap_or_default()
        .rsplit(':')
        .next()
        .unwrap_or_default()
}

fn attributes(
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<std::collections::HashMap<String, String>> {
    event
        .attributes()
        .map(|attribute| {
            let attribute = attribute?;
            let key = local_name(attribute.key.as_ref()).to_string();
            let value = decode_xml_text(attribute.value.as_ref())?;
            Ok((key, value))
        })
        .collect()
}

fn decode_xml_text(value: &[u8]) -> Result<String> {
    let value = std::str::from_utf8(value).context("XML was not UTF-8")?;
    Ok(unescape(value)?.into_owned())
}

fn set_link(item: &mut Torrent, value: &str) {
    if value.starts_with("magnet:") {
        item.magnet = Some(value.to_string());
    } else if !value.is_empty() {
        item.download = Some(value.to_string());
    }
}

fn set_torznab_attr(item: &mut Torrent, attributes: &std::collections::HashMap<String, String>) {
    let (Some(name), Some(value)) = (attributes.get("name"), attributes.get("value")) else {
        return;
    };
    match name.as_str() {
        "magneturl" => item.magnet = Some(value.clone()),
        "seeders" => item.seeders = value.parse().ok(),
        "peers" => item.leechers = value.parse().ok(),
        "leechers" => item.leechers = value.parse().ok(),
        "grabs" | "downloads" => item.grabs = value.parse().ok(),
        "size" => item.size_bytes = value.parse().ok(),
        "infohash" if item.magnet.is_none() => {
            item.magnet = Some(format!("magnet:?xt=urn:btih:{value}"));
        }
        _ => {}
    }
}

fn set_text_field(item: &mut Torrent, name: &str, value: String) {
    if value.is_empty() {
        return;
    }
    match name {
        "title" => item.title = value,
        "guid" | "link" => {
            if value.starts_with("magnet:") {
                item.magnet = Some(value);
            } else if name == "link" {
                item.details = Some(value);
            }
        }
        "category" => item.category = Some(value),
        "pubDate" | "published" => item.published = Some(value),
        "size" if item.size_bytes.is_none() => item.size_bytes = value.parse().ok(),
        _ => {}
    }
}

fn print_discovery(results: &[DiscoveryResult], color: bool) {
    if results.is_empty() {
        println!(
            "{}",
            paint(YELLOW, "No reachable Torznab endpoints found.", color)
        );
        return;
    }
    println!(
        "{:<58} {:>8}  {}",
        paint(BOLD, "ENDPOINT", color),
        paint(BOLD, "LATENCY", color),
        paint(BOLD, "SOURCE", color)
    );
    println!("{}", paint(DIM, &"─".repeat(86), color));
    for result in results {
        println!(
            "{:<58} {:>7}{}  {}",
            paint(CYAN, &result.endpoint, color),
            paint(DIM, &result.latency_ms.to_string(), color),
            paint(DIM, "ms", color),
            paint(DIM, &result.origin, color)
        );
    }
    eprintln!(
        "\n{} verified endpoint(s)",
        paint(GREEN, &results.len().to_string(), color)
    );
}

fn print_torrents(torrents: &[Torrent], color: bool) {
    for (position, torrent) in torrents.iter().enumerate() {
        println!(
            "{}. {}  {}",
            paint(DIM, &(position + 1).to_string(), color),
            paint(&format!("{BOLD}{CYAN}"), &torrent.title, color),
            paint(DIM, &format!("[{}]", torrent.source), color)
        );
        let mut metadata = Vec::new();
        if let Some(size) = torrent.size_bytes {
            metadata.push(paint(YELLOW, &format_bytes(size), color));
        }
        if let Some(seeders) = torrent.seeders {
            metadata.push(paint(GREEN, &format!("{seeders} seeds"), color));
        }
        if let Some(leechers) = torrent.leechers {
            metadata.push(paint(RED, &format!("{leechers} leech"), color));
        }
        if let Some(grabs) = torrent.grabs {
            metadata.push(paint(DIM, &format!("{grabs} grabs"), color));
        }
        if let Some(category) = &torrent.category {
            metadata.push(paint(MAGENTA, category, color));
        }
        if let Some(published) = &torrent.published {
            metadata.push(paint(DIM, published, color));
        }
        if !metadata.is_empty() {
            println!("   {}", metadata.join(&paint(DIM, " · ", color)));
        }
        if let Some(magnet) = &torrent.magnet {
            println!("{}", paint(DIM, magnet, color));
        } else if let Some(download) = &torrent.download {
            println!("{}", paint(DIM, download, color));
        } else if let Some(details) = &torrent.details {
            println!("{}", paint(DIM, details, color));
        }
        println!();
    }
}

fn color_enabled(no_color: bool) -> bool {
    !no_color && env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn paint(code: &str, text: &str, enabled: bool) -> String {
    if enabled {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

fn format_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{size:.2} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_torznab_result_feed() {
        let xml = r#"<?xml version="1.0"?>
            <rss xmlns:torznab="http://torznab.com/schemas/2015/feed"><channel>
              <item>
                <title>Ubuntu &amp; Friends</title>
                <guid>magnet:?xt=urn:btih:abc</guid>
                <link>https://indexer.example/details/42</link>
                <category>5000</category>
                <pubDate>Mon, 01 Jan 2026 00:00:00 +0000</pubDate>
                <enclosure url="https://indexer.example/download/42" length="1073741824" type="application/x-bittorrent"/>
                <torznab:attr name="seeders" value="27"/>
                <torznab:attr name="peers" value="4"/>
                <torznab:attr name="grabs" value="9"/>
              </item>
            </channel></rss>"#;
        let results = parse_feed(xml).expect("feed parses");
        assert_eq!(results.len(), 1);
        let result = &results[0];
        assert_eq!(result.title, "Ubuntu & Friends");
        assert_eq!(result.magnet.as_deref(), Some("magnet:?xt=urn:btih:abc"));
        assert_eq!(
            result.download.as_deref(),
            Some("https://indexer.example/download/42")
        );
        assert_eq!(result.seeders, Some(27));
        assert_eq!(result.leechers, Some(4));
        assert_eq!(result.size_bytes, Some(1_073_741_824));
    }

    #[test]
    fn preserves_existing_endpoint_query_parameters() {
        let endpoint = Url::parse("https://example.test/torznab?profile=linux").unwrap();
        let url = torznab_url(&endpoint, [("t", "search"), ("q", "ubuntu")], Some("key")).unwrap();
        assert_eq!(
            url.as_str(),
            "https://example.test/torznab?profile=linux&t=search&q=ubuntu&apikey=key"
        );
    }

    #[test]
    fn converts_shodan_address_to_torznab_endpoint() {
        assert_eq!(
            shodan_torznab_url("203.0.113.7", 3333),
            "http://203.0.113.7:3333/torznab"
        );
        assert_eq!(
            shodan_torznab_url("2001:db8::1", 443),
            "https://[2001:db8::1]/torznab"
        );
    }

    #[test]
    fn identifies_caps_documents() {
        assert!(is_caps_document(
            "<?xml version=\"1.0\"?><caps serverType=\"newznab\"/>"
        ));
        assert!(!is_caps_document("<html><title>bitmagnet</title></html>"));
    }
}
