//! Configuration, read only from `PINGENV_*` environment variables.
//!
//! Every variable carries the prefix so that anything unrecognised under it is
//! an error: a typo is reported instead of being silently ignored, and
//! unrelated variables in the environment can never be mistaken for settings.
//!
//! Parsing takes an iterator of pairs rather than reading the process
//! environment directly, so the whole thing is testable. Every problem found is
//! collected and reported at once: fixing a container's environment one error
//! per restart is miserable.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// How hosts without their own certificate files get a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// No HTTPS listener at all.
    Off,
    /// Certificates are requested from an ACME CA (HTTP-01).
    Acme,
    /// A self-signed certificate is generated at startup. For local use.
    SelfSigned,
    /// Every route must name its own certificate and key files.
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Upstream {
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// A directory served straight from this process instead of an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticSite {
    pub root: PathBuf,
    /// Files up to this size are read into memory at startup; larger ones are
    /// streamed from disk. Zero keeps everything on disk.
    pub memory_max_file: u64,
    /// URL paths below the root (files or directories) eligible for memory,
    /// without a trailing slash. An empty entry is the root: everything.
    pub memory_paths: Vec<String>,
    /// How long a memory copy is trusted before the file is checked again.
    /// `None` never re-checks: the copy is a startup snapshot.
    pub memory_refresh: Option<Duration>,
    /// Served for paths that match no file, for single-page applications.
    pub fallback: Option<String>,
    pub cache_control: String,
    /// Send text compressed to clients that accept it: a gzip copy of files
    /// held in memory, and precompressed `.br` / `.gz` copies found next to
    /// a file.
    pub compress: bool,
}

#[derive(Debug, Clone)]
pub struct Route {
    /// The `<NAME>` part of `ROUTE_<NAME>_*`, lowercased. Used in logs.
    pub name: String,
    /// Lowercase host names; `*.example.com` matches one extra label.
    pub hosts: Vec<String>,
    /// Path prefix, always starting with `/` and without a trailing `/`
    /// (except for the root itself).
    pub path: String,
    pub strip_prefix: bool,
    /// Empty when the route serves files.
    pub upstreams: Vec<Upstream>,
    pub site: Option<StaticSite>,
    /// Overrides the `Host` header sent to the upstream.
    pub set_host: Option<String>,
    pub cert_files: Option<CertFiles>,
    /// Let `/.well-known/acme-challenge/` requests that this process has no
    /// answer for reach the upstream (or files), without the HTTPS redirect.
    pub acme_passthrough: bool,
    /// `Some(None)` disables the upstream read timeout for this route.
    pub read_timeout: Option<Option<Duration>>,
    /// Overrides the global limit on request bodies; `Some(None)` lifts it.
    pub max_body_size: Option<Option<u64>>,
}

/// `None` means no limit.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub upstream_connect: Option<Duration>,
    pub upstream_read: Option<Duration>,
    pub write: Option<Duration>,
    /// How long a client connection may stay open with no request on it.
    pub client_idle: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub email: Option<String>,
    /// Extra root certificate to trust when talking to the ACME server.
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub http_addr: SocketAddr,
    pub https_addr: SocketAddr,
    pub tls: TlsMode,
    /// Offer HTTP/2 on the HTTPS listener.
    pub http2: bool,
    pub https_redirect: bool,
    /// Port used in redirect `Location` headers; differs from the listen port
    /// when the container port is published on another one.
    pub https_redirect_port: u16,
    pub data_dir: PathBuf,
    pub acme: AcmeConfig,
    pub routes: Vec<Route>,
    /// Upper bound on file bytes held in memory across all routes.
    pub memory_max_total: u64,
    /// Largest request body accepted, unless a route sets its own. `None`
    /// means no limit.
    pub max_body_size: Option<u64>,
    pub timeouts: Timeouts,
    /// `Strict-Transport-Security` value, sent on HTTPS responses.
    pub hsts: Option<String>,
    /// How often certificate files given with `TLS_CERT_FILE` are re-checked.
    pub cert_reload_interval: Duration,
    pub threads: usize,
    pub shutdown_grace_seconds: u64,
    pub log_level: log::LevelFilter,
}

pub const PREFIX: &str = "PINGENV_";

const GLOBALS: &[&str] = &[
    "TLS_MODE",
    "HTTP_ADDR",
    "HTTPS_ADDR",
    "HTTP2",
    "HTTPS_REDIRECT",
    "HTTPS_REDIRECT_PORT",
    "DATA_DIR",
    "ACME_EMAIL",
    "ACME_STAGING",
    "ACME_DIRECTORY_URL",
    "ACME_CA_FILE",
    "MEMORY_MAX_TOTAL",
    "MAX_BODY_SIZE",
    "UPSTREAM_CONNECT_TIMEOUT",
    "UPSTREAM_READ_TIMEOUT",
    "WRITE_TIMEOUT",
    "IDLE_TIMEOUT",
    "HSTS",
    "CERT_RELOAD_INTERVAL",
    "THREADS",
    "SHUTDOWN_GRACE_SECONDS",
    "LOG_LEVEL",
];

/// Globals that only mean something with a TLS mode. `HSTS` and
/// `HTTPS_REDIRECT` are in the same position and have their own messages.
const TLS_ONLY: &[&str] = &[
    "HTTPS_ADDR",
    "HTTP2",
    "HTTPS_REDIRECT_PORT",
    "DATA_DIR",
    "ACME_EMAIL",
    "ACME_STAGING",
    "ACME_DIRECTORY_URL",
    "ACME_CA_FILE",
    "CERT_RELOAD_INTERVAL",
];

const ROUTE_FIELDS: &[&str] = &[
    "MEMORY_MAX_FILE",
    "MEMORY_PATHS",
    "MEMORY_REFRESH",
    "ACME_PASSTHROUGH",
    "MAX_BODY_SIZE",
    "READ_TIMEOUT",
    "CACHE_CONTROL",
    "COMPRESS",
    "TLS_CERT_FILE",
    "TLS_KEY_FILE",
    "STRIP_PREFIX",
    "SET_HOST",
    "UPSTREAM",
    "FALLBACK",
    "HOST",
    "PATH",
    "ROOT",
];

/// Off by default: the operating system already keeps hot files in its page
/// cache, so a copy in this process mostly adds staleness.
const DEFAULT_MEMORY_MAX_FILE: u64 = 0;
const DEFAULT_MEMORY_REFRESH: Duration = Duration::from_secs(5 * 60);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// Long enough for a browser to reuse the connection for its next click,
/// short enough that connections nobody uses do not pile up.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
/// Enough for forms and API calls. An application that takes uploads says so,
/// on its route.
const DEFAULT_MAX_BODY_SIZE: u64 = 1024 * 1024;
const DEFAULT_CERT_RELOAD_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_MEMORY_MAX_TOTAL: u64 = 128 * 1024 * 1024;
const DEFAULT_CACHE_CONTROL: &str = "no-cache";

impl Config {
    pub fn from_env<I>(vars: I) -> Result<Config, Vec<String>>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut errors = Vec::new();
        let mut globals: BTreeMap<String, String> = BTreeMap::new();
        let mut raw_routes: BTreeMap<String, BTreeMap<&'static str, String>> = BTreeMap::new();

        for (full_key, value) in vars {
            let Some(key) = full_key.strip_prefix(PREFIX).map(str::to_string) else {
                continue;
            };
            let value = value.trim().to_string();
            if let Some(rest) = key.strip_prefix("ROUTE_") {
                // Longest field name first, so `ROUTE_A_TLS_CERT_FILE` is not
                // read as a route called `A_TLS_CERT` with a `FILE` field.
                let field = ROUTE_FIELDS.iter().find_map(|f| {
                    let name = rest.strip_suffix(f)?.strip_suffix('_')?;
                    (!name.is_empty()).then_some((name, *f))
                });
                match field {
                    Some((name, field)) => {
                        raw_routes
                            .entry(name.to_string())
                            .or_default()
                            .insert(field, value);
                    }
                    None => errors.push(format!(
                        "{full_key}: unknown route setting (expected {PREFIX}ROUTE_<NAME>_ followed by one of {})",
                        ROUTE_FIELDS.join(", ")
                    )),
                }
            } else if GLOBALS.contains(&key.as_str()) {
                globals.insert(key, value);
            } else {
                errors.push(format!("{full_key}: unknown setting"));
            }
        }

        let get = |k: &str| globals.get(k).filter(|v| !v.is_empty()).cloned();

        let mut tls_mode_understood = true;
        let tls = match get("TLS_MODE")
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("off") => TlsMode::Off,
            Some("acme") => TlsMode::Acme,
            Some("selfsigned") | Some("self-signed") => TlsMode::SelfSigned,
            Some("manual") => TlsMode::Manual,
            Some(other) => {
                errors.push(format!(
                    "PINGENV_TLS_MODE: '{other}' is not one of off, acme, selfsigned, manual"
                ));
                tls_mode_understood = false;
                TlsMode::Off
            }
        };

        let http_addr = parse_addr(
            &mut errors,
            "PINGENV_HTTP_ADDR",
            get("HTTP_ADDR"),
            "0.0.0.0:80",
        );
        let https_addr = parse_addr(
            &mut errors,
            "PINGENV_HTTPS_ADDR",
            get("HTTPS_ADDR"),
            "0.0.0.0:443",
        );
        let http2 = parse_bool(&mut errors, "PINGENV_HTTP2", get("HTTP2"), true);
        let https_redirect = parse_bool(
            &mut errors,
            "PINGENV_HTTPS_REDIRECT",
            get("HTTPS_REDIRECT"),
            tls != TlsMode::Off,
        );
        if https_redirect && tls == TlsMode::Off {
            errors.push(
                "PINGENV_HTTPS_REDIRECT: cannot redirect to HTTPS while PINGENV_TLS_MODE is off"
                    .into(),
            );
        }
        let https_redirect_port = parse_num(
            &mut errors,
            "PINGENV_HTTPS_REDIRECT_PORT",
            get("HTTPS_REDIRECT_PORT"),
            443u16,
        );

        let staging = parse_bool(
            &mut errors,
            "PINGENV_ACME_STAGING",
            get("ACME_STAGING"),
            false,
        );
        let directory_url = match get("ACME_DIRECTORY_URL") {
            Some(url) => {
                if staging {
                    errors.push(
                        "PINGENV_ACME_STAGING and PINGENV_ACME_DIRECTORY_URL are both set; use one"
                            .into(),
                    );
                }
                if !url.starts_with("https://") {
                    errors.push("PINGENV_ACME_DIRECTORY_URL: must start with https://".into());
                }
                url
            }
            None if staging => LETS_ENCRYPT_STAGING.to_string(),
            None => LETS_ENCRYPT_PRODUCTION.to_string(),
        };
        // With TLS off these would be read and then do nothing, which is how
        // a forgotten PINGENV_TLS_MODE=acme becomes a plain HTTP server. (If
        // the mode itself is wrong, that one error says enough.)
        if tls == TlsMode::Off && tls_mode_understood {
            let set = TLS_ONLY.iter().filter(|key| get(key).is_some());
            // `false` spells out the default, which is not a mistake.
            for key in set.filter(|key| **key != "ACME_STAGING" || staging) {
                errors.push(format!(
                    "PINGENV_{key}: does nothing while PINGENV_TLS_MODE is off (the default); \
                     set PINGENV_TLS_MODE to acme, selfsigned or manual, or remove it"
                ));
            }
        }
        let email = get("ACME_EMAIL");
        if let Some(e) = &email
            && (!e.contains('@') || e.contains(char::is_whitespace))
        {
            errors.push(format!(
                "PINGENV_ACME_EMAIL: '{e}' does not look like an email address"
            ));
        }

        let default_threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        let memory_max_total = match get("MEMORY_MAX_TOTAL") {
            None => DEFAULT_MEMORY_MAX_TOTAL,
            Some(v) => parse_size(&v).unwrap_or_else(|why| {
                errors.push(format!("PINGENV_MEMORY_MAX_TOTAL: '{v}' {why}"));
                0
            }),
        };
        let max_body_size = match get("MAX_BODY_SIZE") {
            None => Some(DEFAULT_MAX_BODY_SIZE),
            Some(v) => parse_limit(&v).unwrap_or_else(|why| {
                errors.push(format!("PINGENV_MAX_BODY_SIZE: '{v}' {why}"));
                None
            }),
        };

        let timeouts = Timeouts {
            upstream_connect: parse_timeout(
                &mut errors,
                "PINGENV_UPSTREAM_CONNECT_TIMEOUT",
                get("UPSTREAM_CONNECT_TIMEOUT"),
                DEFAULT_CONNECT_TIMEOUT,
            ),
            upstream_read: parse_timeout(
                &mut errors,
                "PINGENV_UPSTREAM_READ_TIMEOUT",
                get("UPSTREAM_READ_TIMEOUT"),
                DEFAULT_READ_TIMEOUT,
            ),
            write: parse_timeout(
                &mut errors,
                "PINGENV_WRITE_TIMEOUT",
                get("WRITE_TIMEOUT"),
                DEFAULT_WRITE_TIMEOUT,
            ),
            client_idle: parse_timeout(
                &mut errors,
                "PINGENV_IDLE_TIMEOUT",
                get("IDLE_TIMEOUT"),
                DEFAULT_IDLE_TIMEOUT,
            ),
        };
        let hsts = get("HSTS");
        if let Some(value) = &hsts {
            if tls == TlsMode::Off {
                errors.push("PINGENV_HSTS: cannot be set while PINGENV_TLS_MODE is off".into());
            }
            if !value.starts_with("max-age=")
                || !value.chars().all(|c| c.is_ascii_graphic() || c == ' ')
            {
                errors.push(format!(
                    "PINGENV_HSTS: '{value}' must be printable ASCII starting with max-age=, \
                     like max-age=31536000"
                ));
            }
        }
        let cert_reload_interval = parse_timeout(
            &mut errors,
            "PINGENV_CERT_RELOAD_INTERVAL",
            get("CERT_RELOAD_INTERVAL"),
            DEFAULT_CERT_RELOAD_INTERVAL,
        )
        .unwrap_or(DEFAULT_CERT_RELOAD_INTERVAL);

        let threads = parse_num(
            &mut errors,
            "PINGENV_THREADS",
            get("THREADS"),
            default_threads,
        );
        if threads == 0 {
            errors.push("PINGENV_THREADS: must be at least 1".into());
        }
        let shutdown_grace_seconds = parse_num(
            &mut errors,
            "PINGENV_SHUTDOWN_GRACE_SECONDS",
            get("SHUTDOWN_GRACE_SECONDS"),
            5u64,
        );
        let log_level = match get("LOG_LEVEL") {
            None => log::LevelFilter::Info,
            Some(v) => v.parse().unwrap_or_else(|_| {
                errors.push(format!(
                    "PINGENV_LOG_LEVEL: '{v}' is not one of off, error, warn, info, debug, trace"
                ));
                log::LevelFilter::Info
            }),
        };

        let mut routes = Vec::new();
        for (name, fields) in &raw_routes {
            if let Some(route) = parse_route(&mut errors, name, fields) {
                routes.push(route);
            }
        }
        if raw_routes.is_empty() {
            errors.push(
                "no routes configured: set PINGENV_ROUTE_<NAME>_HOST and either \
                 PINGENV_ROUTE_<NAME>_UPSTREAM or PINGENV_ROUTE_<NAME>_ROOT"
                    .into(),
            );
        }

        let mut seen = HashSet::new();
        let certified = cert_files_by_host(&routes);
        for route in &routes {
            for host in &route.hosts {
                if !seen.insert((host.clone(), route.path.clone())) {
                    errors.push(format!(
                        "PINGENV_ROUTE_{}_HOST: {host}{} is already served by another route",
                        route.name.to_uppercase(),
                        route.path
                    ));
                }
            }
            let var = |f: &str| format!("PINGENV_ROUTE_{}_{f}", route.name.to_uppercase());
            if tls == TlsMode::Off && route.cert_files.is_some() {
                errors.push(format!(
                    "{}: certificate files are set but PINGENV_TLS_MODE is off",
                    var("TLS_CERT_FILE")
                ));
            }
            for host in &route.hosts {
                match (certified.get(host.as_str()), &route.cert_files, tls) {
                    // One host cannot present two certificates.
                    (Some(first), Some(_), _) if first.cert_files != route.cert_files => errors
                        .push(format!(
                            "{}: {host} already has a different certificate, from \
                             PINGENV_ROUTE_{}_TLS_CERT_FILE; a host has one certificate, \
                             whichever of its routes names it",
                            var("TLS_CERT_FILE"),
                            first.name.to_uppercase()
                        )),
                    (None, _, TlsMode::Manual) => errors.push(format!(
                        "{}: {host} has no certificate; PINGENV_TLS_MODE is manual, so one \
                         of its routes must set TLS_CERT_FILE and TLS_KEY_FILE",
                        var("HOST")
                    )),
                    (None, _, TlsMode::Acme) if host.starts_with("*.") => errors.push(format!(
                        "{}: {host} is a wildcard, which HTTP-01 cannot validate; \
                         give this route certificate files instead",
                        var("HOST")
                    )),
                    _ => {}
                }
            }
        }

        if !errors.is_empty() {
            errors.sort();
            errors.dedup();
            return Err(errors);
        }

        Ok(Config {
            http_addr,
            https_addr,
            tls,
            http2,
            https_redirect,
            https_redirect_port,
            data_dir: PathBuf::from(get("DATA_DIR").unwrap_or_else(|| "/data".into())),
            acme: AcmeConfig {
                directory_url,
                email,
                ca_file: get("ACME_CA_FILE").map(PathBuf::from),
            },
            routes,
            memory_max_total,
            max_body_size,
            timeouts,
            hsts,
            cert_reload_interval,
            threads,
            shutdown_grace_seconds,
            log_level,
        })
    }

    /// The certificate and key files of every host that was given some.
    ///
    /// A certificate belongs to a host, not to a route: files named on one
    /// route cover its hosts wherever else they are routed.
    pub fn cert_files(&self) -> BTreeMap<&str, &CertFiles> {
        cert_files_by_host(&self.routes)
            .into_iter()
            .filter_map(|(host, route)| Some((host, route.cert_files.as_ref()?)))
            .collect()
    }

    /// Hosts that no route gave certificate files, sorted.
    fn hosts_without_cert_files(&self) -> Vec<String> {
        let certified = self.cert_files();
        let hosts = self.routes.iter().flat_map(|r| &r.hosts);
        let mut hosts: Vec<String> = hosts
            .filter(|host| !certified.contains_key(host.as_str()))
            .cloned()
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Hosts whose certificates are obtained from the ACME CA.
    pub fn acme_hosts(&self) -> Vec<String> {
        match self.tls {
            TlsMode::Acme => self.hosts_without_cert_files(),
            _ => Vec::new(),
        }
    }

    /// Hosts that get a certificate generated at startup.
    pub fn self_signed_hosts(&self) -> Vec<String> {
        match self.tls {
            TlsMode::SelfSigned => self.hosts_without_cert_files(),
            _ => Vec::new(),
        }
    }
}

/// For each host with certificate files, the route that names them. If two
/// routes name different files for one host the first is kept here, and
/// `Config::from_env` reports the second.
fn cert_files_by_host(routes: &[Route]) -> BTreeMap<&str, &Route> {
    let mut by_host = BTreeMap::new();
    for route in routes.iter().filter(|r| r.cert_files.is_some()) {
        for host in &route.hosts {
            by_host.entry(host.as_str()).or_insert(route);
        }
    }
    by_host
}

fn parse_route(
    errors: &mut Vec<String>,
    name: &str,
    fields: &BTreeMap<&'static str, String>,
) -> Option<Route> {
    let var = |f: &str| format!("PINGENV_ROUTE_{name}_{f}");
    let field = |f: &str| fields.get(f).filter(|v| !v.is_empty());
    let before = errors.len();

    if !name
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        errors.push(format!(
            "PINGENV_ROUTE_{name}_*: route names may only contain A-Z, 0-9 and _"
        ));
    }

    let mut hosts = Vec::new();
    match field("HOST") {
        None => errors.push(format!("{}: missing", var("HOST"))),
        Some(raw) => {
            let listed = entries(raw);
            if listed.is_empty() {
                errors.push(format!("{}: '{raw}' lists no host name", var("HOST")));
            }
            for host in listed {
                let host = host.to_ascii_lowercase();
                match validate_host(&host, true) {
                    Ok(()) => hosts.push(host),
                    Err(why) => errors.push(format!("{}: '{host}' {why}", var("HOST"))),
                }
            }
        }
    }

    let mut upstreams = Vec::new();
    match field("UPSTREAM") {
        None if field("ROOT").is_some() => {}
        None => errors.push(format!(
            "{} or {}: one of them is required",
            var("UPSTREAM"),
            var("ROOT")
        )),
        Some(_) if field("ROOT").is_some() => errors.push(format!(
            "{} and {}: a route either proxies or serves files, not both",
            var("UPSTREAM"),
            var("ROOT")
        )),
        Some(raw) => {
            let listed = entries(raw);
            // Not the same as missing: the variable is set, and a route that
            // got this far with no upstream would have nowhere to send to.
            if listed.is_empty() {
                errors.push(format!(
                    "{}: '{raw}' lists no upstream (expected host:port, comma separated)",
                    var("UPSTREAM")
                ));
            }
            for item in listed {
                match parse_upstream(item) {
                    Ok(u) => upstreams.push(u),
                    Err(why) => errors.push(format!("{}: '{item}' {why}", var("UPSTREAM"))),
                }
            }
        }
    }

    let mut path = field("PATH").cloned().unwrap_or_else(|| "/".into());
    if !path.starts_with('/') {
        errors.push(format!("{}: '{path}' must start with /", var("PATH")));
    }
    while path.len() > 1 && path.ends_with('/') {
        path.pop();
    }

    let strip_prefix = parse_bool(
        errors,
        &var("STRIP_PREFIX"),
        field("STRIP_PREFIX").cloned(),
        false,
    );

    let set_host = field("SET_HOST").cloned();
    if let Some(h) = &set_host {
        let name_part = h.rsplit_once(':').map_or(h.as_str(), |(n, _)| n);
        if let Err(why) = validate_host(&name_part.to_ascii_lowercase(), false) {
            errors.push(format!("{}: '{h}' {why}", var("SET_HOST")));
        }
    }

    let cert_files = match (field("TLS_CERT_FILE"), field("TLS_KEY_FILE")) {
        (Some(cert), Some(key)) => Some(CertFiles {
            cert: PathBuf::from(cert),
            key: PathBuf::from(key),
        }),
        (None, None) => None,
        _ => {
            errors.push(format!(
                "{} and {}: set both or neither",
                var("TLS_CERT_FILE"),
                var("TLS_KEY_FILE")
            ));
            None
        }
    };

    let acme_passthrough = parse_bool(
        errors,
        &var("ACME_PASSTHROUGH"),
        field("ACME_PASSTHROUGH").cloned(),
        false,
    );
    let read_timeout = field("READ_TIMEOUT").map(|v| {
        parse_duration(v).unwrap_or_else(|why| {
            errors.push(format!("{}: '{v}' {why}", var("READ_TIMEOUT")));
            None
        })
    });
    let max_body_size = field("MAX_BODY_SIZE").map(|v| {
        parse_limit(v).unwrap_or_else(|why| {
            errors.push(format!("{}: '{v}' {why}", var("MAX_BODY_SIZE")));
            None
        })
    });

    let site = match field("ROOT") {
        Some(root) => {
            if !root.starts_with('/') {
                errors.push(format!(
                    "{}: '{root}' must be an absolute path",
                    var("ROOT")
                ));
            }
            for upstream_only in ["STRIP_PREFIX", "SET_HOST", "READ_TIMEOUT", "MAX_BODY_SIZE"] {
                if field(upstream_only).is_some() {
                    errors.push(format!(
                        "{}: only applies to routes with an upstream",
                        var(upstream_only)
                    ));
                }
            }
            let fallback = field("FALLBACK").cloned();
            if let Some(f) = &fallback
                && !f.starts_with('/')
            {
                errors.push(format!("{}: '{f}' must start with /", var("FALLBACK")));
            }
            let memory_max_file = match field("MEMORY_MAX_FILE") {
                None => DEFAULT_MEMORY_MAX_FILE,
                Some(v) => parse_size(v).unwrap_or_else(|why| {
                    errors.push(format!("{}: '{v}' {why}", var("MEMORY_MAX_FILE")));
                    0
                }),
            };
            // `""` stands for the root itself: everything is eligible.
            let memory_paths = match field("MEMORY_PATHS") {
                None => vec![String::new()],
                Some(raw) => {
                    let listed = entries(raw);
                    if listed.is_empty() {
                        errors.push(format!(
                            "{}: '{raw}' lists no path (leave it unset for everything)",
                            var("MEMORY_PATHS")
                        ));
                    }
                    if listed.iter().any(|p| !p.starts_with('/')) {
                        errors.push(format!(
                            "{}: every path must start with /",
                            var("MEMORY_PATHS")
                        ));
                    }
                    listed
                        .into_iter()
                        .map(|p| p.trim_end_matches('/').to_string())
                        .collect()
                }
            };
            let memory_refresh = match field("MEMORY_REFRESH") {
                None => Some(DEFAULT_MEMORY_REFRESH),
                Some(v) => parse_duration(v).unwrap_or_else(|why| {
                    errors.push(format!("{}: '{v}' {why}", var("MEMORY_REFRESH")));
                    None
                }),
            };
            let cache_control = field("CACHE_CONTROL")
                .cloned()
                .unwrap_or_else(|| DEFAULT_CACHE_CONTROL.into());
            if !cache_control
                .chars()
                .all(|c| c.is_ascii_graphic() || c == ' ')
            {
                errors.push(format!("{}: must be printable ASCII", var("CACHE_CONTROL")));
            }
            let compress = parse_bool(errors, &var("COMPRESS"), field("COMPRESS").cloned(), true);
            Some(StaticSite {
                root: PathBuf::from(root),
                memory_max_file,
                memory_paths,
                memory_refresh,
                fallback,
                cache_control,
                compress,
            })
        }
        None => {
            for files_only in [
                "FALLBACK",
                "MEMORY_MAX_FILE",
                "MEMORY_PATHS",
                "MEMORY_REFRESH",
                "CACHE_CONTROL",
                "COMPRESS",
            ] {
                if field(files_only).is_some() {
                    errors.push(format!(
                        "{}: only applies to routes with a {}",
                        var(files_only),
                        var("ROOT")
                    ));
                }
            }
            None
        }
    };

    (errors.len() == before).then(|| Route {
        name: name.to_ascii_lowercase(),
        hosts,
        path,
        strip_prefix,
        upstreams,
        site,
        set_host,
        cert_files,
        acme_passthrough,
        read_timeout,
        max_body_size,
    })
}

/// The entries of a comma separated setting. Empty ones are dropped, so a
/// stray comma does no harm; a value that is nothing but commas comes back
/// empty, which the caller reports: it is set, and yet it lists nothing.
fn entries(raw: &str) -> Vec<&str> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// Parses a byte count: a bare number, or one with a `KiB`/`MiB`/`GiB`
/// (powers of 1024) or `KB`/`MB`/`GB` (powers of 1000) suffix.
pub fn parse_size(text: &str) -> Result<u64, &'static str> {
    const UNITS: &[(&str, u64)] = &[
        ("KIB", 1 << 10),
        ("MIB", 1 << 20),
        ("GIB", 1 << 30),
        ("KB", 1_000),
        ("MB", 1_000_000),
        ("GB", 1_000_000_000),
        ("B", 1),
    ];
    let upper = text.trim().to_ascii_uppercase();
    let (digits, factor) = UNITS
        .iter()
        .find_map(|(unit, factor)| Some((upper.strip_suffix(unit)?.trim_end(), *factor)))
        .unwrap_or((upper.as_str(), 1));
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(factor))
        .ok_or("is not a size like 0, 65536, 512KiB or 2MiB")
}

/// A size used as a limit: zero means "no limit" and comes back as `None`.
pub fn parse_limit(text: &str) -> Result<Option<u64>, &'static str> {
    parse_size(text).map(|bytes| (bytes > 0).then_some(bytes))
}

/// A duration like `250ms`, `30s`, `5m`, `2h`; a bare number is seconds. Zero
/// means "no limit" and comes back as `None`.
pub fn parse_duration(text: &str) -> Result<Option<Duration>, &'static str> {
    const UNITS: &[(&str, u64)] = &[("MS", 1), ("S", 1_000), ("M", 60_000), ("H", 3_600_000)];
    let upper = text.trim().to_ascii_uppercase();
    let (digits, millis) = UNITS
        .iter()
        .find_map(|(unit, factor)| Some((upper.strip_suffix(unit)?.trim_end(), *factor)))
        .unwrap_or((upper.as_str(), 1_000));
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(millis))
        .map(|ms| (ms > 0).then(|| Duration::from_millis(ms)))
        .ok_or("is not a duration like 0, 30, 500ms, 30s, 5m or 2h")
}

fn parse_timeout(
    errors: &mut Vec<String>,
    key: &str,
    value: Option<String>,
    default: Duration,
) -> Option<Duration> {
    match value {
        None => Some(default),
        Some(v) => parse_duration(&v).unwrap_or_else(|why| {
            errors.push(format!("{key}: '{v}' {why}"));
            Some(default)
        }),
    }
}

fn validate_host(host: &str, allow_wildcard: bool) -> Result<(), &'static str> {
    let name = match host.strip_prefix("*.") {
        Some(rest) if allow_wildcard => rest,
        Some(_) => return Err("may not be a wildcard"),
        None => host,
    };
    if name.is_empty() || name.len() > 253 {
        return Err("is not a valid host name");
    }
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if !name.split('.').all(label_ok) {
        return Err("is not a valid host name (use host names only: no scheme, port or path)");
    }
    Ok(())
}

fn parse_upstream(item: &str) -> Result<Upstream, String> {
    let (tls, rest) = if let Some(r) = item.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = item.strip_prefix("http://") {
        (false, r)
    } else if item.contains("://") {
        return Err("has an unsupported scheme (use http:// or https://)".into());
    } else {
        (false, item)
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains('/') {
        return Err("must not contain a path".into());
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| format!("has an invalid port '{p}'"))?;
            (h, port)
        }
        None if tls => (rest, 443),
        None => return Err("needs a port, like app:8080".into()),
    };
    // Underscores are not valid in DNS names but Docker Compose service names
    // routinely contain them, so they are accepted here.
    let ok = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'));
    if !ok {
        return Err("has an invalid host name (IPv6 upstreams are not supported)".into());
    }
    Ok(Upstream {
        host: host.to_ascii_lowercase(),
        port,
        tls,
    })
}

fn parse_addr(
    errors: &mut Vec<String>,
    key: &str,
    value: Option<String>,
    default: &str,
) -> SocketAddr {
    let fallback: SocketAddr = default.parse().expect("default address is valid");
    match value {
        None => fallback,
        Some(v) => v.parse().unwrap_or_else(|_| {
            errors.push(format!("{key}: '{v}' is not an address like 0.0.0.0:8080"));
            fallback
        }),
    }
}

fn parse_bool(errors: &mut Vec<String>, key: &str, value: Option<String>, default: bool) -> bool {
    match value.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None => default,
        Some("true" | "1" | "yes" | "on") => true,
        Some("false" | "0" | "no" | "off") => false,
        Some(v) => {
            errors.push(format!("{key}: '{v}' is not true or false"));
            default
        }
    }
}

fn parse_num<T: std::str::FromStr>(
    errors: &mut Vec<String>,
    key: &str,
    value: Option<String>,
    default: T,
) -> T {
    match value {
        None => default,
        Some(v) => v.parse().unwrap_or_else(|_| {
            errors.push(format!("{key}: '{v}' is not a valid number"));
            default
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Result<Config, Vec<String>> {
        Config::from_env(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
    }

    #[test]
    fn minimal_config() {
        let cfg = env(&[
            ("PINGENV_ROUTE_APP_HOST", "Example.com, www.example.com"),
            ("PINGENV_ROUTE_APP_UPSTREAM", "app:8080"),
            ("PATH", "/usr/bin"),
        ])
        .unwrap();
        assert_eq!(cfg.tls, TlsMode::Off);
        assert!(!cfg.https_redirect);
        assert_eq!(cfg.routes.len(), 1);
        let r = &cfg.routes[0];
        assert_eq!(r.name, "app");
        assert_eq!(r.hosts, ["example.com", "www.example.com"]);
        assert_eq!(r.path, "/");
        assert_eq!(
            r.upstreams,
            [Upstream {
                host: "app".into(),
                port: 8080,
                tls: false
            }]
        );
    }

    #[test]
    fn route_names_may_contain_underscores() {
        let cfg = env(&[
            ("PINGENV_ROUTE_MY_API_HOST", "api.example.com"),
            (
                "PINGENV_ROUTE_MY_API_UPSTREAM",
                "https://backend.internal, http://other:81/",
            ),
            ("PINGENV_ROUTE_MY_API_PATH", "/v1/"),
            ("PINGENV_ROUTE_MY_API_STRIP_PREFIX", "true"),
            ("PINGENV_ROUTE_MY_API_TLS_CERT_FILE", "/c.pem"),
            ("PINGENV_ROUTE_MY_API_TLS_KEY_FILE", "/k.pem"),
            ("PINGENV_TLS_MODE", "manual"),
        ])
        .unwrap();
        let r = &cfg.routes[0];
        assert_eq!(r.name, "my_api");
        assert_eq!(r.path, "/v1");
        assert!(r.strip_prefix);
        assert_eq!(
            r.upstreams[0],
            Upstream {
                host: "backend.internal".into(),
                port: 443,
                tls: true
            }
        );
        assert_eq!(
            r.upstreams[1],
            Upstream {
                host: "other".into(),
                port: 81,
                tls: false
            }
        );
        assert!(r.cert_files.is_some());
        assert!(cfg.https_redirect);
    }

    #[test]
    fn reports_every_problem_at_once() {
        let errs = env(&[
            ("PINGENV_ROUTE_A_HOST", "https://example.com"),
            ("PINGENV_ROUTE_A_UPSTREAM", "app"),
            ("PINGENV_ROUTE_B_HOST", "b.example.com"),
            ("PINGENV_ROUTE_C_HOSTT", "typo.example.com"),
            ("PINGENV_TLS_MODE", "letsencrypt"),
            ("PINGENV_HTTP_ADDR", "80"),
        ])
        .unwrap_err();
        let all = errs.join("\n");
        assert!(all.contains("PINGENV_ROUTE_A_HOST"), "{all}");
        assert!(
            all.contains("PINGENV_ROUTE_A_UPSTREAM: 'app' needs a port"),
            "{all}"
        );
        assert!(
            all.contains(
                "PINGENV_ROUTE_B_UPSTREAM or PINGENV_ROUTE_B_ROOT: one of them is required"
            ),
            "{all}"
        );
        assert!(
            all.contains("PINGENV_ROUTE_C_HOSTT: unknown route setting"),
            "{all}"
        );
        assert!(all.contains("TLS_MODE"), "{all}");
        assert!(all.contains("HTTP_ADDR"), "{all}");
    }

    #[test]
    fn no_routes_is_an_error() {
        let errs = env(&[("PINGENV_TLS_MODE", "off")]).unwrap_err();
        assert!(errs[0].contains("no routes configured"));
    }

    #[test]
    fn duplicate_host_and_path_is_an_error() {
        let errs = env(&[
            ("PINGENV_ROUTE_A_HOST", "example.com"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
            ("PINGENV_ROUTE_B_HOST", "example.com"),
            ("PINGENV_ROUTE_B_UPSTREAM", "b:1"),
        ])
        .unwrap_err();
        assert!(
            errs[0].contains("already served by another route"),
            "{errs:?}"
        );
    }

    #[test]
    fn acme_rejects_wildcards_without_cert_files() {
        let errs = env(&[
            ("PINGENV_TLS_MODE", "acme"),
            ("PINGENV_ROUTE_A_HOST", "*.example.com"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
        ])
        .unwrap_err();
        assert!(errs[0].contains("wildcard"), "{errs:?}");
    }

    #[test]
    fn acme_hosts_skip_routes_with_their_own_certificate() {
        let cfg = env(&[
            ("PINGENV_TLS_MODE", "acme"),
            ("PINGENV_ACME_STAGING", "true"),
            ("PINGENV_ROUTE_A_HOST", "a.example.com,b.example.com"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
            ("PINGENV_ROUTE_B_HOST", "*.corp.example.com"),
            ("PINGENV_ROUTE_B_UPSTREAM", "b:1"),
            ("PINGENV_ROUTE_B_TLS_CERT_FILE", "/c.pem"),
            ("PINGENV_ROUTE_B_TLS_KEY_FILE", "/k.pem"),
        ])
        .unwrap();
        assert_eq!(cfg.acme_hosts(), ["a.example.com", "b.example.com"]);
        assert_eq!(cfg.acme.directory_url, LETS_ENCRYPT_STAGING);
    }

    #[test]
    fn a_certificate_named_on_one_route_covers_its_hosts_on_every_route() {
        // Two routes share example.com; only one of them names the files.
        let shared = [
            ("PINGENV_ROUTE_API_HOST", "example.com,api.example.com"),
            ("PINGENV_ROUTE_API_PATH", "/api"),
            ("PINGENV_ROUTE_API_UPSTREAM", "api:1"),
            ("PINGENV_ROUTE_SITE_HOST", "example.com"),
            ("PINGENV_ROUTE_SITE_UPSTREAM", "site:1"),
            ("PINGENV_ROUTE_SITE_TLS_CERT_FILE", "/c.pem"),
            ("PINGENV_ROUTE_SITE_TLS_KEY_FILE", "/k.pem"),
        ];
        let with_mode = |mode: &'static str| {
            let mut vars = shared.to_vec();
            vars.push(("PINGENV_TLS_MODE", mode));
            env(&vars)
        };

        let acme = with_mode("acme").unwrap();
        let files = acme.cert_files();
        assert_eq!(files.keys().copied().collect::<Vec<_>>(), ["example.com"]);
        assert_eq!(files["example.com"].cert, PathBuf::from("/c.pem"));
        // example.com has its files, so only the other host is asked for.
        assert_eq!(acme.acme_hosts(), ["api.example.com"]);
        assert!(acme.self_signed_hosts().is_empty());

        let self_signed = with_mode("selfsigned").unwrap();
        assert_eq!(self_signed.self_signed_hosts(), ["api.example.com"]);
        assert!(self_signed.acme_hosts().is_empty());

        // In manual mode it is the host that needs files, not every route.
        let errs = with_mode("manual").unwrap_err();
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(
            errs[0].starts_with("PINGENV_ROUTE_API_HOST: api.example.com has no certificate"),
            "{errs:?}"
        );
    }

    #[test]
    fn one_host_cannot_be_given_two_certificates() {
        let mut vars = vec![
            ("PINGENV_TLS_MODE", "manual"),
            ("PINGENV_ROUTE_A_HOST", "example.com"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
            ("PINGENV_ROUTE_A_TLS_CERT_FILE", "/a.pem"),
            ("PINGENV_ROUTE_A_TLS_KEY_FILE", "/a.key"),
            ("PINGENV_ROUTE_B_HOST", "example.com"),
            ("PINGENV_ROUTE_B_PATH", "/b"),
            ("PINGENV_ROUTE_B_UPSTREAM", "b:1"),
            ("PINGENV_ROUTE_B_TLS_CERT_FILE", "/b.pem"),
            ("PINGENV_ROUTE_B_TLS_KEY_FILE", "/b.key"),
        ];
        let errs = env(&vars).unwrap_err();
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(
            errs[0].starts_with("PINGENV_ROUTE_B_TLS_CERT_FILE: example.com already has"),
            "{errs:?}"
        );
        assert!(
            errs[0].contains("PINGENV_ROUTE_A_TLS_CERT_FILE"),
            "{errs:?}"
        );

        // Naming the same files twice is redundant, not a conflict.
        vars.retain(|(key, _)| !key.starts_with("PINGENV_ROUTE_B_TLS"));
        vars.push(("PINGENV_ROUTE_B_TLS_CERT_FILE", "/a.pem"));
        vars.push(("PINGENV_ROUTE_B_TLS_KEY_FILE", "/a.key"));
        assert_eq!(env(&vars).unwrap().cert_files().len(), 1);
    }

    #[test]
    fn redirect_without_tls_is_an_error() {
        let errs = env(&[
            ("PINGENV_HTTPS_REDIRECT", "true"),
            ("PINGENV_ROUTE_A_HOST", "example.com"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
        ])
        .unwrap_err();
        assert!(errs[0].contains("HTTPS_REDIRECT"), "{errs:?}");
    }

    #[test]
    fn tls_settings_without_a_tls_mode_are_errors() {
        // The likely mistake: everything for ACME is there except the mode,
        // which defaults to off. That must not start a plain HTTP server.
        let route = [
            ("PINGENV_ROUTE_A_HOST", "example.com"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
        ];
        for (key, value) in [
            ("PINGENV_ACME_EMAIL", "ops@example.com"),
            ("PINGENV_ACME_STAGING", "true"),
            (
                "PINGENV_ACME_DIRECTORY_URL",
                "https://ca.example.com/directory",
            ),
            ("PINGENV_ACME_CA_FILE", "/ca.pem"),
            ("PINGENV_HTTPS_ADDR", "0.0.0.0:8443"),
            ("PINGENV_HTTP2", "false"),
            ("PINGENV_HTTPS_REDIRECT_PORT", "8443"),
            ("PINGENV_DATA_DIR", "/var/lib/pingenv"),
            ("PINGENV_CERT_RELOAD_INTERVAL", "30s"),
        ] {
            let mut vars = route.to_vec();
            vars.push((key, value));
            let errs = env(&vars).expect_err(key);
            assert_eq!(errs.len(), 1, "{errs:?}");
            assert!(errs[0].starts_with(&format!("{key}: ")), "{errs:?}");
            assert!(errs[0].contains("PINGENV_TLS_MODE is off"), "{errs:?}");

            // The same setting is fine once a mode is chosen.
            vars.push(("PINGENV_TLS_MODE", "selfsigned"));
            assert!(env(&vars).is_ok(), "{key} with a TLS mode");
        }

        // Spelling out a default changes nothing, so it is not a mistake.
        let mut vars = route.to_vec();
        vars.push(("PINGENV_ACME_STAGING", "false"));
        vars.push(("PINGENV_HTTPS_REDIRECT", "false"));
        assert!(env(&vars).is_ok());

        // A mode that is set but wrong is one problem, not one per setting.
        let mut vars = route.to_vec();
        vars.push(("PINGENV_TLS_MODE", "letsencrypt"));
        vars.push(("PINGENV_ACME_EMAIL", "ops@example.com"));
        assert_eq!(env(&vars).unwrap_err().len(), 1);
    }

    #[test]
    fn unprefixed_variables_are_ignored_and_unknown_prefixed_ones_are_errors() {
        let errs = env(&[
            ("PINGENV_ROUTE_A_HOST", "example.com"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
            // Neither of these is ours: a Kubernetes service link and a stray global.
            ("ROUTE_X_SERVICE_HOST", "10.0.0.1"),
            ("TLS_MODE", "acme"),
            ("PINGENV_TLS_MOD", "acme"),
        ])
        .unwrap_err();
        assert_eq!(errs, ["PINGENV_TLS_MOD: unknown setting"]);
    }

    #[test]
    fn static_route() {
        let cfg = env(&[
            ("PINGENV_ROUTE_SITE_HOST", "example.com"),
            ("PINGENV_ROUTE_SITE_ROOT", "/srv/site"),
            ("PINGENV_ROUTE_SITE_MEMORY_MAX_FILE", "64KiB"),
            ("PINGENV_ROUTE_SITE_FALLBACK", "/index.html"),
            ("PINGENV_MEMORY_MAX_TOTAL", "10MB"),
        ])
        .unwrap();
        let route = &cfg.routes[0];
        assert!(route.upstreams.is_empty());
        assert_eq!(
            route.site,
            Some(StaticSite {
                root: "/srv/site".into(),
                memory_max_file: 65536,
                memory_paths: vec![String::new()],
                memory_refresh: Some(Duration::from_secs(300)),
                fallback: Some("/index.html".into()),
                cache_control: "no-cache".into(),
                compress: true,
            })
        );
        assert_eq!(cfg.memory_max_total, 10_000_000);
    }

    #[test]
    fn files_stay_on_disk_unless_asked_otherwise() {
        let cfg = env(&[
            ("PINGENV_ROUTE_SITE_HOST", "example.com"),
            ("PINGENV_ROUTE_SITE_ROOT", "/srv/site"),
        ])
        .unwrap();
        assert_eq!(cfg.routes[0].site.as_ref().unwrap().memory_max_file, 0);

        let cfg = env(&[
            ("PINGENV_ROUTE_SITE_HOST", "example.com"),
            ("PINGENV_ROUTE_SITE_ROOT", "/srv/site"),
            ("PINGENV_ROUTE_SITE_MEMORY_MAX_FILE", "1MiB"),
            ("PINGENV_ROUTE_SITE_MEMORY_PATHS", "/css/, /index.html,/"),
            ("PINGENV_ROUTE_SITE_MEMORY_REFRESH", "30s"),
        ])
        .unwrap();
        let site = cfg.routes[0].site.as_ref().unwrap();
        assert_eq!(site.memory_paths, ["/css", "/index.html", ""]);
        assert_eq!(site.memory_refresh, Some(Duration::from_secs(30)));

        let never = env(&[
            ("PINGENV_ROUTE_SITE_HOST", "example.com"),
            ("PINGENV_ROUTE_SITE_ROOT", "/srv/site"),
            ("PINGENV_ROUTE_SITE_MEMORY_REFRESH", "0"),
        ])
        .unwrap();
        assert_eq!(never.routes[0].site.as_ref().unwrap().memory_refresh, None);

        let plain = env(&[
            ("PINGENV_ROUTE_SITE_HOST", "example.com"),
            ("PINGENV_ROUTE_SITE_ROOT", "/srv/site"),
            ("PINGENV_ROUTE_SITE_COMPRESS", "false"),
        ])
        .unwrap();
        assert!(!plain.routes[0].site.as_ref().unwrap().compress);

        let errs = env(&[
            ("PINGENV_ROUTE_SITE_HOST", "example.com"),
            ("PINGENV_ROUTE_SITE_ROOT", "/srv/site"),
            ("PINGENV_ROUTE_SITE_MEMORY_PATHS", "css"),
            ("PINGENV_ROUTE_SITE_MEMORY_REFRESH", "soon"),
        ])
        .unwrap_err()
        .join("\n");
        assert!(
            errs.contains("MEMORY_PATHS: every path must start with /"),
            "{errs}"
        );
        assert!(errs.contains("MEMORY_REFRESH: 'soon'"), "{errs}");
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("0"), Ok(None));
        assert_eq!(parse_duration("45"), Ok(Some(Duration::from_secs(45))));
        assert_eq!(
            parse_duration("250ms"),
            Ok(Some(Duration::from_millis(250)))
        );
        assert_eq!(parse_duration("5m"), Ok(Some(Duration::from_secs(300))));
        assert_eq!(parse_duration(" 2H "), Ok(Some(Duration::from_secs(7200))));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("1d").is_err());
        assert!(parse_duration("-1").is_err());
    }

    #[test]
    fn timeouts_hsts_and_per_route_settings() {
        let cfg = env(&[
            ("PINGENV_TLS_MODE", "selfsigned"),
            ("PINGENV_ROUTE_A_HOST", "a.test"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
        ])
        .unwrap();
        assert_eq!(cfg.timeouts.upstream_connect, Some(Duration::from_secs(10)));
        assert_eq!(cfg.timeouts.upstream_read, Some(Duration::from_secs(60)));
        assert_eq!(cfg.timeouts.write, Some(Duration::from_secs(60)));
        assert_eq!(cfg.timeouts.client_idle, Some(Duration::from_secs(75)));
        assert_eq!(cfg.max_body_size, Some(1024 * 1024));
        assert!(cfg.http2);
        assert_eq!(cfg.hsts, None);
        assert!(!cfg.routes[0].acme_passthrough);
        assert_eq!(cfg.routes[0].read_timeout, None);
        assert_eq!(cfg.routes[0].max_body_size, None);

        let cfg = env(&[
            ("PINGENV_TLS_MODE", "selfsigned"),
            ("PINGENV_UPSTREAM_READ_TIMEOUT", "5s"),
            ("PINGENV_WRITE_TIMEOUT", "0"),
            ("PINGENV_IDLE_TIMEOUT", "30s"),
            ("PINGENV_MAX_BODY_SIZE", "64KiB"),
            ("PINGENV_HTTP2", "false"),
            ("PINGENV_HSTS", "max-age=31536000; includeSubDomains"),
            ("PINGENV_ROUTE_A_HOST", "a.test"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
            ("PINGENV_ROUTE_A_READ_TIMEOUT", "0"),
            ("PINGENV_ROUTE_A_MAX_BODY_SIZE", "0"),
            ("PINGENV_ROUTE_A_ACME_PASSTHROUGH", "true"),
            ("PINGENV_ROUTE_B_HOST", "b.test"),
            ("PINGENV_ROUTE_B_UPSTREAM", "b:1"),
            ("PINGENV_ROUTE_B_MAX_BODY_SIZE", "50MiB"),
        ])
        .unwrap();
        assert_eq!(cfg.timeouts.upstream_read, Some(Duration::from_secs(5)));
        assert_eq!(cfg.timeouts.write, None);
        assert_eq!(cfg.timeouts.client_idle, Some(Duration::from_secs(30)));
        assert_eq!(cfg.max_body_size, Some(64 * 1024));
        assert!(!cfg.http2);
        // Zero lifts the limit, on a route as everywhere else.
        assert_eq!(cfg.routes[0].max_body_size, Some(None));
        assert_eq!(cfg.routes[1].max_body_size, Some(Some(50 << 20)));
        assert_eq!(
            cfg.hsts.as_deref(),
            Some("max-age=31536000; includeSubDomains")
        );
        assert_eq!(cfg.routes[0].read_timeout, Some(None));
        assert!(cfg.routes[0].acme_passthrough);

        let cfg = env(&[
            ("PINGENV_IDLE_TIMEOUT", "0"),
            ("PINGENV_MAX_BODY_SIZE", "0"),
            ("PINGENV_ROUTE_A_HOST", "a.test"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
        ])
        .unwrap();
        assert_eq!(cfg.timeouts.client_idle, None);
        assert_eq!(cfg.max_body_size, None);

        let errs = env(&[
            ("PINGENV_HSTS", "max-age=1"),
            ("PINGENV_ROUTE_A_HOST", "a.test"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
        ])
        .unwrap_err()
        .join("\n");
        assert!(errs.contains("PINGENV_HSTS: cannot be set while"), "{errs}");
        let errs = env(&[
            ("PINGENV_TLS_MODE", "selfsigned"),
            ("PINGENV_HSTS", "preload"),
            ("PINGENV_ROUTE_A_HOST", "a.test"),
            ("PINGENV_ROUTE_A_ROOT", "/srv"),
            ("PINGENV_ROUTE_A_READ_TIMEOUT", "5"),
            ("PINGENV_ROUTE_A_MAX_BODY_SIZE", "5MiB"),
            ("PINGENV_MAX_BODY_SIZE", "big"),
            ("PINGENV_IDLE_TIMEOUT", "soon"),
        ])
        .unwrap_err()
        .join("\n");
        assert!(
            errs.contains("must be printable ASCII starting with max-age="),
            "{errs}"
        );
        assert!(
            errs.contains("PINGENV_ROUTE_A_READ_TIMEOUT: only applies"),
            "{errs}"
        );
        // Files are only ever read with GET and HEAD: there is no body to limit.
        assert!(
            errs.contains("PINGENV_ROUTE_A_MAX_BODY_SIZE: only applies"),
            "{errs}"
        );
        assert!(
            errs.contains("PINGENV_MAX_BODY_SIZE: 'big' is not a size"),
            "{errs}"
        );
        assert!(
            errs.contains("PINGENV_IDLE_TIMEOUT: 'soon' is not a duration"),
            "{errs}"
        );
    }

    #[test]
    fn a_route_proxies_or_serves_files_but_not_both() {
        let errs = env(&[
            ("PINGENV_ROUTE_A_HOST", "a.test"),
            ("PINGENV_ROUTE_A_ROOT", "relative"),
            ("PINGENV_ROUTE_A_UPSTREAM", "a:1"),
            ("PINGENV_ROUTE_A_STRIP_PREFIX", "true"),
            ("PINGENV_ROUTE_B_HOST", "b.test"),
            ("PINGENV_ROUTE_B_UPSTREAM", "b:1"),
            ("PINGENV_ROUTE_B_FALLBACK", "/index.html"),
            ("PINGENV_ROUTE_B_COMPRESS", "true"),
        ])
        .unwrap_err();
        let all = errs.join("\n");
        assert!(all.contains("not both"), "{all}");
        assert!(all.contains("must be an absolute path"), "{all}");
        assert!(
            all.contains("PINGENV_ROUTE_A_STRIP_PREFIX: only applies"),
            "{all}"
        );
        assert!(
            all.contains("PINGENV_ROUTE_B_FALLBACK: only applies"),
            "{all}"
        );
        // Compressing what an upstream sends is the upstream's business.
        assert!(
            all.contains("PINGENV_ROUTE_B_COMPRESS: only applies"),
            "{all}"
        );
    }

    #[test]
    fn a_list_of_nothing_but_commas_is_an_error() {
        // Set, so not "missing", and yet it lists nothing. A route that
        // started with no upstream had nowhere to send its requests.
        let errs = env(&[
            ("PINGENV_ROUTE_A_HOST", "a.test"),
            ("PINGENV_ROUTE_A_UPSTREAM", ","),
            ("PINGENV_ROUTE_B_HOST", " , "),
            ("PINGENV_ROUTE_B_UPSTREAM", "b:1"),
            ("PINGENV_ROUTE_C_HOST", "c.test"),
            ("PINGENV_ROUTE_C_ROOT", "/srv/site"),
            ("PINGENV_ROUTE_C_MEMORY_PATHS", ",,"),
        ])
        .unwrap_err();
        let all = errs.join("\n");
        assert!(
            all.contains("PINGENV_ROUTE_A_UPSTREAM: ',' lists no upstream"),
            "{all}"
        );
        assert!(
            all.contains("PINGENV_ROUTE_B_HOST: ',' lists no host name"),
            "{all}"
        );
        assert!(
            all.contains("PINGENV_ROUTE_C_MEMORY_PATHS: ',,' lists no path"),
            "{all}"
        );
        assert_eq!(errs.len(), 3, "{all}");

        // A stray comma among real entries is still only a stray comma.
        let cfg = env(&[
            ("PINGENV_ROUTE_A_HOST", "a.test,"),
            ("PINGENV_ROUTE_A_UPSTREAM", ",a:1,,b:2"),
        ])
        .unwrap();
        assert_eq!(cfg.routes[0].hosts, ["a.test"]);
        assert_eq!(cfg.routes[0].upstreams.len(), 2);
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("0"), Ok(0));
        assert_eq!(parse_size("1500"), Ok(1500));
        assert_eq!(parse_size("2kib"), Ok(2048));
        assert_eq!(parse_size("1 MiB"), Ok(1 << 20));
        assert_eq!(parse_size("3MB"), Ok(3_000_000));
        assert_eq!(parse_size("1GiB"), Ok(1 << 30));
        assert!(parse_size("lots").is_err());
        assert!(parse_size("-1").is_err());
        assert!(parse_size("99999999999999GiB").is_err());

        assert_eq!(parse_limit("0"), Ok(None));
        assert_eq!(parse_limit("1MiB"), Ok(Some(1 << 20)));
        assert!(parse_limit("lots").is_err());
    }
}
