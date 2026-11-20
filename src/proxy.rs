//! The request path: answer ACME challenges, pick a route by host and path,
//! redirect plain HTTP to HTTPS, and forward everything else upstream.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use log::{info, warn};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;
use pingora::protocols::http::ServerSession;
use pingora::proxy::FailToProxy;
use tokio::time::Instant;

use crate::acme::{CHALLENGE_PREFIX, ChallengeStore};
use crate::config::{Config, Route, Timeouts, Upstream};
use crate::files::{self, Site};

/// Upstream names are re-resolved this often, so a container that comes back
/// with a new address is picked up without restarting the proxy.
const DNS_TTL: Duration = Duration::from_secs(10);
/// How long a request waits for a refreshed address before going ahead with
/// the one it already has. Long enough for any healthy resolver.
const STALE_WAIT: Duration = Duration::from_millis(500);
/// How long the resolver gets to answer at all.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECT_RETRIES: u32 = 2;

pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    pub fn new(routes: Vec<Route>) -> Self {
        Self { routes }
    }

    /// Exact hosts win over wildcards; within a host the longest matching path
    /// prefix wins.
    pub fn find(&self, host: &str, path: &str) -> Option<usize> {
        let wildcard = host
            .split_once('.')
            .map(|(_, parent)| format!("*.{parent}"));
        let best = |want: &str| {
            self.routes
                .iter()
                .enumerate()
                .filter(|(_, r)| r.hosts.iter().any(|h| h == want) && path_matches(&r.path, path))
                .max_by_key(|(_, r)| r.path.len())
                .map(|(i, _)| i)
        };
        best(host).or_else(|| wildcard.as_deref().and_then(best))
    }
}

/// `/api` matches `/api` and `/api/x` but not `/apix`.
fn path_matches(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn strip_prefix(prefix: &str, path_and_query: &str) -> String {
    if prefix == "/" {
        return path_and_query.to_string();
    }
    let rest = &path_and_query[prefix.len()..];
    if rest.starts_with('/') {
        rest.to_string()
    } else {
        format!("/{rest}")
    }
}

/// Lowercased, without a port or the trailing dot of a fully qualified name.
///
/// `None` for anything that is not a plain `host`, `host:port` or
/// `[v6]:port`. The header is the client's to write and ends up in the access
/// log and in `X-Forwarded-Host`, so what cannot be a host is not passed on.
fn normalize_host(raw: &str) -> Option<String> {
    let (host, port) = match raw.strip_prefix('[') {
        Some(v6) => {
            let (host, rest) = v6.split_once(']')?;
            let port = match rest {
                "" => None,
                _ => Some(rest.strip_prefix(':')?),
            };
            let address = |c: char| c.is_ascii_hexdigit() || matches!(c, ':' | '.');
            (host.chars().all(address).then_some(host)?, port)
        }
        None => {
            let (host, port) = match raw.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (raw, None),
            };
            // Underscores are not valid in host names, but they turn up, and
            // a name no route knows is a 404 either way.
            let name = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_');
            (host.chars().all(name).then_some(host)?, port)
        }
    };
    if port.is_some_and(|p| !p.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }
    let host = host.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Host the client asked for, lowercased and without a port.
fn request_host(req: &RequestHeader) -> Option<String> {
    let raw = req
        .uri
        .host()
        .or_else(|| req.headers.get(http::header::HOST)?.to_str().ok())?;
    normalize_host(raw)
}

/// The authority as the client wrote it, port included.
fn client_authority(req: &RequestHeader) -> Option<String> {
    let from_header = req
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok());
    from_header
        .map(str::to_string)
        .or_else(|| req.uri.authority().map(|a| a.to_string()))
}

/// A request that names two different hosts (an absolute-form target and a
/// `Host` header, or two `Host` headers) is routed on one and would be
/// answered on the other, so it is refused instead. So is a `Host` header
/// that is not a host at all.
fn bad_host(req: &RequestHeader) -> Option<&'static str> {
    let mut headers = req.headers.get_all(http::header::HOST).iter();
    let header = match (headers.next(), headers.next()) {
        // HTTP/2 has no `Host`, only the target; that is checked on its own.
        (None, _) => return None,
        (Some(only), None) => only.to_str().ok().and_then(normalize_host),
        (Some(_), Some(_)) => return Some("ambiguous host\n"),
    };
    let Some(header) = header else {
        return Some("malformed host\n");
    };
    match req.uri.host().map(normalize_host) {
        Some(target) if target.as_deref() != Some(header.as_str()) => Some("ambiguous host\n"),
        _ => None,
    }
}

fn port_of(authority: &str) -> Option<u16> {
    let after_host = match authority.strip_prefix('[') {
        Some(rest) => rest.split_once(']')?.1.strip_prefix(':')?,
        None => authority.split_once(':')?.1,
    };
    after_host.parse().ok()
}

/// `%61` is `a`, and clients, proxies and upstreams may differ on whether
/// they know it. Decoding the characters that never need escaping (letters,
/// digits, `-`, `_`, `~`) before routing makes `/%61pi` match `/api`, and
/// the decoded form is what gets forwarded. Dots and slashes stay as sent.
fn decode_unreserved(path: &str) -> Option<String> {
    let hex = |b: u8| (b as char).to_digit(16);
    let bytes = path.as_bytes();
    // Bytes, not chars: a path may hold UTF-8 that was never escaped, and it
    // has to come out as it went in.
    let mut out = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            let byte = (high * 16 + low) as u8;
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~') {
                out.push(byte);
                i += 3;
                changed = true;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Only ASCII was swapped for ASCII, so this is still UTF-8.
    changed.then(|| String::from_utf8(out).ok()).flatten()
}

fn normalize_request_path(session: &mut Session) -> Result<()> {
    let uri = &session.req_header().uri;
    let Some(path) = decode_unreserved(uri.path()) else {
        return Ok(());
    };
    let path_and_query = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(
        path_and_query
            .parse()
            .or_err(InternalError, "normalised path is not valid")?,
    );
    let rebuilt = http::Uri::from_parts(parts).or_err(InternalError, "normalised URI")?;
    session.req_header_mut().set_uri(rebuilt);
    Ok(())
}

/// How a `host:port` is turned into addresses. A field rather than a direct
/// call so that tests can stand in a resolver that is slow or broken.
type Lookup =
    Arc<dyn Fn(String) -> BoxFuture<'static, std::io::Result<Vec<SocketAddr>>> + Send + Sync>;

fn system_lookup() -> Lookup {
    Arc::new(|authority| {
        Box::pin(async move { Ok(tokio::net::lookup_host(authority).await?.collect()) })
    })
}

/// What is known about one upstream name.
struct Known {
    addrs: Vec<SocketAddr>,
    /// When the resolver was last asked, whatever it answered: a resolver
    /// that fails is asked again a TTL later, not on every request. (Tokio's
    /// `Instant`, which is the standard one except that tests can pause it.)
    asked: Instant,
    /// A lookup is under way; nobody else needs to start one.
    refreshing: bool,
}

/// Upstream names, resolved at most once per `DNS_TTL` each.
///
/// An address that is already known is never held hostage by the resolver:
/// when it is due for a refresh, one request waits `STALE_WAIT` for the new
/// answer and everyone else carries on with the old one. A resolver that is
/// slow or down therefore costs little, as long as the upstream stays where it
/// was. Only a name that has never resolved has to wait for its lookup.
struct Resolver {
    lookup: Lookup,
    cache: Arc<Mutex<HashMap<String, Known>>>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new(system_lookup())
    }
}

impl Resolver {
    fn new(lookup: Lookup) -> Self {
        Self {
            lookup,
            cache: Default::default(),
        }
    }

    async fn resolve(&self, upstream: &Upstream) -> Result<Vec<SocketAddr>> {
        let authority = upstream.authority();
        if let Ok(addr) = authority.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }
        let known = match self.cache.lock().unwrap().get_mut(&authority) {
            Some(known) if known.refreshing || known.asked.elapsed() < DNS_TTL => {
                return Ok(known.addrs.clone());
            }
            Some(known) => {
                known.refreshing = true;
                Some(known.addrs.clone())
            }
            None => None,
        };

        // Its own task, so that it finishes (and records what it found) even
        // if this request stops waiting or its client goes away.
        let refresh = tokio::spawn(refresh(
            self.lookup.clone(),
            self.cache.clone(),
            authority.clone(),
        ));
        match known {
            Some(addrs) => match tokio::time::timeout(STALE_WAIT, refresh).await {
                Ok(Ok(Ok(fresh))) => Ok(fresh),
                // Slow or failed: `refresh` says so in the log.
                _ => Ok(addrs),
            },
            None => match refresh.await {
                Ok(Ok(addrs)) => Ok(addrs),
                Ok(Err(why)) => Err(unresolved(&authority, why)),
                Err(e) => Err(unresolved(&authority, e)),
            },
        }
    }
}

/// An upstream that cannot be found is the upstream's failure, like one that
/// cannot be reached: marked as such, it is answered with a 502, not a 500.
fn unresolved(authority: &str, why: impl std::fmt::Display) -> Box<Error> {
    Error::explain(ConnectNoRoute, format!("{authority}: {why}")).into_up()
}

/// Asks the resolver once and records the outcome. A failure keeps whatever
/// address was known: a resolver hiccup should not take down an upstream that
/// was reachable a moment ago.
async fn refresh(
    lookup: Lookup,
    cache: Arc<Mutex<HashMap<String, Known>>>,
    authority: String,
) -> std::result::Result<Vec<SocketAddr>, String> {
    let outcome = match tokio::time::timeout(LOOKUP_TIMEOUT, lookup(authority.clone())).await {
        Ok(Ok(addrs)) if addrs.is_empty() => Err("no addresses".to_string()),
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!(
            "no answer from the resolver in {}s",
            LOOKUP_TIMEOUT.as_secs()
        )),
    };
    let mut cache = cache.lock().unwrap();
    match &outcome {
        Ok(addrs) => {
            let known = Known {
                addrs: addrs.clone(),
                asked: Instant::now(),
                refreshing: false,
            };
            cache.insert(authority, known);
        }
        Err(why) => {
            if let Some(known) = cache.get_mut(&authority) {
                warn!("{authority}: lookup failed ({why}), keeping the last known address");
                known.asked = Instant::now();
                known.refreshing = false;
            }
        }
    }
    outcome
}

/// The requests being served right now. Shutdown reads it to stop waiting
/// once there are none left.
#[derive(Clone, Default)]
pub struct InFlight(Arc<AtomicUsize>);

impl InFlight {
    pub fn count(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }

    fn enter(&self) -> Entered {
        self.0.fetch_add(1, Ordering::AcqRel);
        Entered(self.0.clone())
    }
}

/// One request's share of the count, given back when it is dropped: however
/// the request ends, it cannot be left counted.
struct Entered(Arc<AtomicUsize>);

impl Drop for Entered {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct Gateway {
    router: Router,
    /// One entry per route; `Some` for routes that serve files.
    sites: Vec<Option<Site>>,
    counters: Vec<AtomicUsize>,
    resolver: Resolver,
    challenges: Arc<ChallengeStore>,
    https_redirect: bool,
    https_redirect_port: u16,
    timeouts: Timeouts,
    hsts: Option<String>,
    in_flight: InFlight,
}

impl Gateway {
    pub fn new(
        config: &Config,
        sites: Vec<Option<Site>>,
        challenges: Arc<ChallengeStore>,
        in_flight: InFlight,
    ) -> Self {
        Self {
            in_flight,
            sites,
            counters: config.routes.iter().map(|_| AtomicUsize::new(0)).collect(),
            router: Router::new(config.routes.clone()),
            resolver: Resolver::default(),
            challenges,
            https_redirect: config.https_redirect,
            https_redirect_port: config.https_redirect_port,
            timeouts: config.timeouts,
            hsts: config.hsts.clone(),
        }
    }
}

#[derive(Default)]
pub struct RequestCtx {
    route: Option<usize>,
    host: String,
    /// The authority as the client wrote it, port included.
    forwarded_host: String,
    upstream: Option<String>,
    connect_failures: u32,
    started: Option<Instant>,
    /// Held, not read: the request is counted for as long as this lives.
    _in_flight: Option<Entered>,
}

fn is_tls(session: &Session) -> bool {
    session.digest().is_some_and(|d| d.ssl_digest.is_some())
}

/// A response written here rather than by an upstream: an error, a redirect.
/// `hsts` is the `Strict-Transport-Security` value to send with it, which the
/// caller has only for requests that came over HTTPS.
pub(crate) async fn respond(
    session: &mut Session,
    status: u16,
    headers: &[(&'static str, String)],
    body: &'static str,
    hsts: Option<&str>,
) -> Result<()> {
    let mut resp = ResponseHeader::build(status, Some(headers.len() + 3))?;
    resp.insert_header("Content-Type", "text/plain; charset=utf-8")?;
    resp.insert_header("Content-Length", body.len().to_string())?;
    for (name, value) in headers {
        resp.insert_header(*name, value)?;
    }
    if let Some(value) = hsts {
        resp.insert_header("Strict-Transport-Security", value)?;
    }
    session
        .write_response_header(Box::new(resp), body.is_empty())
        .await?;
    if !body.is_empty() {
        session
            .write_response_body(Some(Bytes::from_static(body.as_bytes())), true)
            .await?;
    }
    Ok(())
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> RequestCtx {
        RequestCtx {
            _in_flight: Some(self.in_flight.enter()),
            ..Default::default()
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut RequestCtx) -> Result<bool> {
        ctx.started = Some(Instant::now());
        // The client has to keep reading the response too.
        session.set_write_timeout(self.timeouts.write);
        let tls = is_tls(session);
        let hsts = self.hsts.as_deref().filter(|_| tls);
        normalize_request_path(session)?;
        let req = session.req_header();
        let path = req.uri.path().to_string();

        if let Some(why) = bad_host(req) {
            respond(session, 400, &[], why, hsts).await?;
            return Ok(true);
        }

        // Before routing and before the redirect: the CA validates over plain
        // HTTP, and it does so before the host has any certificate.
        let challenge = if tls {
            None
        } else {
            path.strip_prefix(CHALLENGE_PREFIX)
        };
        if let Some(token) = challenge
            && let Some(key_authorization) = self.challenges.get(token)
        {
            let mut resp = ResponseHeader::build(200, Some(2))?;
            resp.insert_header("Content-Type", "application/octet-stream")?;
            resp.insert_header("Content-Length", key_authorization.len().to_string())?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(Bytes::from(key_authorization)), true)
                .await?;
            return Ok(true);
        }

        let Some(host) = request_host(req) else {
            respond(session, 400, &[], "missing host\n", hsts).await?;
            return Ok(true);
        };
        ctx.forwarded_host = client_authority(req).unwrap_or_else(|| host.clone());
        let Some(route) = self.router.find(&host, &path) else {
            ctx.host = host;
            respond(session, 404, &[], "no route for this host\n", hsts).await?;
            return Ok(true);
        };
        ctx.route = Some(route);

        // A challenge this process has no answer for belongs to whoever runs
        // ACME for the route, if the route says so.
        let passthrough = challenge.is_some() && self.router.routes[route].acme_passthrough;
        if challenge.is_some() && !passthrough {
            ctx.host = host;
            respond(session, 404, &[], "unknown challenge\n", hsts).await?;
            return Ok(true);
        }

        if !tls && self.https_redirect && !passthrough {
            let target = req.uri.path_and_query().map_or("/", |pq| pq.as_str());
            let location = match self.https_redirect_port {
                443 => format!("https://{host}{target}"),
                port => format!("https://{host}:{port}{target}"),
            };
            ctx.host = host;
            respond(session, 308, &[("Location", location)], "", hsts).await?;
            return Ok(true);
        }
        ctx.host = host;

        if let Some(site) = &self.sites[route] {
            let prefix = &self.router.routes[route].path;
            let source = files::serve(site, session, prefix, hsts).await?;
            ctx.upstream = Some(source.to_string());
            return Ok(true);
        }
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<Box<HttpPeer>> {
        let index = ctx.route.expect("request_filter sets the route");
        let route = &self.router.routes[index];
        // Round robin across upstreams; a retry lands on the next one.
        let turn = self.counters[index].fetch_add(1, Ordering::Relaxed);
        let upstream = &route.upstreams[turn % route.upstreams.len()];
        // Before resolving, so the access log names it even if that fails.
        ctx.upstream = Some(upstream.authority());
        let addrs = self.resolver.resolve(upstream).await?;
        let addr = addrs[turn / route.upstreams.len() % addrs.len()];

        let mut peer = HttpPeer::new(addr, upstream.tls, upstream.host.clone());
        peer.options.connection_timeout = self.timeouts.upstream_connect;
        peer.options.read_timeout = route.read_timeout.unwrap_or(self.timeouts.upstream_read);
        peer.options.write_timeout = self.timeouts.write;
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut RequestCtx,
    ) -> Result<()> {
        let route = &self.router.routes[ctx.route.expect("request_filter sets the route")];

        // These are overwritten, not appended to: this proxy is the edge, so
        // whatever the client sent in them is not to be trusted. The ones this
        // proxy does not fill in are dropped for the same reason.
        for name in ["Forwarded", "X-Real-IP", "X-Forwarded-Server"] {
            upstream_request.remove_header(name);
        }
        if let Some(addr) = session.client_addr().and_then(|a| a.as_inet()) {
            upstream_request.insert_header("X-Forwarded-For", addr.ip().to_string())?;
        }
        let tls = is_tls(session);
        upstream_request.insert_header("X-Forwarded-Proto", if tls { "https" } else { "http" })?;
        upstream_request.insert_header("X-Forwarded-Host", &ctx.forwarded_host)?;
        let default_port = if tls { 443 } else { 80 };
        let port = port_of(&ctx.forwarded_host).unwrap_or(default_port);
        upstream_request.insert_header("X-Forwarded-Port", port.to_string())?;

        match &route.set_host {
            Some(host) => {
                upstream_request.insert_header("Host", host)?;
            }
            // HTTP/2 requests carry the host in :authority and have no Host
            // header, which an HTTP/1.1 upstream requires.
            None if upstream_request.headers.get(http::header::HOST).is_none() => {
                let authority = upstream_request
                    .uri
                    .authority()
                    .map_or_else(|| ctx.host.clone(), |a| a.to_string());
                upstream_request.insert_header("Host", authority)?;
            }
            None => {}
        }

        if route.strip_prefix && route.path != "/" {
            let original = upstream_request
                .uri
                .path_and_query()
                .map_or("/", |pq| pq.as_str());
            let rewritten = strip_prefix(&route.path, original);
            let uri = rewritten
                .parse::<http::Uri>()
                .or_err(InternalError, "rewritten path is not a valid URI")?;
            upstream_request.set_uri(uri);
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut RequestCtx,
    ) -> Result<()> {
        if let Some(value) = &self.hsts
            && is_tls(session)
        {
            upstream_response.insert_header("Strict-Transport-Security", value)?;
        }
        Ok(())
    }

    /// The response for a request that failed on the way: an upstream that
    /// is down or too slow, mostly. The status is chosen as Pingora chooses
    /// it by default; the difference is that the response carries the same
    /// `Strict-Transport-Security` as every other one.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        _ctx: &mut RequestCtx,
    ) -> FailToProxy {
        let code = match (e.etype(), e.esource()) {
            (HTTPStatus(code), _) => *code,
            (_, ErrorSource::Upstream) => 502,
            // The client is gone: nobody to answer.
            (WriteError | ReadError | ConnectionClosed, ErrorSource::Downstream) => 0,
            (_, ErrorSource::Downstream) => 400,
            (_, ErrorSource::Internal | ErrorSource::Unset) => 500,
        };
        if code > 0 {
            let mut resp = ServerSession::generate_error(code);
            if let Some(value) = self.hsts.as_deref().filter(|_| is_tls(session)) {
                // The value was checked when the configuration was read.
                let _ = resp.insert_header("Strict-Transport-Security", value);
            }
            let written = session
                .as_downstream_mut()
                .write_error_response(resp, Bytes::new());
            if let Err(e) = written.await {
                warn!("could not send the {code} response: {e}");
            }
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut RequestCtx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        // Nothing has been sent upstream yet, so trying again is always safe.
        if ctx.connect_failures < MAX_CONNECT_RETRIES {
            ctx.connect_failures += 1;
            e.set_retry(true);
        }
        e
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut RequestCtx) {
        let req = session.req_header();
        let status = session.response_written().map_or(0, |r| r.status.as_u16());
        let client = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map_or_else(|| "-".to_string(), |a| a.ip().to_string());
        let route = ctx
            .route
            .map_or("-", |i| self.router.routes[i].name.as_str());
        // The query string is left out on purpose: it often carries tokens.
        info!(
            target: "access",
            "{client} {} {}{} {status} route={route} upstream={} {}ms",
            req.method,
            if ctx.host.is_empty() { "-" } else { &ctx.host },
            req.uri.path(),
            ctx.upstream.as_deref().unwrap_or("-"),
            ctx.started.map_or(0, |s| s.elapsed().as_millis()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str, hosts: &[&str], path: &str) -> Route {
        Route {
            name: name.into(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            path: path.into(),
            strip_prefix: false,
            upstreams: vec![],
            site: None,
            set_host: None,
            cert_files: None,
            acme_passthrough: false,
            read_timeout: None,
        }
    }

    fn name(router: &Router, host: &str, path: &str) -> Option<String> {
        router
            .find(host, path)
            .map(|i| router.routes[i].name.clone())
    }

    #[test]
    fn routing_precedence() {
        let router = Router::new(vec![
            route("root", &["example.com"], "/"),
            route("api", &["example.com"], "/api"),
            route("deep", &["example.com"], "/api/v2"),
            route("wild", &["*.example.com"], "/"),
            route("exact", &["a.example.com"], "/only"),
        ]);
        assert_eq!(name(&router, "example.com", "/").as_deref(), Some("root"));
        assert_eq!(
            name(&router, "example.com", "/apix").as_deref(),
            Some("root")
        );
        assert_eq!(name(&router, "example.com", "/api").as_deref(), Some("api"));
        assert_eq!(
            name(&router, "example.com", "/api/users").as_deref(),
            Some("api")
        );
        assert_eq!(
            name(&router, "example.com", "/api/v2/x").as_deref(),
            Some("deep")
        );
        assert_eq!(
            name(&router, "b.example.com", "/x").as_deref(),
            Some("wild")
        );
        // An exact host that has no matching path falls back to the wildcard.
        assert_eq!(
            name(&router, "a.example.com", "/only/1").as_deref(),
            Some("exact")
        );
        assert_eq!(
            name(&router, "a.example.com", "/else").as_deref(),
            Some("wild")
        );
        assert_eq!(name(&router, "x.y.example.com", "/"), None);
        assert_eq!(name(&router, "other.test", "/"), None);
    }

    #[test]
    fn prefix_stripping_keeps_the_query() {
        assert_eq!(strip_prefix("/api", "/api"), "/");
        assert_eq!(strip_prefix("/api", "/api/"), "/");
        assert_eq!(strip_prefix("/api", "/api/users?id=1"), "/users?id=1");
        assert_eq!(strip_prefix("/api", "/api?id=1"), "/?id=1");
        assert_eq!(strip_prefix("/", "/x?y"), "/x?y");
    }

    #[test]
    fn host_is_normalised() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(request_host(&req), None);
        req.insert_header("Host", "Example.COM.:8443").unwrap();
        assert_eq!(request_host(&req).as_deref(), Some("example.com"));
        req.insert_header("Host", "[::1]:80").unwrap();
        assert_eq!(request_host(&req).as_deref(), Some("::1"));

        assert_eq!(
            normalize_host("my_app.test").as_deref(),
            Some("my_app.test")
        );
        assert_eq!(normalize_host("a.test:").as_deref(), Some("a.test"));
        assert_eq!(normalize_host("[fe80::1]").as_deref(), Some("fe80::1"));
    }

    #[test]
    fn what_cannot_be_a_host_is_not_one() {
        for bad in [
            "",
            ".",
            ":80",
            "a.test:80x",
            "a.test:80:80",
            // Spaces would let a client write its own access log fields.
            "a.test 200 route=admin",
            "a.test/admin",
            "a.test\tx",
            "user@a.test",
            "caf\u{e9}.test",
            "[::1",
            "[::1]x",
            "[::1]:x",
            "[a.test]",
            "[]",
        ] {
            assert_eq!(normalize_host(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_request_naming_two_hosts_or_no_real_host_is_refused() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(bad_host(&req), None);
        req.insert_header("Host", "app.test:8443").unwrap();
        assert_eq!(bad_host(&req), None);
        req.insert_header("Host", "app.test 200 route=admin")
            .unwrap();
        assert_eq!(bad_host(&req), Some("malformed host\n"));

        // HTTP/2 carries the authority in the URI (`:authority`).
        let mut absolute = RequestHeader::build("GET", b"/x", None).unwrap();
        absolute.set_uri("http://app.test/x".parse().unwrap());
        assert_eq!(bad_host(&absolute), None);
        absolute.insert_header("Host", "App.test").unwrap();
        assert_eq!(bad_host(&absolute), None);
        absolute.insert_header("Host", "admin.internal").unwrap();
        assert_eq!(bad_host(&absolute), Some("ambiguous host\n"));

        let mut twice = RequestHeader::build("GET", b"/", None).unwrap();
        twice.append_header("Host", "a.test").unwrap();
        twice.append_header("Host", "a.test").unwrap();
        assert_eq!(bad_host(&twice), Some("ambiguous host\n"));
    }

    #[test]
    fn unreserved_escapes_are_decoded_and_the_rest_left_alone() {
        assert_eq!(decode_unreserved("/%61pi").as_deref(), Some("/api"));
        assert_eq!(decode_unreserved("/a%2Dz%7E%5f").as_deref(), Some("/a-z~_"));
        assert_eq!(decode_unreserved("/plain"), None);
        // Slashes, dots, spaces and malformed escapes are not touched.
        assert_eq!(decode_unreserved("/a%2Fb"), None);
        assert_eq!(decode_unreserved("/%2e%2e/x"), None);
        assert_eq!(decode_unreserved("/a%20b"), None);
        assert_eq!(decode_unreserved("/%zz%6"), None);
        assert_eq!(decode_unreserved("/%61%").as_deref(), Some("/a%"));
        // Neither is UTF-8 that was sent as it is, escaped or not.
        assert_eq!(decode_unreserved("/caf\u{e9}/\u{65e5}\u{672c}"), None);
        assert_eq!(
            decode_unreserved("/%61/caf\u{e9}/\u{65e5}\u{672c}/%7E").as_deref(),
            Some("/a/caf\u{e9}/\u{65e5}\u{672c}/~")
        );
        assert_eq!(
            decode_unreserved("/%61/caf%C3%A9").as_deref(),
            Some("/a/caf%C3%A9")
        );
    }

    #[test]
    fn requests_are_counted_while_they_are_served() {
        let in_flight = InFlight::default();
        let (first, second) = (in_flight.enter(), in_flight.enter());
        assert_eq!(in_flight.count(), 2);
        drop(first);
        assert_eq!(in_flight.count(), 1);
        drop(second);
        assert_eq!(in_flight.count(), 0);
    }

    #[test]
    fn the_client_authority_comes_from_host_or_the_uri() {
        let mut h1 = RequestHeader::build("GET", b"/", None).unwrap();
        h1.insert_header("Host", "app.test:8443").unwrap();
        assert_eq!(client_authority(&h1).as_deref(), Some("app.test:8443"));

        // HTTP/2 has no Host header: the port has to come from `:authority`.
        let mut h2 = RequestHeader::build("GET", b"/", None).unwrap();
        h2.set_uri("https://app.test:8443/".parse().unwrap());
        assert_eq!(client_authority(&h2).as_deref(), Some("app.test:8443"));
        assert_eq!(
            client_authority(&RequestHeader::build("GET", b"/", None).unwrap()),
            None
        );
    }

    const A: &str = "10.0.0.1:80";
    const B: &str = "10.0.0.2:80";

    fn named(host: &str) -> Upstream {
        Upstream {
            host: host.into(),
            port: 80,
            tls: false,
        }
    }

    type Answer = (Duration, std::result::Result<&'static str, &'static str>);

    /// A resolver whose n-th lookup takes `script(n).0` and then gives
    /// `script(n).1`, plus the number of lookups made so far.
    fn scripted(
        script: impl Fn(usize) -> Answer + Send + Sync + 'static,
    ) -> (Resolver, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let lookup: Lookup = Arc::new(move |_authority| {
            let (delay, answer) = script(counter.fetch_add(1, Ordering::SeqCst));
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                answer
                    .map(|addr| vec![addr.parse().unwrap()])
                    .map_err(std::io::Error::other)
            })
        });
        (Resolver::new(lookup), calls)
    }

    fn addrs(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    const INSTANT: Duration = Duration::ZERO;

    #[tokio::test(start_paused = true)]
    async fn a_slow_resolver_does_not_stall_a_known_upstream() {
        let (resolver, _) = scripted(|n| match n {
            0 => (INSTANT, Ok(A)),
            _ => (Duration::from_secs(3), Ok(B)),
        });
        assert_eq!(resolver.resolve(&named("app")).await.unwrap(), addrs(&[A]));

        tokio::time::sleep(DNS_TTL + Duration::from_secs(1)).await;
        let asked = Instant::now();
        let got = resolver.resolve(&named("app")).await.unwrap();
        assert!(
            asked.elapsed() <= Duration::from_secs(1),
            "waited {:?} for an address that was already known",
            asked.elapsed()
        );
        assert_eq!(got, addrs(&[A]));

        // The slow answer is not thrown away: once it lands it is used.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(resolver.resolve(&named("app")).await.unwrap(), addrs(&[B]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_resolver_that_never_answers_is_given_up_on() {
        let (resolver, calls) = scripted(|n| match n {
            0 => (INSTANT, Ok(A)),
            _ => (Duration::from_secs(3600), Ok(B)),
        });
        resolver.resolve(&named("app")).await.unwrap();
        tokio::time::sleep(DNS_TTL + Duration::from_secs(1)).await;
        assert_eq!(resolver.resolve(&named("app")).await.unwrap(), addrs(&[A]));

        // The stuck lookup does not block later ones for ever.
        tokio::time::sleep(LOOKUP_TIMEOUT + DNS_TTL + Duration::from_secs(1)).await;
        assert_eq!(resolver.resolve(&named("app")).await.unwrap(), addrs(&[A]));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn requests_arriving_together_share_one_lookup() {
        let (resolver, calls) = scripted(|n| match n {
            0 => (INSTANT, Ok(A)),
            _ => (Duration::from_millis(50), Ok(B)),
        });
        resolver.resolve(&named("app")).await.unwrap();
        tokio::time::sleep(DNS_TTL + Duration::from_secs(1)).await;

        let upstream = named("app");
        let together = (0..50).map(|_| resolver.resolve(&upstream));
        for result in futures_util::future::join_all(together).await {
            result.unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2, "one to start, one refresh");
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_resolver_is_asked_once_per_ttl_not_once_per_request() {
        let (resolver, calls) = scripted(|n| match n {
            0 => (INSTANT, Ok(A)),
            _ => (INSTANT, Err("servfail")),
        });
        resolver.resolve(&named("app")).await.unwrap();
        tokio::time::sleep(DNS_TTL + Duration::from_secs(1)).await;

        for _ in 0..10 {
            // The last known address keeps the upstream reachable.
            assert_eq!(resolver.resolve(&named("app")).await.unwrap(), addrs(&[A]));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        tokio::time::sleep(DNS_TTL + Duration::from_secs(1)).await;
        resolver.resolve(&named("app")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3, "asked again a TTL later");
    }

    #[tokio::test(start_paused = true)]
    async fn an_unknown_upstream_waits_for_its_first_lookup_but_not_forever() {
        let (resolver, _) = scripted(|_| (Duration::from_millis(200), Ok(A)));
        assert_eq!(resolver.resolve(&named("app")).await.unwrap(), addrs(&[A]));

        let (resolver, _) = scripted(|_| (Duration::from_secs(3600), Ok(A)));
        let asked = Instant::now();
        assert!(resolver.resolve(&named("app")).await.is_err());
        assert!(asked.elapsed() <= Duration::from_secs(10), "gave up late");

        let (resolver, _) = scripted(|_| (INSTANT, Err("nxdomain")));
        let error = resolver.resolve(&named("app")).await.unwrap_err();
        // The upstream's failure, so a 502 for the client and not a 500.
        assert_eq!(error.esource(), &ErrorSource::Upstream);
        assert!(error.to_string().contains("app:80: nxdomain"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn addresses_are_not_looked_up() {
        let (resolver, calls) = scripted(|_| (INSTANT, Err("unused")));
        let literal = Upstream {
            host: "127.0.0.1".into(),
            port: 8080,
            tls: false,
        };
        assert_eq!(
            resolver.resolve(&literal).await.unwrap(),
            addrs(&["127.0.0.1:8080"])
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ports_come_from_the_client_authority() {
        assert_eq!(port_of("example.com:8443"), Some(8443));
        assert_eq!(port_of("example.com"), None);
        assert_eq!(port_of("[::1]:8080"), Some(8080));
        assert_eq!(port_of("[::1]"), None);
    }
}
