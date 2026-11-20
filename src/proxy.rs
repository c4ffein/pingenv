//! The request path: answer ACME challenges, pick a route by host and path,
//! redirect plain HTTP to HTTPS, and forward everything else upstream.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use log::{info, warn};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;

use crate::acme::{CHALLENGE_PREFIX, ChallengeStore};
use crate::config::{Config, Route, Timeouts, Upstream};
use crate::files::{self, Site};

/// Upstream names are re-resolved this often, so a container that comes back
/// with a new address is picked up without restarting the proxy.
const DNS_TTL: Duration = Duration::from_secs(10);
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
fn normalize_host(raw: &str) -> Option<String> {
    let host = match raw.trim().strip_prefix('[') {
        Some(v6) => v6.split(']').next()?,
        None => raw.trim().split(':').next()?,
    };
    (!host.is_empty()).then(|| host.trim_end_matches('.').to_ascii_lowercase())
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
/// answered on the other, so it is refused instead.
fn ambiguous_host(req: &RequestHeader) -> bool {
    if req.headers.get_all(http::header::HOST).iter().count() > 1 {
        return true;
    }
    let header = req
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok());
    match (req.uri.host(), header) {
        (Some(target), Some(header)) => normalize_host(target) != normalize_host(header),
        _ => false,
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
    let mut out = String::with_capacity(path.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            let byte = (high * 16 + low) as u8;
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~') {
                out.push(byte as char);
                i += 3;
                changed = true;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    changed.then_some(out)
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

#[derive(Default)]
struct Resolver {
    cache: Mutex<HashMap<String, (Instant, Vec<SocketAddr>)>>,
}

impl Resolver {
    async fn resolve(&self, upstream: &Upstream) -> Result<Vec<SocketAddr>> {
        let authority = upstream.authority();
        if let Ok(addr) = authority.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }
        let cached = self.cache.lock().unwrap().get(&authority).cloned();
        if let Some((at, addrs)) = &cached
            && at.elapsed() < DNS_TTL
        {
            return Ok(addrs.clone());
        }
        let looked_up = tokio::net::lookup_host(&authority)
            .await
            .map(|found| found.collect::<Vec<SocketAddr>>());
        match looked_up {
            Ok(addrs) => {
                if addrs.is_empty() {
                    return Error::e_explain(ConnectNoRoute, format!("{authority}: no addresses"));
                }
                self.cache
                    .lock()
                    .unwrap()
                    .insert(authority, (Instant::now(), addrs.clone()));
                Ok(addrs)
            }
            // A resolver hiccup should not take down an upstream that was
            // reachable a moment ago.
            Err(e) => match cached {
                Some((_, addrs)) => {
                    warn!("{authority}: lookup failed ({e}), using last known address");
                    Ok(addrs)
                }
                None => Error::e_explain(ConnectNoRoute, format!("{authority}: {e}")),
            },
        }
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
}

impl Gateway {
    pub fn new(config: &Config, sites: Vec<Option<Site>>, challenges: Arc<ChallengeStore>) -> Self {
        Self {
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
}

fn is_tls(session: &Session) -> bool {
    session.digest().is_some_and(|d| d.ssl_digest.is_some())
}

pub(crate) async fn respond(
    session: &mut Session,
    status: u16,
    headers: &[(&'static str, String)],
    body: &'static str,
) -> Result<()> {
    let mut resp = ResponseHeader::build(status, Some(headers.len() + 2))?;
    resp.insert_header("Content-Type", "text/plain; charset=utf-8")?;
    resp.insert_header("Content-Length", body.len().to_string())?;
    for (name, value) in headers {
        resp.insert_header(*name, value)?;
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
        RequestCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut RequestCtx) -> Result<bool> {
        ctx.started = Some(Instant::now());
        // The client has to keep reading the response too.
        session.set_write_timeout(self.timeouts.write);
        let tls = is_tls(session);
        normalize_request_path(session)?;
        let req = session.req_header();
        let path = req.uri.path().to_string();

        if ambiguous_host(req) {
            respond(session, 400, &[], "ambiguous host\n").await?;
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
            respond(session, 400, &[], "missing host\n").await?;
            return Ok(true);
        };
        ctx.forwarded_host = client_authority(req).unwrap_or_else(|| host.clone());
        let Some(route) = self.router.find(&host, &path) else {
            ctx.host = host;
            respond(session, 404, &[], "no route for this host\n").await?;
            return Ok(true);
        };
        ctx.route = Some(route);

        // A challenge this process has no answer for belongs to whoever runs
        // ACME for the route, if the route says so.
        let passthrough = challenge.is_some() && self.router.routes[route].acme_passthrough;
        if challenge.is_some() && !passthrough {
            ctx.host = host;
            respond(session, 404, &[], "unknown challenge\n").await?;
            return Ok(true);
        }

        if !tls && self.https_redirect && !passthrough {
            let target = req.uri.path_and_query().map_or("/", |pq| pq.as_str());
            let location = match self.https_redirect_port {
                443 => format!("https://{host}{target}"),
                port => format!("https://{host}:{port}{target}"),
            };
            ctx.host = host;
            respond(session, 308, &[("Location", location)], "").await?;
            return Ok(true);
        }
        ctx.host = host;

        if let Some(site) = &self.sites[route] {
            let prefix = &self.router.routes[route].path;
            let hsts = self.hsts.as_deref().filter(|_| tls);
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
        let addrs = self.resolver.resolve(upstream).await?;
        let addr = addrs[turn / route.upstreams.len() % addrs.len()];

        ctx.upstream = Some(upstream.authority());
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
    }

    #[test]
    fn a_request_naming_two_hosts_is_ambiguous() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        assert!(!ambiguous_host(&req));
        req.insert_header("Host", "app.test:8443").unwrap();
        assert!(!ambiguous_host(&req));

        // HTTP/2 carries the authority in the URI (`:authority`).
        let mut absolute = RequestHeader::build("GET", b"/x", None).unwrap();
        absolute.set_uri("http://app.test/x".parse().unwrap());
        absolute.insert_header("Host", "App.test").unwrap();
        assert!(!ambiguous_host(&absolute));
        absolute.insert_header("Host", "admin.internal").unwrap();
        assert!(ambiguous_host(&absolute));

        let mut twice = RequestHeader::build("GET", b"/", None).unwrap();
        twice.append_header("Host", "a.test").unwrap();
        twice.append_header("Host", "a.test").unwrap();
        assert!(ambiguous_host(&twice));
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

    #[test]
    fn ports_come_from_the_client_authority() {
        assert_eq!(port_of("example.com:8443"), Some(8443));
        assert_eq!(port_of("example.com"), None);
        assert_eq!(port_of("[::1]:8080"), Some(8080));
        assert_eq!(port_of("[::1]"), None);
    }
}
