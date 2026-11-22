mod acme;
mod certs;
mod config;
mod files;
mod limit;
mod proxy;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::{error, info};
use pingora::apps::HttpServerOptions;
use pingora::listeners::TcpSocketOptions;
use pingora::listeners::tls::TlsSettings;
use pingora::protocols::TcpKeepalive;
use pingora::proxy::http_proxy_service;
use pingora::server::configuration::ServerConf;
use pingora::server::{Server, ShutdownWatch};
use pingora::services::background::{BackgroundService, background_service};

use crate::acme::{AcmeService, ChallengeStore};
use crate::certs::{BoxError, CertReloader, CertStore};
use crate::config::{CertFiles, Config, TlsMode};
use crate::files::{MemoryBudget, Site};
use crate::proxy::InFlight;

fn main() -> ExitCode {
    let vars = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)));
    let config = match Config::from_env(vars) {
        Ok(config) => config,
        Err(problems) => {
            eprintln!("pingenv: invalid configuration");
            for problem in problems {
                eprintln!("  - {problem}");
            }
            return ExitCode::from(2);
        }
    };

    if std::env::args().nth(1).as_deref() == Some("--healthcheck") {
        return healthcheck(&config);
    }

    env_logger::Builder::new()
        .filter_level(config.log_level)
        .format_target(false)
        .init();

    match run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("startup failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// For a container `HEALTHCHECK`, since the image has no shell or curl: the
/// process is healthy if it accepts connections on its HTTP port. Takes the
/// same environment as the server, so it finds the port by itself.
fn healthcheck(config: &Config) -> ExitCode {
    let mut addr = config.http_addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr {
            SocketAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
            SocketAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
        });
    }
    match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pingenv: nothing is accepting connections on {addr}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Ends a shutdown as soon as there is nothing left to wait for.
///
/// On `SIGTERM` Pingora closes the listeners, lets requests in flight carry
/// on, and then sleeps for the whole grace period whether or not anything is
/// still running. With nothing running that is only downtime: the container
/// replacing this one cannot have the ports until the process is gone. The
/// grace period stays the upper bound; this just stops waiting when the last
/// request is done.
struct Drain {
    in_flight: InFlight,
}

#[async_trait]
impl BackgroundService for Drain {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if shutdown.changed().await.is_err() {
            return;
        }
        // Two looks in a row, so that a request which had arrived but was not
        // yet being served when the signal came is not missed.
        let mut quiet = 0;
        while quiet < 2 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            quiet = if self.in_flight.count() == 0 {
                quiet + 1
            } else {
                0
            };
        }
        info!("no requests in flight, exiting");
        // What Pingora itself does once the grace period is over.
        std::process::exit(0);
    }
}

/// For every accepted connection: have the kernel check that a quiet client
/// is still there. One that vanished without closing (a phone that left the
/// network, a NAT that forgot the connection) is found within two minutes and
/// dropped, where the idle timeout does not reach: a request or a WebSocket
/// that is open but silent.
fn socket_options() -> TcpSocketOptions {
    let mut options = TcpSocketOptions::default();
    options.tcp_keepalive = Some(TcpKeepalive {
        idle: Duration::from_secs(60),
        interval: Duration::from_secs(10),
        count: 6,
        // The system default.
        #[cfg(target_os = "linux")]
        user_timeout: Duration::ZERO,
    });
    options
}

fn run(config: Config) -> Result<(), BoxError> {
    let store = Arc::new(CertStore::new());
    let challenges = Arc::new(ChallengeStore::default());

    // Certificates are per host: files named on one route serve that host on
    // all of them, and each pair of files is loaded and watched once.
    let reloader = CertReloader::new(store.clone(), config.cert_reload_interval);
    let mut by_files: Vec<(&CertFiles, Vec<String>)> = Vec::new();
    for (host, files) in config.cert_files() {
        match by_files.iter_mut().find(|(known, _)| *known == files) {
            Some((_, hosts)) => hosts.push(host.to_string()),
            None => by_files.push((files, vec![host.to_string()])),
        }
    }
    for (files, hosts) in by_files {
        let key = Arc::new(certs::certified_key_from_files(&files.cert, &files.key)?);
        for host in &hosts {
            store.set(host, key.clone());
        }
        reloader.watch(hosts, files.cert.clone(), files.key.clone());
    }
    for host in config.self_signed_hosts() {
        store.set(&host, Arc::new(certs::self_signed(&host)?));
    }

    let budget = MemoryBudget::new(config.memory_max_total);
    let sites = config
        .routes
        .iter()
        .map(|route| {
            route
                .site
                .as_ref()
                .map(|site| Site::load(&route.name, site, budget.clone()))
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let acme_hosts = config.acme_hosts();
    let acme = if acme_hosts.is_empty() {
        None
    } else {
        Some(AcmeService::new(
            config.acme.clone(),
            acme_hosts,
            &config.data_dir,
            store.clone(),
            challenges.clone(),
        )?)
    };

    let conf = ServerConf {
        threads: config.threads,
        grace_period_seconds: Some(config.shutdown_grace_seconds),
        graceful_shutdown_timeout_seconds: Some(3),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let in_flight = InFlight::default();
    let mut service = http_proxy_service(
        &server.configuration,
        proxy::Gateway::new(&config, sites, challenges, in_flight.clone()),
    );
    // An HTTP/2 connection with no request on it is closed after the same
    // time as an idle HTTP/1.1 one, which the gateway sees to per request.
    let mut options = HttpServerOptions::default();
    options.h2_idle_timeout = config.timeouts.client_idle;
    service
        .app_logic_mut()
        .expect("a new service has its application")
        .server_options = Some(options);
    service.add_tcp_with_settings(&config.http_addr.to_string(), socket_options());
    info!("listening for HTTP on {}", config.http_addr);

    if config.tls != TlsMode::Off {
        // The paths are unused: every certificate comes from the resolver.
        let mut tls = TlsSettings::intermediate("", "")?;
        tls.set_cert_resolver(store);
        if config.http2 {
            tls.enable_h2();
        }
        service.add_tls_with_settings(&config.https_addr.to_string(), Some(socket_options()), tls);
        info!(
            "listening for HTTPS on {} ({:?}{})",
            config.https_addr,
            config.tls,
            if config.http2 { "" } else { ", HTTP/1.1 only" }
        );
    }
    for route in &config.routes {
        let mut upstreams: Vec<String> = route.upstreams.iter().map(|u| u.authority()).collect();
        if let Some(site) = &route.site {
            upstreams.push(format!("files in {}", site.root.display()));
        }
        if let Some(redirect) = &route.redirect {
            upstreams.push(format!("{} to {}", redirect.status, redirect.to));
        }
        info!(
            "route {}: {}{} -> {}",
            route.name,
            route.hosts.join(","),
            route.path,
            upstreams.join(",")
        );
    }

    server.add_service(service);
    server.add_service(background_service("drain", Drain { in_flight }));
    if let Some(acme) = acme {
        server.add_service(background_service("acme", acme));
    }
    if !reloader.is_empty() {
        server.add_service(background_service("cert-reload", reloader));
    }
    server.run_forever()
}
