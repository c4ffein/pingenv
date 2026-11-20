# pingenv

A small reverse proxy and static file server built on
[Pingora](https://github.com/cloudflare/pingora), configured **only by
environment variables**, with certificate issuance and renewal built in. No
config file, no admin UI, no sidecar.

```sh
docker run -p 80:80 -p 443:443 -v pingenv-data:/data \
  -e PINGENV_TLS_MODE=acme \
  -e PINGENV_ROUTE_APP_HOST=app.example.com \
  -e PINGENV_ROUTE_APP_UPSTREAM=app:8080 \
  pingenv
```

See [`docker-compose.yml`](docker-compose.yml) for a fuller example.

Every setting starts with `PINGENV_`. An unknown `PINGENV_*` variable is an
error, so a typo stops the container instead of being silently ignored;
variables without the prefix are never read. A bad configuration prints every
problem at once and exits with status 2.

## Routes

A route is a group of variables sharing a name:
`PINGENV_ROUTE_<NAME>_<SETTING>`. Names use `A-Z`, `0-9` and `_`, and only
show up in logs. Each route either proxies to an upstream or serves files.

| `PINGENV_ROUTE_<NAME>_…` | Meaning |
|---|---|
| `HOST` | **Required.** Host names, comma separated. `*.example.com` matches exactly one extra label. |
| `PATH` | Path prefix, default `/`. `/api` matches `/api` and `/api/x`, not `/apix`. |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | PEM certificate chain and key for this route's hosts, instead of ACME. Re-read when the files change (see `PINGENV_CERT_RELOAD_INTERVAL`). |
| `ACME_PASSTHROUGH` | `true` lets `/.well-known/acme-challenge/` requests that pingenv has no answer for reach this route's upstream or files, with no HTTPS redirect. For an upstream that runs its own ACME client (certbot, say), paired with `TLS_CERT_FILE`. Default `false`. |

An exact host beats a wildcard, and within a host the longest path prefix
wins. Requests for a host with no route get a 404.

### Proxying

| `PINGENV_ROUTE_<NAME>_…` | Meaning |
|---|---|
| `UPSTREAM` | `host:port`, comma separated for round robin. Prefix with `https://` to connect over TLS (port defaults to 443, certificate is verified). |
| `STRIP_PREFIX` | `true` removes the path prefix before forwarding. Default `false`. |
| `SET_HOST` | Replaces the `Host` header sent upstream. By default the client's is kept. |
| `READ_TIMEOUT` | How long to wait for the upstream to send (response headers, then each piece of the body). Overrides `PINGENV_UPSTREAM_READ_TIMEOUT` for this route; `0` means no limit. |

### Serving files

| `PINGENV_ROUTE_<NAME>_…` | Meaning |
|---|---|
| `ROOT` | Absolute path of the directory to serve. The route's path prefix maps onto it: with `PATH=/docs`, `/docs/a.css` is `ROOT/a.css`. |
| `MEMORY_MAX_FILE` | Files up to this size are held in memory; larger ones are streamed from disk. Default `0`: everything is served from disk, and the operating system's page cache keeps hot files fast. |
| `MEMORY_PATHS` | With `MEMORY_MAX_FILE` set: which files and directories, below `ROOT`, may be held in memory. Comma separated, like `/index.html,/assets`. Default `/`: everything. |
| `MEMORY_REFRESH` | How long a copy in memory is trusted before the file is checked again; if it changed it is reloaded, and if it is gone or grew past the limit it is dropped. Default `5m`; `0` never checks (a startup snapshot). |
| `FALLBACK` | File served when nothing matches, for single-page apps, e.g. `/index.html`. Only applies to paths whose last segment has no dot, so a missing `/app.js` is still a 404. |
| `CACHE_CONTROL` | `Cache-Control` header for this route. Default `no-cache` (browsers revalidate, and get a cheap 304). |

Sizes are a number of bytes, or use `KiB`/`MiB`/`GiB` (or `KB`/`MB`/`GB`).
Durations are seconds, or use `ms`/`s`/`m`/`h`: `30`, `500ms`, `5m`.

**Memory is opt-in.** The files chosen by `MEMORY_MAX_FILE` and `MEMORY_PATHS`
are loaded at startup and counted against `PINGENV_MEMORY_MAX_TOTAL`, so a
directory bigger than expected fails at startup, not under load. Each copy is
checked against its file at most once per `MEMORY_REFRESH` window: an edit shows
up within that window, a deleted file stops being served. Files that were not
loaded (too large, outside `MEMORY_PATHS`, or added later) are always read from
disk. Set `MEMORY_REFRESH=0` for a frozen snapshot, which suits a site baked
into an image.

What it does and does not do:

- `index.html` is served for directories; a directory asked for without its
  trailing slash is redirected. There are **no directory listings**.
- Dotfiles and dot-directories are never served, so a stray `.env` or `.git`
  cannot leak. `.well-known` is the one exception.
- `..` in any encoding is refused, and symlinks are only followed if they
  stay inside the root and lead nowhere a request path could not (a link to
  `.git` or `.env` is refused too).
- `GET` and `HEAD` only. `ETag`, `Last-Modified`, conditional requests and
  single byte ranges are supported.
- No compression and no content negotiation.

## Layouts

The same image covers three setups; only the variables differ.

- **Proxy only.** Every route has an `UPSTREAM`.
- **One container doing both.** Some routes have an `UPSTREAM`, others a
  `ROOT`. See [`docker-compose.yml`](docker-compose.yml).
- **Edge plus file server.** One container terminates TLS and proxies; a
  second one, with TLS off, serves the directory. The file server's `HOST`
  must be the same as the edge's, since the client's `Host` header is passed
  through. See [`docker-compose.split.yml`](docker-compose.split.yml).

The split costs one extra hop per file request. What it buys: the site can be
redeployed by restarting the file server alone, without dropping the edge's
connections or its other routes, and the container holding the certificates
has no access to the content.

## Changing the configuration

There is no reload: the configuration is the environment, and the environment
of a running process cannot change. Recreate the container (`docker compose up
-d`, `containerctl service recreate`, a new Kubernetes revision) and the new
one starts from the new variables. What that costs depends on what is replaced:

- **An upstream or the file server in the split layout:** nothing visible. The
  edge keeps running, re-resolves names every 10 seconds and retries a failed
  connection on the next upstream, so a swap shows up as at most a few
  failed requests.
- **The edge itself:** a gap of a second or two while the new container binds
  the ports, and requests in flight get `PINGENV_SHUTDOWN_GRACE_SECONDS` to
  finish. Certificates survive if `PINGENV_DATA_DIR` is a volume.
- **Certificate files** (`TLS_CERT_FILE`) are the exception: they are re-read
  when they change, so renewing them needs no recreate.

## Global settings

| Variable | Default | Meaning |
|---|---|---|
| `PINGENV_TLS_MODE` | `off` | `off`: HTTP only. `acme`: certificates from an ACME CA. `selfsigned`: generated at startup, for local use. `manual`: every route brings its own files. |
| `PINGENV_HTTP_ADDR` | `0.0.0.0:80` | Plain HTTP listener. |
| `PINGENV_HTTPS_ADDR` | `0.0.0.0:443` | HTTPS listener (HTTP/1.1 and HTTP/2), unless TLS is off. |
| `PINGENV_HTTPS_REDIRECT` | `true` with TLS | Redirect HTTP requests for known hosts to HTTPS (308). |
| `PINGENV_HTTPS_REDIRECT_PORT` | `443` | Port used in the redirect, if HTTPS is published on another one. |
| `PINGENV_DATA_DIR` | `/data` | Where the ACME account and certificates are stored. |
| `PINGENV_ACME_EMAIL` | none | Contact address registered with the CA. |
| `PINGENV_ACME_STAGING` | `false` | Use Let's Encrypt's staging CA (untrusted certificates, generous limits). |
| `PINGENV_ACME_DIRECTORY_URL` | Let's Encrypt | Any other ACME CA. |
| `PINGENV_ACME_CA_FILE` | none | Extra root to trust when talking to the ACME server (private or test CAs). |
| `PINGENV_MEMORY_MAX_TOTAL` | `128MiB` | Cap on file bytes held in memory across all routes, kept for the life of the process. Exceeding it at startup is an error; a copy that no longer fits when it is refreshed is dropped and served from disk. |
| `PINGENV_UPSTREAM_CONNECT_TIMEOUT` | `10s` | Time allowed to open a connection to an upstream. `0` for no limit. |
| `PINGENV_UPSTREAM_READ_TIMEOUT` | `60s` | Time an upstream may stay silent while sending a response. Streaming responses that pause longer need a route-level `READ_TIMEOUT`. |
| `PINGENV_WRITE_TIMEOUT` | `60s` | Time a client, or an upstream, may take to accept data that is being sent to it. |
| `PINGENV_HSTS` | none | `Strict-Transport-Security` value, like `max-age=31536000`, sent on HTTPS responses that pingenv or its upstreams produce. Browsers remember it, so start small. |
| `PINGENV_CERT_RELOAD_INTERVAL` | `60s` | How often `TLS_CERT_FILE` / `TLS_KEY_FILE` are checked for changes. |
| `PINGENV_THREADS` | CPU count | Worker threads. |
| `PINGENV_SHUTDOWN_GRACE_SECONDS` | `5` | Time in-flight requests get to finish after `SIGTERM`. |
| `PINGENV_LOG_LEVEL` | `info` | `off`, `error`, `warn`, `info`, `debug`, `trace`. |

## Certificates

With `PINGENV_TLS_MODE=acme`, each host gets its own certificate through the
HTTP-01 challenge. Using this mode means you accept the CA's terms of service.

- The host name must resolve to this proxy and **port 80 must be reachable**
  from the internet.
- **The data directory must be a volume.** Without it every restart requests
  new certificates and you will hit the CA's rate limits.
- Until the first certificate arrives the host serves a self-signed
  placeholder. Certificates are swapped in live, without a restart.
- Renewal happens after two thirds of a certificate's lifetime. Failures are
  retried after 15 minutes, backing off to 12 hours.
- Wildcard hosts cannot be validated over HTTP-01; give those routes
  certificate files.
- Several hosts are requested at the same time (four at once), so one host with
  broken DNS only holds up itself.
- Certificate files given by hand are checked every `PINGENV_CERT_RELOAD_INTERVAL`.
  A changed pair is loaded live; one that does not load (a key that does not
  match, a half-written file) is reported in the log and the previous
  certificate stays in use. An expired certificate is not noticed until the
  file changes, so renew before expiry.
- Start with `PINGENV_ACME_STAGING=true` and remove it once issuance works.

## Behaviour worth knowing

- `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` (the client's
  `Host`, port included) and `X-Forwarded-Port` are **overwritten**, not
  appended to. `Forwarded`, `X-Real-IP` and `X-Forwarded-Server` are
  **removed**: pingenv assumes it is the edge. Don't put it behind another
  proxy if your app relies on those.
- Before routing, escapes of letters, digits, `-`, `_` and `~` are decoded, so
  `/%61pi` is `/api` for matching and for the upstream. Other escapes, `%2F`
  and `%2e` included, are left as sent.
- A request that names two different hosts (two `Host` headers, or `Host` and
  `:authority` on HTTP/2) is refused with a 400.
- WebSocket and other `Upgrade` requests over HTTP/1.1 are proxied, and the
  end-to-end test covers a WebSocket handshake with data in both directions.
  WebSockets opened over HTTP/2 (RFC 8441) are not supported. The upstream
  read timeout applies to the handshake; whether it applies to an upgraded
  connection that stays quiet has not been tested.
- There is no limit on connections or request rate, and no overall time limit
  on a request: a client that trickles bytes slowly enough to stay inside the
  60 second read timeout is not cut off. Put a rate limiter or a CDN in front
  if that matters.
- Upstream names are re-resolved every 10 seconds, so a container that returns
  with a new address is picked up.
- A failed upstream connection is retried on the next upstream (twice at
  most). There are no active health checks.
- TLS clients that send an unknown server name, or none, are refused.
- Access logs go to stderr, one line per request, without the query string.
  `upstream=` shows the upstream address, or `memory` / `disk` for files.
- The container runs as an unprivileged user (uid 65532). A bind mount used as
  the data directory has to be writable by it.
- Binding ports 80 and 443 as that user works under Docker's defaults, which
  allow unprivileged binding of low ports inside the container. It may not
  elsewhere (Kubernetes with some runtimes, rootless Podman). If the bind
  fails with "permission denied", listen on high ports and map them:
  `PINGENV_HTTP_ADDR=0.0.0.0:8080`, `PINGENV_HTTPS_ADDR=0.0.0.0:8443`,
  `-p 80:8080 -p 443:8443`, and `PINGENV_HTTPS_REDIRECT_PORT=443`.
- The image has a `HEALTHCHECK`: `pingenv --healthcheck` succeeds if the HTTP
  port accepts connections, using the container's own environment to find it.
  It does not check upstreams; there are no active upstream health checks.
- On Kubernetes, a Service named `pingenv` makes the cluster inject
  `PINGENV_SERVICE_HOST`, `PINGENV_PORT` and similar into pods, which are
  rejected as unknown settings. Set `enableServiceLinks: false` on the pod, or
  give the Service another name.

## Not included

DNS-01 and wildcard issuance, multiple replicas sharing certificates, config
reload without restart (see "Changing the configuration"), active upstream
health checks, rate limiting, response caching, compression, directory
listings, metrics.

## Development

```sh
cargo test                          # unit tests
tests/e2e.sh                        # real binary: routing, files, WebSockets, timeouts,
                                    # certificate reload, self-signed TLS (needs python3, openssl)
tests/e2e.sh --acme <pebble-dir>    # plus a real ACME issuance against Pebble
```

Pingora's rustls backend, used here so the build needs no OpenSSL, is marked
experimental upstream. Building needs `cmake`: Pingora enables a zlib-ng
feature that compiles C code (the Dockerfile installs it).

## License

MIT. Dependencies keep their own licenses; Pingora is Apache-2.0.
