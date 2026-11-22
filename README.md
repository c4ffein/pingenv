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

`pingenv` there is the image built from this repository (`docker build -t
pingenv .`). See [`docker-compose.yml`](docker-compose.yml) for a fuller
example.

Every setting starts with `PINGENV_`. An unknown `PINGENV_*` variable is an
error, so a typo stops the container instead of being silently ignored;
variables without the prefix are never read. A setting that would do nothing
is an error too: the ACME and HTTPS settings while `PINGENV_TLS_MODE` is off
(its default), which is what a forgotten `PINGENV_TLS_MODE=acme` looks like. A
bad configuration prints every problem at once and exits with status 2.

## Routes

A route is a group of variables sharing a name:
`PINGENV_ROUTE_<NAME>_<SETTING>`. Names use `A-Z`, `0-9` and `_`, and only
show up in logs. Each route either proxies to an upstream or serves files.

| `PINGENV_ROUTE_<NAME>_…` | Meaning |
|---|---|
| `HOST` | **Required.** Host names, comma separated. `*.example.com` matches exactly one extra label. |
| `PATH` | Path prefix, default `/`. `/api` matches `/api` and `/api/x`, not `/apix`. |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | PEM certificate chain and key for this route's hosts, instead of ACME. A certificate belongs to a host, not to a route: naming the files on one route is enough for a host that several routes share, and naming different files for the same host is an error. Re-read when the files change (see `PINGENV_CERT_RELOAD_INTERVAL`). |
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
| `MAX_BODY_SIZE` | The largest request body this route accepts, instead of `PINGENV_MAX_BODY_SIZE`: `50MiB` for the one application that takes uploads, say. `0` means no limit. |

### Serving files

| `PINGENV_ROUTE_<NAME>_…` | Meaning |
|---|---|
| `ROOT` | Absolute path of the directory to serve. The route's path prefix maps onto it: with `PATH=/docs`, `/docs/a.css` is `ROOT/a.css`. |
| `MEMORY_MAX_FILE` | Files up to this size are held in memory; larger ones are streamed from disk. Default `0`: everything is served from disk, and the operating system's page cache keeps hot files fast. |
| `MEMORY_PATHS` | With `MEMORY_MAX_FILE` set: which files and directories, below `ROOT`, may be held in memory. Comma separated, like `/index.html,/assets`. Default `/`: everything. |
| `MEMORY_REFRESH` | How long a copy in memory is trusted before the file is checked again; if it changed it is reloaded, and if it is gone or grew past the limit it is dropped. Default `5m`; `0` never checks (a startup snapshot). |
| `FALLBACK` | File served when nothing matches, for single-page apps, e.g. `/index.html`. Only applies to paths whose last segment has no dot, so a missing `/app.js` is still a 404. |
| `CACHE_CONTROL` | `Cache-Control` header for this route. Default `no-cache` (browsers revalidate, and get a cheap 304). |
| `COMPRESS` | `false` sends every file as it is. Default `true`: see "Compression" below. |

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

**Compression happens once per file, never once per request.** Text (HTML,
CSS, JavaScript, JSON, SVG, WebAssembly and the like) is sent compressed to
clients whose `Accept-Encoding` allows it, from one of two places:

- **A precompressed copy next to the file**: `app.js.br` (brotli) or
  `app.js.gz` (gzip) beside `app.js`, made by your build. It is used wherever
  the file is served from, and brotli is preferred when the client reads both.
  A copy older than its file is taken for a leftover of an earlier version and
  ignored; so is one that is not smaller.
- **A gzip copy made at load time**, for files held in memory that have no
  `.gz` next to them. It is kept with the file, replaced when the file is, and
  counted against `PINGENV_MEMORY_MAX_TOTAL` (as are precompressed copies of
  files held in memory). Files under 256 bytes, and files that gzip does not
  shrink by a tenth, get none.

A file served from disk with no precompressed copy is sent as it is: nothing is
compressed while a client waits. So with the defaults (everything on disk),
compression takes either `.br` / `.gz` files in the directory or
`MEMORY_MAX_FILE`. Compressed and plain answers carry different `ETag`s and
`Vary: Accept-Encoding`; a byte range is a range of what is sent. Responses
from upstreams are passed through as they come, compressed or not.

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
- No content negotiation other than the compression above, and no brotli
  made here: that is worth doing at the highest setting, which is a job for a
  build, not for a server starting up.

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
  the ports, unless the swap is made in front of the containers (see
  "Replacing the edge without a gap" below). On `SIGTERM` the listeners close
  at once and the process exits as soon as the requests in flight are done:
  immediately if there are none, and after `PINGENV_SHUTDOWN_GRACE_SECONDS` at
  the latest, which cuts off whatever is still running (a WebSocket, a long
  download). Certificates survive if `PINGENV_DATA_DIR` is a volume.
- **Certificate files** (`TLS_CERT_FILE`) are the exception: they are re-read
  when they change, so renewing them needs no recreate.

### Replacing the edge without a gap

The gap is the time between the old container letting go of ports 80 and 443
and the new one holding them. Docker cannot close it: a published port belongs
to one container for as long as that container exists. A redirect on the host
can, in front of both containers, for the length of the swap:

1. **Start the new configuration as a temporary container:** another name, the
   same networks, volumes and variables, and its ports published on spare host
   ports (Docker only lets traffic from outside reach published ports).
2. **Redirect ports 80 and 443 to it.** With nftables: both ports in one
   transaction, in a table of its own whose chain runs before Docker's, and to
   the container's address rather than to its host ports, which keeps the
   clients' addresses. Connections that are open stay with the old container;
   new ones go to the temporary one.
3. **Stop and remove the old container.** It finishes the requests in flight.
4. **Create the final container,** with the usual name and ports 80 and 443
   published. No traffic reaches it yet: the redirect still wins.
5. **Remove the redirect.** New connections reach the final container through
   Docker's own rule; those on the temporary one stay there.
6. **Stop and remove the temporary container.**

It ends as it began, with one container and no rule of your own, and at every
step a container is serving: if the final one does not start, the temporary
one still is.

pingenv's part in this is what the end-to-end test covers: it finishes the
requests in flight before it exits, and an instance started on a data
directory that already holds the certificates serves them and asks the CA for
nothing. The firewall's part is the host's and is **not tested here**: try it
on a spare port before trusting it with 80 and 443.

Worth knowing:

- **The redirect comes off before the container it points at** (steps 5 and 6,
  in that order). Left behind, pointing at a container that is gone, it is an
  outage: ports 80 and 443 lead nowhere.
- **Long-lived connections are cut twice,** at steps 3 and 6. A WebSocket gets
  `PINGENV_SHUTDOWN_GRACE_SECONDS` each time and then has to reconnect.
- **A host name that is new in this configuration** has no certificate yet,
  and every instance asks for one as it starts. The CA checks over port 80 and
  reaches whichever instance has the port at that moment, but only the one
  that asked knows the answer. A request that fails this way is retried 15
  minutes later, with a self-signed placeholder until then. So do step 2 as
  soon as the temporary container listens, and wait for its `certificate
  issued` line before step 3: it comes at once if the redirect was there in
  time for the CA's check, 15 minutes later if not. The final container then
  finds the certificate in the data directory.
- **The instances share the data directory** during the swap. That is fine for
  the seconds it lasts; it is not a way to run two of them for good (see "Not
  included").
- **IPv6** clients need the same redirect in the `ip6` family, if the host
  names have AAAA records.
- **Without Docker's port publishing** (host networking, or no container at
  all) there is nothing to redirect, and two instances cannot listen on one
  port at once. Start the new one anyway: it waits up to 30 seconds for the
  port and takes it when the old one exits, a gap of a second at most.

## Global settings

| Variable | Default | Meaning |
|---|---|---|
| `PINGENV_TLS_MODE` | `off` | `off`: HTTP only. `acme`: certificates from an ACME CA. `selfsigned`: generated at startup, for local use. `manual`: every host has `TLS_CERT_FILE` and `TLS_KEY_FILE` on one of its routes. In every mode, a host with files uses them. |
| `PINGENV_HTTP_ADDR` | `0.0.0.0:80` | Plain HTTP listener. |
| `PINGENV_HTTPS_ADDR` | `0.0.0.0:443` | HTTPS listener (HTTP/1.1 and HTTP/2), unless TLS is off. |
| `PINGENV_HTTP2` | `true` | `false` stops offering HTTP/2 on the HTTPS listener, so every client speaks HTTP/1.1: the switch to reach for when an HTTP/2 vulnerability is announced and the fix is not out yet. |
| `PINGENV_HTTPS_REDIRECT` | `true` with TLS | Redirect HTTP requests for known hosts to HTTPS (308). |
| `PINGENV_HTTPS_REDIRECT_PORT` | `443` | Port used in the redirect, if HTTPS is published on another one. |
| `PINGENV_DATA_DIR` | `/data` | Where the ACME account and certificates are stored. |
| `PINGENV_ACME_EMAIL` | none | Contact address registered with the CA. |
| `PINGENV_ACME_STAGING` | `false` | Use Let's Encrypt's staging CA (untrusted certificates, generous limits). |
| `PINGENV_ACME_DIRECTORY_URL` | Let's Encrypt | Any other ACME CA. |
| `PINGENV_ACME_CA_FILE` | none | Extra root to trust when talking to the ACME server (private or test CAs). |
| `PINGENV_MEMORY_MAX_TOTAL` | `128MiB` | Cap on file bytes held in memory across all routes, compressed copies included, kept for the life of the process. Exceeding it at startup is an error; a copy that no longer fits when it is refreshed is dropped and served from disk. |
| `PINGENV_MAX_BODY_SIZE` | `1MiB` | The largest request body accepted, on every route that does not set its own `MAX_BODY_SIZE`. A larger one is answered with a 413 and not passed on: before the upstream is asked when the request says how long it is, cut off at the limit when it does not. A WebSocket is not a request body and carries any amount. `0` for no limit. |
| `PINGENV_UPSTREAM_CONNECT_TIMEOUT` | `10s` | Time allowed to open a connection to an upstream. `0` for no limit. |
| `PINGENV_UPSTREAM_READ_TIMEOUT` | `60s` | Time an upstream may stay silent while sending a response. Streaming responses that pause longer need a route-level `READ_TIMEOUT`. |
| `PINGENV_WRITE_TIMEOUT` | `60s` | Time a client, or an upstream, may take to accept data that is being sent to it. |
| `PINGENV_IDLE_TIMEOUT` | `75s` | How long a client connection is kept open with no request on it, HTTP/1.1 keep-alive and HTTP/2 alike. A client cannot ask for longer. Counted in whole seconds; `0` for no limit. |
| `PINGENV_HSTS` | none | `Strict-Transport-Security` value, like `max-age=31536000`, sent on every HTTPS response: from upstreams, from files, and pingenv's own redirects and errors (a 404, a 502 for an upstream that is down). Browsers remember it, so start small. |
| `PINGENV_CERT_RELOAD_INTERVAL` | `60s` | How often `TLS_CERT_FILE` / `TLS_KEY_FILE` are checked for changes. |
| `PINGENV_THREADS` | CPU count | Worker threads. |
| `PINGENV_SHUTDOWN_GRACE_SECONDS` | `5` | The longest that requests in flight get to finish after `SIGTERM`. The process exits as soon as they are done, so this is a limit, not a delay. Keep it under the container runtime's stop timeout (10 seconds in Docker). |
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
- A host that has certificate files is never requested from the CA, on any
  of its routes; the other hosts still are.
- Certificate files given by hand are checked every `PINGENV_CERT_RELOAD_INTERVAL`.
  A changed pair is loaded live; one that does not load (a key that does not
  match, a half-written file) is reported in the log and the previous
  certificate stays in use. An expired certificate is not noticed until the
  file changes, so renew before expiry.
- Start with `PINGENV_ACME_STAGING=true` and remove it once issuance works.

## Behaviour worth knowing

- `X-Forwarded-For`, `X-Real-IP` (both the address of the client that
  connected), `X-Forwarded-Proto`, `X-Forwarded-Host` (the client's `Host`,
  port included) and `X-Forwarded-Port` are **overwritten**, not appended to.
  `Forwarded` and `X-Forwarded-Server` are **removed**: pingenv assumes it is
  the edge. Don't put it behind another proxy if your app relies on those.
  An IPv4 client is always given as an IPv4 address, also on a listener bound
  to `[::]`, where it arrives as `::ffff:192.0.2.1`.
- Before routing, escapes of letters, digits, `-`, `_` and `~` are decoded, so
  `/%61pi` is `/api` for matching and for the upstream. Other escapes, `%2F`
  and `%2e` included, are left as sent.
- A request that names two different hosts (two `Host` headers, or `Host` and
  `:authority` on HTTP/2) is refused with a 400. So is a `Host` that is not a
  host name or address with an optional port: it would otherwise reach the
  access log and `X-Forwarded-Host` as the client wrote it.
- A path may contain UTF-8 that was not escaped; it is forwarded as it came.
- WebSocket and other `Upgrade` requests over HTTP/1.1 are proxied, and the
  end-to-end test covers a WebSocket handshake with data in both directions.
  WebSockets opened over HTTP/2 (RFC 8441) are not supported. The upstream
  read timeout applies to the handshake; whether it applies to an upgraded
  connection that stays quiet has not been tested.
- Clients are held to a few limits. A connection with no request on it is
  closed after `PINGENV_IDLE_TIMEOUT`. A client that goes silent while sending
  a request, or before sending one at all, is dropped after about a minute. One
  that vanished without closing is noticed by TCP keepalive within two
  minutes, also in the middle of a WebSocket. A request body larger than
  `PINGENV_MAX_BODY_SIZE` never reaches an upstream.
- There is still no limit on the number of connections or on the request
  rate, and no overall time limit on a request: a client that trickles bytes
  slowly enough to stay inside the 60 second read timeout is not cut off. Put
  a rate limiter or a CDN in front if that matters.
- Upstream names are re-resolved every 10 seconds, so a container that returns
  with a new address is picked up. One lookup serves all the requests waiting
  on it. A resolver that is slow or failing does not hold up an upstream whose
  address is already known: after half a second the request goes ahead with
  the last address, and the resolver is asked again 10 seconds later. Only a
  name that has never resolved waits for its lookup (5 seconds at most, then a
  502).
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
health checks, rate limiting, response caching, compressing while a client
waits (files on disk without a precompressed copy, responses from upstreams),
directory listings, metrics.

## Development

```sh
cargo test                          # unit tests
tests/e2e.sh                        # real binary: routing, files, compression, WebSockets,
                                    # timeouts, limits, shutdown, certificate reload,
                                    # self-signed TLS
                                    # (needs python3, openssl, curl)
tests/e2e.sh --acme <pebble-dir>    # plus a real ACME issuance against Pebble
```

All three run on every push and pull request
([`ci.yml`](.github/workflows/ci.yml)), which also checks formatting and
clippy, builds with the oldest supported toolchain, and builds the image and
starts it. Pushing a tag `vX.Y.Z` that matches the version in `Cargo.toml`
publishes the image as `ghcr.io/c4ffein/pingenv:X.Y.Z` (also `:X.Y` and
`:latest`) for amd64 and arm64 ([`release.yml`](.github/workflows/release.yml)).

Rust 1.95 or newer (`rust-version` in `Cargo.toml`); the image is built with
the version pinned in the Dockerfile. Pingora's rustls backend, used here so
the build needs no OpenSSL, is marked experimental upstream. Building needs
`cmake`: Pingora enables a zlib-ng feature that compiles C code (the
Dockerfile installs it).

## License

MIT. Dependencies keep their own licenses; Pingora is Apache-2.0.
