#!/usr/bin/env bash
# End-to-end test: runs the real binary against local upstreams.
#
#   tests/e2e.sh                      routing, redirects, limits, self-signed TLS
#   tests/e2e.sh --acme <pebble-dir>  also issues a certificate from Pebble,
#                                     Let's Encrypt's ACME test server
#
# The ACME part needs a Pebble checkout with both binaries built:
#   go build -o pebble-bin ./cmd/pebble
#   go build -o challtestsrv-bin ./cmd/pebble-challtestsrv
set -euo pipefail
cd "$(dirname "$0")/.."

PEBBLE_DIR=""
[[ "${1:-}" == "--acme" ]] && PEBBLE_DIR="$(cd "$2" && pwd)"

# Everything here is on localhost; an outbound proxy would only get in the way.
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy

cargo build --quiet
BIN="$PWD/target/debug/pingenv"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0
FAIL=0
check() { # check <description> <actual> <expected>
    if [[ "$2" == "$3" ]]; then
        PASS=$((PASS + 1)); echo "  ok    $1"
    else
        FAIL=$((FAIL + 1)); echo "  FAIL  $1: got '$2', expected '$3'"
    fi
}
wait_for_port() {
    for _ in $(seq 100); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.1
    done
    echo "port $1 never opened"; return 1
}
wait_for_exit() {
    for _ in $(seq 100); do kill -0 "$1" 2>/dev/null || return 0; sleep 0.1; done
}
stopped_within() { # stopped_within <pid> <seconds>: SIGTERM, then is it gone in time?
    kill -TERM "$1"
    for _ in $(seq $(($2 * 10))); do kill -0 "$1" 2>/dev/null || { echo yes; return; }; sleep 0.1; done
    echo no
}
make_cert() { # make_cert <dir> <common name> <dns name>: writes cert.tmp and key.tmp there
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
        -keyout "$1/key.tmp" -out "$1/cert.tmp" -subj "/CN=$2" \
        -addext "subjectAltName=DNS:$3" 2>/dev/null
}
install_cert() { mv "$1/key.tmp" "$1/key.pem"; mv "$1/cert.tmp" "$1/cert.pem"; }
fingerprint() { openssl x509 -in "$1" -noout -fingerprint -sha256; }
served_fingerprint() { # served_fingerprint <port> <server name>
    openssl s_client -connect "127.0.0.1:$1" -servername "$2" </dev/null 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256
}
field() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }

HTTP=18080
HTTPS=18443
RESOLVE=()
for name in app.pingenv.test lb.pingenv.test sub.wild.pingenv.test site.pingenv.test live.pingenv.test split.pingenv.test app2.pingenv.test ws.pingenv.test pt.pingenv.test slow.pingenv.test fresh.pingenv.test paths.pingenv.test m.pingenv.test own.pingenv.test gone.pingenv.test up.pingenv.test idle.pingenv.test other.test; do
    RESOLVE+=(--resolve "$name:$HTTP:127.0.0.1" --resolve "$name:$HTTPS:127.0.0.1")
done
get() { curl -sS --max-time 10 "${RESOLVE[@]}" "$@"; }

python3 tests/echo_upstream.py A 18001 & PIDS+=($!)
python3 tests/echo_upstream.py B 18002 & PIDS+=($!)
python3 tests/ws_echo.py 18003 & PIDS+=($!)
wait_for_port 18001; wait_for_port 18002; wait_for_port 18003

echo "== configuration errors"
set +e
OUT="$(env -i PINGENV_ROUTE_A_HOST=a.test PINGENV_ROUTE_B_UPSTREAM=b PINGENV_TLS_MODE=nope "$BIN" 2>&1)"; CODE=$?
set -e
check "invalid configuration exits with 2" "$CODE" 2
check "reports all problems" "$(grep -c '^  - ' <<<"$OUT")" 4
set +e
OUT="$(env -i PINGENV_ROUTE_A_HOST=a.test PINGENV_ROUTE_A_UPSTREAM=a:1 PINGENV_TLS_MOD=acme TLS_MODE=bogus "$BIN" 2>&1)"; CODE=$?
set -e
check "unknown PINGENV_ variable is an error, unprefixed ones are ignored" \
    "$CODE $(grep -c '^  - ' <<<"$OUT") $(grep -c 'PINGENV_TLS_MOD: unknown setting' <<<"$OUT")" "2 1 1"
set +e
OUT="$(env -i PINGENV_ROUTE_A_HOST=a.test PINGENV_ROUTE_A_UPSTREAM=a:1 PINGENV_ACME_EMAIL=ops@a.test "$BIN" 2>&1)"; CODE=$?
set -e
check "ACME settings with no TLS mode stop it, instead of starting plain HTTP" \
    "$CODE $(grep -c 'PINGENV_ACME_EMAIL: does nothing while PINGENV_TLS_MODE is off' <<<"$OUT")" "2 1"

# A site to serve: small files, one file above the in-memory limit, things
# that must never be served, and a symlink pointing out of the root.
SITE="$WORK/site"
mkdir -p "$SITE/css" "$SITE/docs" "$SITE/.git" "$SITE/.well-known" "$SITE/empty"
echo '<h1>home</h1>' >"$SITE/index.html"
echo 'body{}' >"$SITE/css/site.css"
echo '<h1>docs</h1>' >"$SITE/docs/index.html"
echo 'SECRET=1' >"$SITE/.env"
echo 'x' >"$SITE/.git/config"
echo 'Contact: mailto:x@pingenv.test' >"$SITE/.well-known/security.txt"
echo 'outside' >"$WORK/outside.txt"
ln -s "$WORK/outside.txt" "$SITE/escape.txt"
ln -s "$SITE/css/site.css" "$SITE/inside.css"
# Symlinks that stay inside the root but lead to what a path could not name.
ln -s .git "$SITE/repo"
ln -s .env "$SITE/env.txt"
head -c 300000 /dev/urandom >"$SITE/big.bin"
BIG_SUM="$(sha256sum <"$SITE/big.bin")"
# Text that shrinks: one file with nothing next to it, and one with
# precompressed copies (a real gzip, and a stand-in for brotli, which curl
# may not be able to decode: only the bytes and the headers are checked).
for _ in $(seq 400); do echo 'function answer() { return 42; }'; done >"$SITE/auto.js"
cp "$SITE/auto.js" "$SITE/pre.js"
JS_SUM="$(sha256sum <"$SITE/auto.js")"
python3 -c 'import gzip,sys; sys.stdout.buffer.write(gzip.compress(sys.stdin.buffer.read()))' <"$SITE/pre.js" >"$SITE/pre.js.gz"
printf 'brotli-stand-in' >"$SITE/pre.js.br"

# A certificate for a host that two routes share, named on only one of them.
OWN="$WORK/own"; mkdir -p "$OWN"
make_cert "$OWN" own own.pingenv.test; install_cert "$OWN"

echo "== self-signed mode"
env -i \
    PINGENV_HTTP_ADDR=127.0.0.1:$HTTP PINGENV_HTTPS_ADDR=127.0.0.1:$HTTPS PINGENV_HTTPS_REDIRECT_PORT=$HTTPS \
    PINGENV_TLS_MODE=selfsigned PINGENV_HSTS='max-age=31536000' PINGENV_UPSTREAM_READ_TIMEOUT=2s \
    PINGENV_ROUTE_APP_HOST=app.pingenv.test PINGENV_ROUTE_APP_UPSTREAM=127.0.0.1:18001 \
    PINGENV_ROUTE_API_HOST=app.pingenv.test PINGENV_ROUTE_API_PATH=/api PINGENV_ROUTE_API_STRIP_PREFIX=true \
    PINGENV_ROUTE_API_UPSTREAM=localhost:18002 PINGENV_ROUTE_API_SET_HOST=backend.internal \
    PINGENV_ROUTE_LB_HOST=lb.pingenv.test PINGENV_ROUTE_LB_UPSTREAM=127.0.0.1:18001,127.0.0.1:18009,127.0.0.1:18002 \
    PINGENV_ROUTE_SITE_HOST=site.pingenv.test PINGENV_ROUTE_SITE_ROOT="$SITE" \
    PINGENV_ROUTE_SITE_MEMORY_MAX_FILE=64KiB PINGENV_ROUTE_SITE_FALLBACK=/index.html \
    PINGENV_ROUTE_ASSETS_HOST=app.pingenv.test PINGENV_ROUTE_ASSETS_PATH=/static \
    PINGENV_ROUTE_ASSETS_ROOT="$SITE" PINGENV_ROUTE_ASSETS_CACHE_CONTROL='public, max-age=60' \
    PINGENV_ROUTE_LIVE_HOST=live.pingenv.test PINGENV_ROUTE_LIVE_ROOT="$SITE" \
    PINGENV_ROUTE_LIVE_MEMORY_MAX_FILE=0 \
    PINGENV_ROUTE_WS_HOST=ws.pingenv.test PINGENV_ROUTE_WS_UPSTREAM=127.0.0.1:18003 \
    PINGENV_ROUTE_PT_HOST=pt.pingenv.test PINGENV_ROUTE_PT_UPSTREAM=127.0.0.1:18001 PINGENV_ROUTE_PT_ACME_PASSTHROUGH=true \
    PINGENV_ROUTE_SLOW_HOST=slow.pingenv.test PINGENV_ROUTE_SLOW_UPSTREAM=127.0.0.1:18001 PINGENV_ROUTE_SLOW_READ_TIMEOUT=10s \
    PINGENV_ROUTE_FRESH_HOST=fresh.pingenv.test PINGENV_ROUTE_FRESH_ROOT="$SITE" \
    PINGENV_ROUTE_FRESH_MEMORY_MAX_FILE=64KiB PINGENV_ROUTE_FRESH_MEMORY_REFRESH=1s \
    PINGENV_ROUTE_PATHS_HOST=paths.pingenv.test PINGENV_ROUTE_PATHS_ROOT="$SITE" \
    PINGENV_ROUTE_PATHS_MEMORY_MAX_FILE=64KiB PINGENV_ROUTE_PATHS_MEMORY_PATHS=/css \
    PINGENV_ROUTE_SPLIT_HOST=split.pingenv.test PINGENV_ROUTE_SPLIT_UPSTREAM=127.0.0.1:18090 \
    PINGENV_ROUTE_WILD_HOST='*.wild.pingenv.test' PINGENV_ROUTE_WILD_UPSTREAM=127.0.0.1:18001 \
    PINGENV_ROUTE_OWN_HOST=own.pingenv.test PINGENV_ROUTE_OWN_UPSTREAM=127.0.0.1:18001 \
    PINGENV_ROUTE_OWN_TLS_CERT_FILE="$OWN/cert.pem" PINGENV_ROUTE_OWN_TLS_KEY_FILE="$OWN/key.pem" \
    PINGENV_ROUTE_OWN2_HOST=own.pingenv.test PINGENV_ROUTE_OWN2_PATH=/two PINGENV_ROUTE_OWN2_UPSTREAM=127.0.0.1:18002 \
    PINGENV_ROUTE_GONE_HOST=gone.pingenv.test PINGENV_ROUTE_GONE_UPSTREAM=no-such-name.invalid:80 \
    PINGENV_ROUTE_UP_HOST=up.pingenv.test PINGENV_ROUTE_UP_UPSTREAM=127.0.0.1:18001 PINGENV_ROUTE_UP_MAX_BODY_SIZE=3MiB \
    "$BIN" >"$WORK/selfsigned.log" 2>&1 &
GATE=$!; PIDS+=($GATE)
wait_for_port $HTTP; wait_for_port $HTTPS

check "http redirects to https" \
    "$(get -o /dev/null -w '%{http_code} %{redirect_url}' "http://app.pingenv.test:$HTTP/x?y=1")" \
    "308 https://app.pingenv.test:$HTTPS/x?y=1"
check "unknown host is not redirected" \
    "$(get -o /dev/null -w '%{http_code}' "http://other.test:$HTTP/")" 404
check "unknown acme challenge is a 404, not a redirect" \
    "$(get -o /dev/null -w '%{http_code}' "http://app.pingenv.test:$HTTP/.well-known/acme-challenge/nope")" 404
check "unknown SNI fails the handshake" \
    "$(get -k -o /dev/null -w '%{http_code}' "https://other.test:$HTTPS/" 2>/dev/null || true)" 000

BODY="$(get -k -H 'X-Forwarded-For: 6.6.6.6' -H 'X-Real-IP: 6.6.6.6' -H 'Forwarded: for=6.6.6.6' -H 'X-Forwarded-Port: 1' "https://app.pingenv.test:$HTTPS/hello?q=1")"
check "routes to upstream A" "$(field 'd["upstream"]' <<<"$BODY")" A
check "path and query are kept" "$(field 'd["path"]' <<<"$BODY")" "/hello?q=1"
check "client Host is kept" "$(field 'd["headers"]["host"]' <<<"$BODY")" "app.pingenv.test:$HTTPS"
check "X-Forwarded-Proto" "$(field 'd["headers"]["x-forwarded-proto"]' <<<"$BODY")" https
check "spoofed X-Forwarded-For is replaced" "$(field 'd["headers"]["x-forwarded-for"]' <<<"$BODY")" 127.0.0.1
check "X-Forwarded-Host keeps the port" "$(field 'd["headers"]["x-forwarded-host"]' <<<"$BODY")" "app.pingenv.test:$HTTPS"
check "X-Forwarded-Port is what the client used" "$(field 'd["headers"]["x-forwarded-port"]' <<<"$BODY")" "$HTTPS"
check "spoofed X-Real-IP is replaced too" "$(field 'd["headers"]["x-real-ip"]' <<<"$BODY")" 127.0.0.1
check "spoofed Forwarded is dropped" "$(field 'd["headers"].get("forwarded", "-")' <<<"$BODY")" "-"
check "HSTS on proxied HTTPS responses" \
    "$(get -k -o /dev/null -D - "https://app.pingenv.test:$HTTPS/" | tr -d '\r' | awk -F': ' 'tolower($1)=="strict-transport-security"{print $2}')" "max-age=31536000"
check "no HSTS on the plain HTTP redirect" \
    "$(get -o /dev/null -D - "http://app.pingenv.test:$HTTP/" | grep -ci strict-transport || true)" 0
check "a Host that is not a host is refused" \
    "$(get -o /dev/null -w '%{http_code}' -H 'Host: app.pingenv.test 200 route=admin' "http://app.pingenv.test:$HTTP/")" 400
check "and never reaches the access log" \
    "$(sleep 0.2; grep -c 'route=admin' "$WORK/selfsigned.log" || true)" 0
check "HSTS when no route matches" \
    "$(get -k -o /dev/null -D - -H 'Host: nope.test' "https://app.pingenv.test:$HTTPS/" | tr -d '\r' | awk -F': ' 'tolower($1)=="strict-transport-security"{print $2}')" "max-age=31536000"
check "a certificate named on one route serves the host on all of them" \
    "$([[ "$(served_fingerprint $HTTPS own.pingenv.test)" == "$(fingerprint "$OWN/cert.pem")" ]] && echo same || echo different)" same
check "and the other route still routes" \
    "$(get -k "https://own.pingenv.test:$HTTPS/two" | field 'd["upstream"]')" B
check "absolute-form target that disagrees with Host is refused" \
    "$(get -k -o /dev/null -w '%{http_code}' --http1.1 --request-target "http://app.pingenv.test:$HTTPS/x" -H 'Host: admin.internal' "https://app.pingenv.test:$HTTPS/")" 400

check "negotiates HTTP/2" \
    "$(get -k --http2 -o /dev/null -w '%{http_version}' "https://app.pingenv.test:$HTTPS/")" 2
BODY="$(get -k --http2 "https://app.pingenv.test:$HTTPS/h2")"
check "HTTP/2 request reaches upstream with a Host" \
    "$(field 'd["headers"]["host"]' <<<"$BODY")" "app.pingenv.test:$HTTPS"

BODY="$(get -k "https://app.pingenv.test:$HTTPS/api/users?id=7")"
check "longest path prefix wins" "$(field 'd["upstream"]' <<<"$BODY")" B
check "prefix is stripped" "$(field 'd["path"]' <<<"$BODY")" "/users?id=7"
check "SET_HOST overrides Host" "$(field 'd["headers"]["host"]' <<<"$BODY")" backend.internal
check "an escaped letter still matches its route" \
    "$(get -k --path-as-is "https://app.pingenv.test:$HTTPS/%61pi/users?id=7" | field 'd["upstream"] + d["path"]')" "B/users?id=7"
check "unescaped UTF-8 in a path is forwarded as it came" \
    "$(python3 tests/raw_get.py $HTTPS "app.pingenv.test:$HTTPS" '/%61pi/café' | field 'd["path"].encode("latin-1").decode()')" "/café"
check "/apix does not match /api" \
    "$(get -k "https://app.pingenv.test:$HTTPS/apix" | field 'd["upstream"]')" A

SEEN=""
for _ in 1 2 3 4 5 6; do
    SEEN+="$(get -k "https://lb.pingenv.test:$HTTPS/" | field 'd["upstream"]')"
done
check "round robin skips the dead upstream" "$(grep -o . <<<"$SEEN" | sort -u | tr -d '\n') ${#SEEN}" "AB 6"
check "wildcard host" \
    "$(get -k "https://sub.wild.pingenv.test:$HTTPS/" | field 'd["upstream"]')" A
check "upstream read timeout gives a gateway error, with HSTS like any other response" \
    "$(get -k -o /dev/null -D - -w '%{http_code}' "https://app.pingenv.test:$HTTPS/sleep/5" | tr -d '\r' | awk -F': ' 'tolower($1)=="strict-transport-security"{printf "%s ", $2} END{print $0}')" "max-age=31536000 502"
check "an upstream whose name does not resolve is a gateway error too, and is named in the log" \
    "$(get -k -o /dev/null -w '%{http_code}' "https://gone.pingenv.test:$HTTPS/") $(sleep 0.2; grep -c 'gone.pingenv.test/ 502 route=gone upstream=no-such-name.invalid:80' "$WORK/selfsigned.log")" "502 1"
check "a route can raise its own read timeout" \
    "$(get -k -o /dev/null -w '%{http_code}' "https://slow.pingenv.test:$HTTPS/sleep/3")" 200
check "acme challenge without a token is not forwarded by default" \
    "$(get -o /dev/null -w '%{http_code}' "http://app.pingenv.test:$HTTP/.well-known/acme-challenge/x")" 404
check "with ACME_PASSTHROUGH it reaches the upstream, with no redirect" \
    "$(get "http://pt.pingenv.test:$HTTP/.well-known/acme-challenge/tok" | field 'd["upstream"] + d["path"]')" "A/.well-known/acme-challenge/tok"
check "other paths on that route are still redirected" \
    "$(get -o /dev/null -w '%{http_code}' "http://pt.pingenv.test:$HTTP/other")" 308
check "access log has one line per request" \
    "$(grep -c 'route=api upstream=localhost:18002' "$WORK/selfsigned.log")" 3

echo "== request body limit"
head -c $((512 * 1024)) /dev/zero >"$WORK/half.bin"
head -c $((2 * 1024 * 1024)) /dev/zero >"$WORK/two.bin"
head -c $((4 * 1024 * 1024)) /dev/zero >"$WORK/four.bin"
# `Expect:` makes curl send the body at once instead of asking first, which
# is what a browser does: the answer has to reach a client that is mid-upload.
post() { get -k -H 'Expect:' "${@:2}" --data-binary @"$WORK/$1.bin"; }
U="https://app.pingenv.test:$HTTPS/upload"
check "a body within the limit reaches the upstream whole" "$(post half "$U" | field 'd["body_bytes"]')" 524288
check "a body over the default limit is refused" "$(post two -o /dev/null -w '%{http_code}' "$U")" 413
check "and the upstream is never asked" \
    "$(sleep 0.2; grep -c 'POST app.pingenv.test/upload 413 route=app upstream=- ' "$WORK/selfsigned.log")" 1
check "a body that does not say how long it is gets counted, and refused once over" \
    "$(post two -o /dev/null -w '%{http_code}' -H 'Transfer-Encoding: chunked' "$U") $(post half -H 'Transfer-Encoding: chunked' "$U" | field 'd["body_bytes"]')" "413 524288"
check "the same over HTTP/2, with a length and without" \
    "$(post two -o /dev/null -w '%{http_code}' --http2 "$U") $(get -k -o /dev/null -w '%{http_code}' --http2 -X POST -T - "$U" <"$WORK/two.bin")" "413 413"
check "a body over the limit is not reported as an error of the proxy's" \
    "$(grep -c 'ERROR.*over the limit' "$WORK/selfsigned.log" || true)" 0
check "a route can raise the limit for itself" \
    "$(post two "https://up.pingenv.test:$HTTPS/" | field 'd["body_bytes"]') $(post four -o /dev/null -w '%{http_code}' "https://up.pingenv.test:$HTTPS/")" "2097152 413"

echo "== static files"
S="https://site.pingenv.test:$HTTPS"
code() { get -k -o /dev/null -w '%{http_code}' "$@"; }
hdr() { get -k -o /dev/null -D - "${@:2}" | tr -d '\r' | awk -F': ' -v h="$1" 'tolower($1)==tolower(h){print $2}'; }
src() { sleep 0.2; grep "$1 " "$WORK/selfsigned.log" | tail -1 | grep -o 'upstream=[a-z-]*'; }

check "serves the index for /" "$(get -k "$S/")" '<h1>home</h1>'
check "content type" "$(hdr content-type "$S/css/site.css")" 'text/css; charset=utf-8'
check "small file comes from memory" "$(src 'site.pingenv.test/css/site.css')" upstream=memory
check "default Cache-Control" "$(hdr cache-control "$S/css/site.css")" no-cache
check "large file is intact" "$(get -k "$S/big.bin" | sha256sum)" "$BIG_SUM"
check "large file is streamed from disk" "$(src 'site.pingenv.test/big.bin')" upstream=disk
check "large file over HTTP/2 is intact" "$(get -k --http2 "$S/big.bin" | sha256sum)" "$BIG_SUM"
check "HEAD has a length and no body" \
    "$(get -k -I "$S/big.bin" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-length"{print $2}') $(get -k -I -o /dev/null -w '%{size_download}' "$S/big.bin")" "300000 0"

check "range on a disk file" \
    "$(get -k -r 100000-100099 "$S/big.bin" | sha256sum)" "$(tail -c +100001 "$SITE/big.bin" | head -c 100 | sha256sum)"
check "range status and Content-Range" \
    "$(code -r 100000-100099 "$S/big.bin") $(hdr content-range -r 100000-100099 "$S/big.bin")" "206 bytes 100000-100099/300000"
check "suffix range on a memory file" "$(get -k -r -3 "$S/css/site.css")" "{}"
check "range past the end is 416" "$(code -r 999999- "$S/big.bin")" 416

ETAG="$(hdr etag "$S/css/site.css")"
check "If-None-Match gives 304" "$(code -H "If-None-Match: $ETAG" "$S/css/site.css")" 304
check "If-None-Match with another tag gives 200" "$(code -H 'If-None-Match: "nope"' "$S/css/site.css")" 200
check "If-Modified-Since gives 304" \
    "$(code -H "If-Modified-Since: $(hdr last-modified "$S/big.bin")" "$S/big.bin")" 304
check "If-Range with a stale tag sends the whole file" \
    "$(code -r 0-9 -H 'If-Range: "stale"' "$S/big.bin")" 200

check "directory without slash redirects" \
    "$(get -k -o /dev/null -w '%{http_code} %{redirect_url}' "$S/docs?x=1")" "308 $S/docs/?x=1"
check "directory index" "$(get -k "$S/docs/")" '<h1>docs</h1>'
check "redirect target cannot become another host" \
    "$(get -k --path-as-is -o /dev/null -w '%{http_code} %{redirect_url}' "$S//docs")" "308 $S/docs/"
check "HSTS on files" "$(hdr strict-transport-security "$S/css/site.css")" "max-age=31536000"
check "HSTS on the file server's own answers: 404, redirect, 405, 416" \
    "$(hdr strict-transport-security "$S/missing.js") $(hdr strict-transport-security "$S/docs") $(hdr strict-transport-security -X POST "$S/") $(hdr strict-transport-security -r 999999- "$S/big.bin")" \
    "max-age=31536000 max-age=31536000 max-age=31536000 max-age=31536000"
check "directory without index is not listed" "$(code "https://live.pingenv.test:$HTTPS/empty/")" 404
check "dotfile is refused" "$(code "$S/.env")" 404
check "dot directory is refused" "$(code "$S/.git/config")" 404
check ".well-known is served" "$(code "$S/.well-known/security.txt")" 200
check "traversal is refused" "$(code --path-as-is "$S/css/../../outside.txt")" 404
check "encoded traversal is refused" "$(code --path-as-is "$S/%2e%2e/outside.txt")" 404
check "encoded slash traversal is refused" "$(code --path-as-is "$S/css%2f..%2f..%2foutside.txt")" 404
check "symlink out of the root is refused" "$(code "$S/escape.txt")" 404
check "symlink to a hidden directory is refused" "$(code "https://live.pingenv.test:$HTTPS/repo/config")" 404
check "symlink to a hidden file is refused" "$(code "$S/env.txt")" 404
check "symlink inside the root is served" "$(get -k "$S/inside.css")" 'body{}'
check "fallback for application routes" "$(get -k "$S/users/42")" '<h1>home</h1>'
check "no fallback for missing assets" "$(code "$S/missing.js")" 404
check "POST is refused" "$(code -X POST "$S/")" 405

echo "== compression"
L="https://live.pingenv.test:$HTTPS"
size() { get -k -o /dev/null -w '%{size_download}' "$@"; }
PLAIN_SIZE="$(size "$S/auto.js")"
check "a file held in memory is sent gzipped to a client that asks" \
    "$(hdr content-encoding -H 'Accept-Encoding: gzip' "$S/auto.js") $(get -k --compressed "$S/auto.js" | sha256sum)" "gzip $JS_SUM"
check "and is much smaller on the wire" \
    "$(( $(size -H 'Accept-Encoding: gzip' "$S/auto.js") * 10 < PLAIN_SIZE )) $(src 'site.pingenv.test/auto.js')" "1 upstream=memory"
check "a client that does not ask gets the file as it is" \
    "$(hdr content-encoding "$S/auto.js")|$(get -k "$S/auto.js" | sha256sum)" "|$JS_SUM"
check "both answers say they depend on Accept-Encoding" \
    "$(hdr vary "$S/auto.js") / $(hdr vary -H 'Accept-Encoding: gzip' "$S/auto.js")" "Accept-Encoding / Accept-Encoding"
check "the type is the file's, not the coding's" \
    "$(hdr content-type -H 'Accept-Encoding: gzip' "$S/auto.js")" 'text/javascript; charset=utf-8'
GZ_TAG="$(hdr etag -H 'Accept-Encoding: gzip' "$S/auto.js")"
check "the compressed copy has its own ETag" \
    "$([[ -n "$GZ_TAG" && "$GZ_TAG" != "$(hdr etag "$S/auto.js")" ]] && echo distinct || echo same)" distinct
check "which revalidates to a 304" \
    "$(code -H 'Accept-Encoding: gzip' -H "If-None-Match: $GZ_TAG" "$S/auto.js") $(code -H "If-None-Match: $GZ_TAG" "$S/auto.js")" "304 200"
check "q=0 refuses a coding" "$(hdr content-encoding -H 'Accept-Encoding: gzip;q=0' "$S/auto.js")" ""
check "what does not shrink is left alone" \
    "$(hdr content-encoding -H 'Accept-Encoding: gzip, br' "$S/big.bin")|$(hdr vary -H 'Accept-Encoding: gzip, br' "$S/big.bin")" "|"
check "a file on disk with no copy next to it is not compressed" \
    "$(hdr content-encoding -H 'Accept-Encoding: gzip, br' "$L/auto.js")|$(get -k --compressed "$L/auto.js" | sha256sum)" "|$JS_SUM"
check "a precompressed copy next to a file on disk is sent in its place" \
    "$(hdr content-encoding -H 'Accept-Encoding: gzip' "$L/pre.js") $(get -k --compressed -H 'Accept-Encoding: gzip' "$L/pre.js" | sha256sum) $(src 'live.pingenv.test/pre.js')" "gzip $JS_SUM upstream=disk"
check "brotli is preferred when the client reads both" \
    "$(hdr content-encoding -H 'Accept-Encoding: gzip, br' "$L/pre.js") $(get -k -H 'Accept-Encoding: gzip, br' "$L/pre.js")" "br brotli-stand-in"
check "the same copies are used for a file held in memory" \
    "$(hdr content-encoding -H 'Accept-Encoding: gzip, br' "$S/pre.js") $(get -k -H 'Accept-Encoding: br' "$S/pre.js") $(src 'site.pingenv.test/pre.js')" "br brotli-stand-in upstream=memory"
check "a range is a range of what is sent" \
    "$(code -r 0-4 -H 'Accept-Encoding: br' "$L/pre.js") $(get -k -r 0-4 -H 'Accept-Encoding: br' "$L/pre.js") $(hdr content-range -r 0-4 -H 'Accept-Encoding: br' "$L/pre.js")" "206 brotl bytes 0-4/15"
check "HEAD reports the compressed length" \
    "$(get -k -I -H 'Accept-Encoding: br' "$L/pre.js" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-length"{print $2}')" 15

A="https://app.pingenv.test:$HTTPS/static"
check "files under a path prefix" "$(get -k "$A/css/site.css")" 'body{}'
check "prefix root serves the index" "$(get -k "$A/")" '<h1>home</h1>'
check "prefix without slash redirects" \
    "$(get -k -o /dev/null -w '%{http_code} %{redirect_url}' "$A")" "308 $A/"
check "custom Cache-Control" "$(hdr cache-control "$A/css/site.css")" 'public, max-age=60'
check "no fallback unless configured" "$(code "$A/users/42")" 404
check "other paths still reach the upstream" \
    "$(get -k "https://app.pingenv.test:$HTTPS/statics" | field 'd["upstream"]')" A

check "limit 0 serves small files from disk" "$(get -k "$L/css/site.css") $(src 'live.pingenv.test/css/site.css')" 'body{} upstream=disk'
echo 'body{color:red}' >"$SITE/css/site.css"
echo 'new' >"$SITE/new.txt"
check "memory copy is a startup snapshot" "$(get -k "$S/css/site.css")" 'body{}'
check "disk route sees the change" "$(get -k "$L/css/site.css")" 'body{color:red}'
check "files added later are served from disk" "$(get -k "$S/new.txt") $(src 'site.pingenv.test/new.txt')" 'new upstream=disk'
sleep 2.5
check "a short refresh window picks the change up" "$(get -k "https://fresh.pingenv.test:$HTTPS/css/site.css")" 'body{color:red}'
check "and the file is still served from memory" "$(src 'fresh.pingenv.test/css/site.css')" upstream=memory
check "the default window keeps the old copy" "$(get -k "$S/css/site.css")" 'body{}'
PA="https://paths.pingenv.test:$HTTPS"
check "MEMORY_PATHS: a chosen directory is in memory" "$(get -k "$PA/css/site.css" >/dev/null; src 'paths.pingenv.test/css/site.css')" upstream=memory
check "MEMORY_PATHS: the rest is on disk" "$(get -k "$PA/docs/index.html" >/dev/null; src 'paths.pingenv.test/docs/index.html')" upstream=disk

echo "== websocket"
check "upgrade is proxied and bytes flow both ways" \
    "$(python3 tests/ws_client.py $HTTPS ws.pingenv.test)" \
    "HTTP/1.1 101 Switching Protocols | accept=ok | echo=hello through the proxy"
check "and is not held to the request body limit: it is not a request body" \
    "$(python3 tests/ws_client.py $HTTPS ws.pingenv.test 3145728)" \
    "HTTP/1.1 101 Switching Protocols | accept=ok | echo=hello through the proxy | carried=3145728"

echo "== idle connections"
# The gateway above has the default limit, far longer than this looks for.
check "an idle connection is kept for the next request" \
    "$(python3 tests/idle_client.py $HTTPS app.pingenv.test h1 2)" "reused open"
env -i PINGENV_HTTP_ADDR=127.0.0.1:18082 PINGENV_HTTPS_ADDR=127.0.0.1:18445 PINGENV_TLS_MODE=selfsigned \
    PINGENV_IDLE_TIMEOUT=1s \
    PINGENV_ROUTE_IDLE_HOST=idle.pingenv.test PINGENV_ROUTE_IDLE_UPSTREAM=127.0.0.1:18001 \
    "$BIN" >"$WORK/idle.log" 2>&1 &
IDLE=$!; PIDS+=($IDLE)
wait_for_port 18445
check "but not for longer than the idle timeout" \
    "$(python3 tests/idle_client.py 18445 idle.pingenv.test h1 4)" "reused closed"
check "however long the client asks for" \
    "$(python3 tests/idle_client.py 18445 idle.pingenv.test h1-asks 4)" "reused closed"
check "an idle HTTP/2 connection is closed as well" \
    "$(python3 tests/idle_client.py 18445 idle.pingenv.test h2 4)" "closed"
kill -TERM $IDLE; wait_for_exit $IDLE

echo "== split layout: one pingenv as the edge, another as the file server"
env -i PINGENV_HTTP_ADDR=127.0.0.1:18090 \
    PINGENV_ROUTE_FILES_HOST=split.pingenv.test PINGENV_ROUTE_FILES_ROOT="$SITE" \
    PINGENV_ROUTE_FILES_MEMORY_MAX_FILE=1MiB \
    "$BIN" >"$WORK/inner.log" 2>&1 &
INNER=$!; PIDS+=($INNER)
wait_for_port 18090
P="https://split.pingenv.test:$HTTPS"
check "file served through both" "$(get -k "$P/docs/")" '<h1>docs</h1>'
check "edge proxied it, file server answered from memory" \
    "$(src 'split.pingenv.test/docs/') $(sleep 0.2; grep -c 'split.pingenv.test/docs/ 200 route=files upstream=memory' "$WORK/inner.log")" \
    "upstream= 1"
check "large file through both is intact" "$(get -k "$P/big.bin" | sha256sum)" "$BIG_SUM"
check "range through both" "$(code -r 0-99 "$P/big.bin") $(hdr content-range -r 0-99 "$P/big.bin")" "206 bytes 0-99/300000"
check "304 through both" "$(code -H "If-None-Match: $(hdr etag "$P/big.bin")" "$P/big.bin")" 304
check "compressed through both: the edge passes it on untouched" \
    "$(hdr content-encoding -H 'Accept-Encoding: gzip' "$P/auto.js") $(get -k --compressed "$P/auto.js" | sha256sum)" "gzip $JS_SUM"
check "an idle server exits at once on SIGTERM, not after the grace period" "$(stopped_within $INNER 2)" yes
check "file server down gives 502 on its route" "$(code "$P/docs/")" 502
check "other routes are unaffected" "$(get -k "https://app.pingenv.test:$HTTPS/" | field 'd["upstream"]')" A

HEALTH=(env -i PINGENV_HTTP_ADDR=127.0.0.1:$HTTP PINGENV_ROUTE_A_HOST=a.test PINGENV_ROUTE_A_UPSTREAM=a:1 "$BIN" --healthcheck)
set +e; "${HEALTH[@]}" 2>/dev/null; HEALTHY=$?; set -e
check "--healthcheck succeeds while the server listens" "$HEALTHY" 0
# A request that takes two seconds, and SIGTERM half a second into it.
get -k -o /dev/null -w '%{http_code}' "https://slow.pingenv.test:$HTTPS/sleep/2" >"$WORK/inflight.out" &
INFLIGHT=$!
sleep 0.5
kill -TERM $GATE
sleep 1
check "SIGTERM waits for a request in flight" "$(kill -0 $GATE 2>/dev/null && echo running || echo stopped)" running
wait $INFLIGHT || true
check "which is answered in full" "$(cat "$WORK/inflight.out")" 200
sleep 1
check "and the server exits when it is done, without sitting out the grace period" \
    "$(kill -0 $GATE 2>/dev/null && echo running || echo stopped)" stopped
wait_for_exit $GATE
set +e; "${HEALTH[@]}" 2>/dev/null; DOWN=$?; set -e
check "--healthcheck fails once it stopped" "$DOWN" 1

set +e
OUT="$(env -i PINGENV_ROUTE_S_HOST=s.test PINGENV_ROUTE_S_ROOT="$SITE" PINGENV_ROUTE_S_MEMORY_MAX_FILE=1MiB PINGENV_MEMORY_MAX_TOTAL=10 \
    PINGENV_HTTP_ADDR=127.0.0.1:$HTTP "$BIN" 2>&1)"; CODE=$?
set -e
check "exceeding the memory cap fails at startup" \
    "$CODE $(grep -c 'exceed PINGENV_MEMORY_MAX_TOTAL' <<<"$OUT")" "1 1"

echo "== manual certificates are reloaded when the files change"
CERTDIR="$WORK/manual"; mkdir -p "$CERTDIR"
make_cert "$CERTDIR" first m.pingenv.test; install_cert "$CERTDIR"
env -i PINGENV_HTTP_ADDR=127.0.0.1:18081 PINGENV_HTTPS_ADDR=127.0.0.1:18444 PINGENV_TLS_MODE=manual \
    PINGENV_HTTPS_REDIRECT=false PINGENV_CERT_RELOAD_INTERVAL=1s PINGENV_HTTP2=false \
    PINGENV_ROUTE_M_HOST=m.pingenv.test PINGENV_ROUTE_M_UPSTREAM=127.0.0.1:18001 \
    PINGENV_ROUTE_M_TLS_CERT_FILE="$CERTDIR/cert.pem" PINGENV_ROUTE_M_TLS_KEY_FILE="$CERTDIR/key.pem" \
    PINGENV_ROUTE_M2_HOST=m.pingenv.test PINGENV_ROUTE_M2_PATH=/two PINGENV_ROUTE_M2_UPSTREAM=127.0.0.1:18002 \
    "$BIN" >"$WORK/manual.log" 2>&1 &
MANUAL=$!; PIDS+=($MANUAL)
wait_for_port 18444
BEFORE="$(served_fingerprint 18444 m.pingenv.test)"
check "the certificate from the files is served" \
    "$([[ "$BEFORE" == "$(fingerprint "$CERTDIR/cert.pem")" ]] && echo same || echo different)" same
check "a second route for the host needs no files of its own" \
    "$(curl -sS --max-time 10 -k --resolve m.pingenv.test:18444:127.0.0.1 "https://m.pingenv.test:18444/two" | field 'd["upstream"]')" B
check "with PINGENV_HTTP2=false a client that offers HTTP/2 gets HTTP/1.1" \
    "$(curl -sS --max-time 10 -k --http2 -o /dev/null -w '%{http_version}' --resolve m.pingenv.test:18444:127.0.0.1 "https://m.pingenv.test:18444/")" 1.1
make_cert "$CERTDIR" second-with-a-longer-name m.pingenv.test; install_cert "$CERTDIR"
AFTER="$BEFORE"
for _ in $(seq 50); do AFTER="$(served_fingerprint 18444 m.pingenv.test)"; [[ "$AFTER" != "$BEFORE" ]] && break; sleep 0.2; done
check "a renewed certificate is served without a restart" \
    "$([[ "$AFTER" == "$(fingerprint "$CERTDIR/cert.pem")" ]] && echo same || echo different)" same
echo "not a certificate" >"$CERTDIR/cert.pem"
sleep 3
check "a broken replacement keeps the previous certificate" "$(served_fingerprint 18444 m.pingenv.test)" "$AFTER"
check "and says so" "$(grep -c 'keeping the previous certificate' "$WORK/manual.log" || true)" 1
kill -TERM $MANUAL; wait_for_exit $MANUAL

if [[ -n "$PEBBLE_DIR" ]]; then
    echo "== acme mode (Pebble)"
    MINICA="$PEBBLE_DIR/test/certs/pebble.minica.pem"
    # Mock DNS: every name resolves to 127.0.0.1, so Pebble validates us.
    "$PEBBLE_DIR/challtestsrv-bin" -defaultIPv4 127.0.0.1 -defaultIPv6 "" \
        -http01 "" -https01 "" -tlsalpn01 "" -doh "" >"$WORK/dns.log" 2>&1 &
    PIDS+=($!)
    (cd "$PEBBLE_DIR" && PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 \
        exec ./pebble-bin -config test/config/pebble-config.json -dnsserver 127.0.0.1:8053 \
        >"$WORK/pebble.log" 2>&1) &
    PIDS+=($!)
    wait_for_port 14000; wait_for_port 15000

    start_acme() {
        # Pebble validates on port 5002 (httpPort in its config).
        env -i PINGENV_HTTP_ADDR=127.0.0.1:5002 PINGENV_HTTPS_ADDR=127.0.0.1:$HTTPS PINGENV_HTTPS_REDIRECT=false \
            PINGENV_TLS_MODE=acme PINGENV_ACME_DIRECTORY_URL=https://localhost:14000/dir \
            PINGENV_ACME_CA_FILE="$MINICA" PINGENV_ACME_EMAIL=ops@pingenv.test PINGENV_DATA_DIR="$WORK/data" \
            PINGENV_ROUTE_APP_HOST=app.pingenv.test PINGENV_ROUTE_APP_UPSTREAM=127.0.0.1:18001 \
            PINGENV_ROUTE_APP2_HOST=app2.pingenv.test PINGENV_ROUTE_APP2_UPSTREAM=127.0.0.1:18001 \
            PINGENV_ROUTE_OWN_HOST=own.pingenv.test PINGENV_ROUTE_OWN_UPSTREAM=127.0.0.1:18001 \
            PINGENV_ROUTE_OWN_TLS_CERT_FILE="$OWN/cert.pem" PINGENV_ROUTE_OWN_TLS_KEY_FILE="$OWN/key.pem" \
            PINGENV_ROUTE_OWN2_HOST=own.pingenv.test PINGENV_ROUTE_OWN2_PATH=/two PINGENV_ROUTE_OWN2_UPSTREAM=127.0.0.1:18002 \
            "$BIN" >"$1" 2>&1 &
        GATE=$!; PIDS+=($GATE)
        wait_for_port $HTTPS
    }
    start_acme "$WORK/acme1.log"
    check "answers HTTPS while the certificate is still pending" \
        "$(get -k -o /dev/null -w '%{http_code}' "https://app.pingenv.test:$HTTPS/")" 200

    CERT="$WORK/data/acme/localhost_14000/certs/app.pingenv.test/fullchain.pem"
    for _ in $(seq 300); do [[ "$(grep -c 'certificate issued' "$WORK/acme1.log")" == 2 ]] && break; sleep 0.1; done
    check "certificate is issued" "$(grep -c 'app.pingenv.test: certificate issued' "$WORK/acme1.log")" 1
    check "two hosts each get their own certificate" \
        "$(grep -c 'requesting certificate' "$WORK/acme1.log") $(grep -c 'app2.pingenv.test: certificate issued' "$WORK/acme1.log")" "2 1"
    check "certificate is stored" "$([[ -s "$CERT" ]] && echo yes || echo no)" yes
    # own.pingenv.test is on two routes and only one names its files.
    check "a host with certificate files is not requested from the CA, on any of its routes" \
        "$(grep -c 'own.pingenv.test: requesting' "$WORK/acme1.log" || true)" 0
    check "and its files are what is served" \
        "$([[ "$(served_fingerprint $HTTPS own.pingenv.test)" == "$(fingerprint "$OWN/cert.pem")" ]] && echo same || echo different)" same
    check "private key is owner-only" "$(stat -c %a "$(dirname "$CERT")/privkey.pem")" 600

    curl -sS --cacert "$MINICA" https://localhost:15000/roots/0 >"$WORK/root.pem"
    # No -k: this only passes if the issued certificate was swapped in live.
    check "issued certificate is served and verifies against the CA root" \
        "$(get --cacert "$WORK/root.pem" -o /dev/null -w '%{http_code}' "https://app.pingenv.test:$HTTPS/")" 200

    kill -TERM $GATE
    wait_for_exit $GATE
    start_acme "$WORK/acme2.log"
    check "restart reuses the stored certificate" \
        "$(get --cacert "$WORK/root.pem" -o /dev/null -w '%{http_code}' "https://app.pingenv.test:$HTTPS/")" 200
    sleep 2
    check "restart does not request a new certificate" \
        "$(grep -c 'requesting certificate' "$WORK/acme2.log" || true)" 0
fi

echo
echo "$PASS passed, $FAIL failed"
if [[ $FAIL -gt 0 ]]; then
    for log in "$WORK"/*.log; do echo "--- $log"; tail -20 "$log"; done
    exit 1
fi
