#!/usr/bin/env python3
"""What becomes of a connection that a client opens and then leaves alone.

usage: idle_client.py <https-port> <host> <kind> <seconds>   (certificate not verified)

kind is one of:
  h1          two requests on one HTTP/1.1 connection, then silence
  h1-asks     the same, asking for ten minutes with `Keep-Alive: timeout=600`
  h2          an HTTP/2 connection with no request on it

Prints `closed` if the server closed the connection within <seconds> of the
silence starting, `open` if it did not. For h1 that is preceded by `reused`
when the second request was answered on the same connection: the server did
keep it for as long as it was in use.
"""
import socket
import ssl
import sys
import time

port, host, kind, seconds = int(sys.argv[1]), sys.argv[2], sys.argv[3], float(sys.argv[4])

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.set_alpn_protocols(["h2" if kind == "h2" else "http/1.1"])
raw = socket.create_connection(("127.0.0.1", port), timeout=5)
sock = context.wrap_socket(raw, server_hostname=host)


def request():
    asks = b"Connection: keep-alive\r\nKeep-Alive: timeout=600\r\n" if kind == "h1-asks" else b""
    sock.sendall(b"GET /idle HTTP/1.1\r\nHost: " + host.encode() + b"\r\n" + asks + b"\r\n")
    reply = b""
    while b"\r\n\r\n" not in reply:
        chunk = sock.recv(65536)
        if not chunk:
            return False
        reply += chunk
    head, body = reply.split(b"\r\n\r\n", 1)
    length = next(
        int(line.split(b":")[1]) for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")
    )
    while len(body) < length:
        body += sock.recv(65536)
    return head.startswith(b"HTTP/1.1 200")


said = []
if kind == "h2":
    # The connection preface and an empty SETTINGS frame, then an
    # acknowledgement of the server's: an HTTP/2 connection that is fully set
    # up and has nothing on it.
    sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
    sock.sendall(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00")
else:
    first = request()
    time.sleep(0.3)
    said.append("reused" if first and request() else "not-reused")

deadline = time.monotonic() + seconds
state = "open"
while state == "open":
    left = deadline - time.monotonic()
    if left <= 0:
        break
    sock.settimeout(left)
    try:
        if not sock.recv(65536):  # HTTP/2 frames (settings, GOAWAY) may come first
            state = "closed"
    except socket.timeout:
        break
    except OSError:
        state = "closed"
said.append(state)
print(" ".join(said))
