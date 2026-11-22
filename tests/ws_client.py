#!/usr/bin/env python3
"""Opens a WebSocket through the proxy and checks that bytes flow both ways.

usage: ws_client.py <connect-port> <host-header> [bytes]   (HTTPS, certificate not verified)

With [bytes], that much more is sent afterwards and has to come back: a
connection that has been upgraded carries any amount, for as long as it lives.
"""
import base64
import hashlib
import os
import socket
import ssl
import sys

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
port, host = int(sys.argv[1]), sys.argv[2]

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
raw = socket.create_connection(("127.0.0.1", port), timeout=5)
sock = context.wrap_socket(raw, server_hostname=host)

key = base64.b64encode(os.urandom(16))
sock.sendall(
    b"GET /chat HTTP/1.1\r\nHost: " + host.encode() + b"\r\nUpgrade: websocket\r\n"
    b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + b"\r\n\r\n"
)
reply = b""
while b"\r\n\r\n" not in reply:
    chunk = sock.recv(4096)
    if not chunk:
        break
    reply += chunk
status = reply.split(b"\r\n")[0].decode()
accept = base64.b64encode(hashlib.sha1(key + GUID).digest())
good = accept in reply
sock.sendall(b"hello through the proxy")
echoed = sock.recv(4096).decode(errors="replace")
carried = ""
if len(sys.argv) > 3:
    # One piece at a time, each read back before the next is sent.
    piece, left, back = os.urandom(32768), int(sys.argv[3]), 0
    try:
        while left:
            sent = piece[: min(left, len(piece))]
            sock.sendall(sent)
            got = b""
            while len(got) < len(sent):
                chunk = sock.recv(65536)
                if not chunk:
                    raise ConnectionError
                got += chunk
            back += len(got) if got == sent else 0
            left -= len(sent)
    except OSError:
        pass
    carried = f" | carried={back}"
print(f"{status} | accept={'ok' if good else 'bad'} | echo={echoed}{carried}")
