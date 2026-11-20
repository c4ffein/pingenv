#!/usr/bin/env python3
"""Test upstream: completes a WebSocket handshake, then echoes raw bytes."""
import base64
import hashlib
import socketserver
import sys

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        headers = {}
        for line in data.split(b"\r\n")[1:]:
            if b":" in line:
                name, value = line.split(b":", 1)
                headers[name.strip().lower()] = value.strip()
        key = headers.get(b"sec-websocket-key", b"")
        accept = base64.b64encode(hashlib.sha1(key + GUID).digest())
        self.request.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        while True:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            self.request.sendall(chunk)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


Server(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
