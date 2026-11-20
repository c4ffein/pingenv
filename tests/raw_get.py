#!/usr/bin/env python3
"""GET over HTTPS with the request target sent exactly as given.

curl escapes what it thinks needs escaping; this does not, so a path can carry
raw UTF-8. Prints the response body.

usage: raw_get.py <connect-port> <host-header> <target>   (certificate not verified)
"""
import socket
import ssl
import sys

port, host, target = int(sys.argv[1]), sys.argv[2], sys.argv[3]

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
raw = socket.create_connection(("127.0.0.1", port), timeout=5)
sock = context.wrap_socket(raw, server_hostname=host.split(":")[0])
sock.sendall(
    b"GET " + target.encode() + b" HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n"
)
reply = b""
while chunk := sock.recv(65536):
    reply += chunk
sys.stdout.buffer.write(reply.split(b"\r\n\r\n", 1)[1])
