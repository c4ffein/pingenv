#!/usr/bin/env python3
"""Test upstream: answers every request with a JSON description of it."""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME, PORT = sys.argv[1], int(sys.argv[2])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def body_length(self):
        """How many bytes of request body arrived, however it was framed."""
        if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
            return len(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        total = 0
        while True:
            size = int(self.rfile.readline().split(b";")[0], 16)
            if size == 0:
                while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                    pass  # trailers
                return total
            total += len(self.rfile.read(size))
            self.rfile.readline()

    def do_GET(self):
        if self.path.startswith("/sleep/"):
            time.sleep(float(self.path.split("/")[2].split("?")[0]))
        try:
            received = self.body_length()
        except ValueError:
            return  # the proxy cut the body short, as a size-limit test expects
        body = json.dumps(
            {
                "upstream": NAME,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body_bytes": received,
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass  # the proxy gave up first, as a timeout test expects

    do_POST = do_GET

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
