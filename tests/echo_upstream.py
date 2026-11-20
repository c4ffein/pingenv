#!/usr/bin/env python3
"""Test upstream: answers every request with a JSON description of it."""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME, PORT = sys.argv[1], int(sys.argv[2])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith("/sleep/"):
            time.sleep(float(self.path.split("/")[2].split("?")[0]))
        body = json.dumps(
            {
                "upstream": NAME,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
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

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
