#!/usr/bin/env python3
"""The "internet" web server of the VPN lab (scripts/e2e/vpn_lab.sh).

GET /      -> "caller=<the source IP this server sees>"
GET /blob  -> 16 MiB of deterministic bytes (their SHA-256 is written to
              BLOB_SHA_FILE at startup) to prove bulk transfer integrity.
Every request is logged as "<source-ip> <path>".

usage: lab_http.py BIND_IP PORT LOG_FILE BLOB_SHA_FILE
"""
import hashlib
import random
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND, PORT, LOG, SHA_FILE = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
BLOB = random.Random(1).randbytes(16 << 20)
with open(SHA_FILE, "w") as f:
    f.write(hashlib.sha256(BLOB).hexdigest() + "\n")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = BLOB if self.path == "/blob" else f"caller={self.client_address[0]}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        with open(LOG, "a") as f:
            f.write(f"{self.client_address[0]} {self.path}\n")


ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
