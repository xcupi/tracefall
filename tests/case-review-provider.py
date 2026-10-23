#!/usr/bin/env python3
"""Synthetic test provider ONLY. Never use this for casework or accuracy claims.
Usage: python3 tests/case-review-provider.py OUTPUT_DIR [PORT=18480]
Records requests under OUTPUT_DIR and returns fixed explicitly synthetic lines.
"""
import http.server
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"TRACEFALL_SYNTHETIC_REVIEW_PROVIDER")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        with (root / "requests.jsonl").open("ab") as output:
            output.write(body + b"\n")
        response = {
            "model": "synthetic-review-test",
            "choices": [{"message": {
                "role": "assistant",
                "content": "A parsed unflagged observation is recorded. [E1]\n"
                           "This is a bounded partial selection. [K1]",
            }, "finish_reason": "stop"}],
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())


http.server.HTTPServer(("127.0.0.1", int(sys.argv[2]) if len(sys.argv) > 2 else 18480), Handler).serve_forever()
