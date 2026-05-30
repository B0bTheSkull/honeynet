#!/usr/bin/env python3
"""
Sentinel receiver — the Pi-side endpoint for HoneyNet writeup-worthy alerts.

Listens on the tailnet only, validates a bearer token, and persists each alert
to a JSONL file while printing a human-readable summary (visible via
`journalctl -u sentinel-receiver -f`). Dependency-free (stdlib only).

Config via environment (systemd loads it from /etc/sentinel-receiver.env):
    SENTINEL_TOKEN    required — must match the token the VPS watcher sends
    SENTINEL_BIND     default 100.87.221.5  (the Pi's tailnet IP; never 0.0.0.0)
    SENTINEL_PORT     default 8787
    SENTINEL_PATH     default /honeynet
    SENTINEL_LOG      default ~/sentinel/honeynet-alerts.jsonl
"""
import hmac
import json
import os
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = os.environ.get("SENTINEL_TOKEN", "")
BIND = os.environ.get("SENTINEL_BIND", "100.87.221.5")
PORT = int(os.environ.get("SENTINEL_PORT", "8787"))
PATH = os.environ.get("SENTINEL_PATH", "/honeynet")
LOG = Path(os.environ.get("SENTINEL_LOG", str(Path.home() / "sentinel" / "honeynet-alerts.jsonl")))


def _authorized(header):
    if not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[len("Bearer "):], TOKEN)


class Handler(BaseHTTPRequestHandler):
    server_version = "sentinel/1.0"

    def _reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.rstrip("/") != PATH.rstrip("/"):
            self._reply(404, {"error": "not found"})
            return
        if not _authorized(self.headers.get("Authorization")):
            self._reply(401, {"error": "unauthorized"})
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(n).decode() or "{}")
        except (ValueError, json.JSONDecodeError):
            self._reply(400, {"error": "bad json"})
            return

        record = {"received_at": datetime.now().isoformat(), "remote": self.client_address[0], **payload}
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(record) + "\n")

        stats = payload.get("stats", {})
        print(f"\n🛰  HONEYNET ALERT [{record['received_at'][11:19]}] from {record['remote']}")
        print(f"    {payload.get('milestone', '?')}: {payload.get('reason', '')}")
        print(f"    events={stats.get('total_events')} ips={stats.get('unique_ips')} "
              f"coordinated={stats.get('coordinated_scans')}\n", flush=True)
        self._reply(200, {"ok": True})

    def do_GET(self):
        # Lightweight health check (no token needed; reveals nothing sensitive).
        if self.path.rstrip("/") in ("/health", ""):
            self._reply(200, {"ok": True, "service": "sentinel-receiver"})
        else:
            self._reply(404, {"error": "not found"})

    def log_message(self, *args):
        pass  # silence default per-request stderr logging; we print our own


def main():
    if not TOKEN:
        print("[sentinel-receiver] SENTINEL_TOKEN is required", file=sys.stderr)
        sys.exit(2)
    # The tailnet IP may not be assigned yet at boot — retry the bind briefly.
    deadline = time.time() + 60
    while True:
        try:
            httpd = ThreadingHTTPServer((BIND, PORT), Handler)
            break
        except OSError as e:
            if time.time() > deadline:
                print(f"[sentinel-receiver] could not bind {BIND}:{PORT}: {e}", file=sys.stderr)
                sys.exit(1)
            time.sleep(3)
    print(f"[sentinel-receiver] listening on {BIND}:{PORT}{PATH} -> {LOG}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
