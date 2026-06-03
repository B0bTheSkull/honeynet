#!/usr/bin/env python3
"""
HoneyNet -> Sentinel "worth a writeup" watcher.

Reads the honeynet event log, computes how much *real signal* has accumulated,
and pings the Sentinel home-ops console (HTTP webhook, over Tailscale) the first
time the data crosses each writeup-worthy milestone. Fires once per milestone,
then stays quiet -- no spam.

Config comes from environment (loaded by systemd from /etc/honeynet-sentinel.env):
    SENTINEL_WEBHOOK_URL   required, e.g. http://pi.tailnet-name.ts.net:8787/hook
    SENTINEL_TOKEN         required, sent as Authorization: Bearer <token>
    HONEYNET_LOG           default /opt/honeynet/logs/honeynet.json
    STATE_FILE             default /var/lib/honeynet-sentinel/state.json
    MIN_UNIQUE_IPS         default 15   (milestone: distinct attacker IPs)
    MIN_TOTAL_EVENTS       default 250  (milestone: total logged events)
    # A coordinated-scan event always counts as a milestone on first sighting.

Exit codes: 0 normal (sent or nothing to do), 2 config error. Network/log
errors are logged to stderr and exit 0 so the timer keeps running.
"""
import json
import os
import sys
import ssl
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from urllib.parse import urlsplit, urlunsplit


def _status_url(webhook_url):
    """Derive the /status endpoint from the milestone webhook URL."""
    return urlunsplit(urlsplit(webhook_url)._replace(path="/status"))


def fail(msg, code=2):
    print(f"[writeup-watch] {msg}", file=sys.stderr)
    sys.exit(code)


def load_events(log_path):
    p = Path(log_path)
    if not p.exists():
        return []
    events = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def summarize(events):
    unique_ips = set()
    by_event = Counter()
    by_hp = Counter()
    ip_counts = Counter()
    coordinated = 0
    creds = Counter()
    last_event_ts = None
    for e in events:
        ip = e.get("source_ip")
        # Don't count the synthetic SYSTEM rows toward attacker IPs
        if ip and e.get("honeypot") != "SYSTEM":
            unique_ips.add(ip)
            ip_counts[ip] += 1
        et = e.get("event_type", "?")
        by_event[et] += 1
        by_hp[e.get("honeypot", "?")] += 1
        if et == "coordinated_scan":
            coordinated += 1
        d = e.get("details") or {}
        if "username" in d and "password" in d:
            creds[f"{d['username']}:{d['password']}"] += 1
        ts = e.get("timestamp")
        if ts and (last_event_ts is None or ts > last_event_ts):
            last_event_ts = ts
    return {
        "total_events": len(events),
        "unique_ips": len(unique_ips),
        "coordinated_scans": coordinated,
        "by_honeypot": dict(by_hp),
        "by_event_type": dict(by_event),
        "top_creds": creds.most_common(10),
        "top_ips": ip_counts.most_common(100),
        "last_event_ts": last_event_ts,
    }


def load_state(state_file):
    p = Path(state_file)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {"fired": []}


def save_state(state_file, state):
    p = Path(state_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(p)


def post(url, token, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    # Transport security: the webhook rides the Tailscale mesh, which already
    # provides end-to-end WireGuard encryption between VPS and Pi -- so plain
    # http:// over the tailnet is safe. If you use https://, full certificate
    # verification is enforced (no insecure bypass on purpose).
    if url.lower().startswith("https://"):
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return resp.status
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status


def main():
    url = os.environ.get("SENTINEL_WEBHOOK_URL")
    token = os.environ.get("SENTINEL_TOKEN")
    if not url or not token:
        fail("SENTINEL_WEBHOOK_URL and SENTINEL_TOKEN must be set")

    log_path = os.environ.get("HONEYNET_LOG", "/opt/honeynet/logs/honeynet.json")
    state_file = os.environ.get("STATE_FILE", "/var/lib/honeynet-sentinel/state.json")
    min_ips = int(os.environ.get("MIN_UNIQUE_IPS", "15"))
    min_events = int(os.environ.get("MIN_TOTAL_EVENTS", "250"))

    events = load_events(log_path)
    if not events:
        return  # nothing logged yet
    s = summarize(events)

    # --- Always send a status heartbeat so the dashboard can show liveness ---
    status_url = os.environ.get("SENTINEL_STATUS_URL") or _status_url(url)
    heartbeat = {
        "type": "status",
        "source": "honeynet",
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total_events": s["total_events"],
            "unique_ips": s["unique_ips"],
            "coordinated_scans": s["coordinated_scans"],
            "by_honeypot": s["by_honeypot"],
            "by_event_type": s["by_event_type"],
            "top_credentials": s["top_creds"],
            "top_ips": s["top_ips"],
            "last_event_ts": s["last_event_ts"],
        },
    }
    try:
        st = post(status_url, token, heartbeat)
        print(f"[writeup-watch] sent status heartbeat -> HTTP {st}")
    except Exception as e:
        print(f"[writeup-watch] heartbeat send failed: {e}", file=sys.stderr)

    state = load_state(state_file)
    fired = set(state.get("fired", []))

    # Decide which milestones are newly crossed.
    milestones = []
    if s["coordinated_scans"] > 0 and "coordinated_scan" not in fired:
        milestones.append(("coordinated_scan",
                           "First COORDINATED SCAN captured -- one IP hit "
                           "multiple decoys. Strong writeup material."))
    if s["unique_ips"] >= min_ips and "unique_ips" not in fired:
        milestones.append(("unique_ips",
                           f"{s['unique_ips']} distinct attacker IPs logged "
                           f"(threshold {min_ips})."))
    if s["total_events"] >= min_events and "total_events" not in fired:
        milestones.append(("total_events",
                           f"{s['total_events']} total events logged "
                           f"(threshold {min_events})."))

    if not milestones:
        return

    for key, reason in milestones:
        payload = {
            "source": "honeynet",
            "title": "HoneyNet: data is writeup-worthy",
            "milestone": key,
            "reason": reason,
            "stats": {
                "total_events": s["total_events"],
                "unique_ips": s["unique_ips"],
                "coordinated_scans": s["coordinated_scans"],
                "by_honeypot": s["by_honeypot"],
                "top_credentials": s["top_creds"],
            },
            "priority": "high" if key == "coordinated_scan" else "default",
        }
        try:
            status = post(url, token, payload)
            print(f"[writeup-watch] sent milestone '{key}' -> HTTP {status}")
            fired.add(key)
        except Exception as e:
            # Leave it unfired so we retry next tick.
            print(f"[writeup-watch] send failed for '{key}': {e}", file=sys.stderr)

    state["fired"] = sorted(fired)
    save_state(state_file, state)


if __name__ == "__main__":
    main()
