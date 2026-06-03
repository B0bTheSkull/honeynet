"""Centralized JSON event logger for HoneyNet."""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
import time

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"


class HoneyLogger:
    def __init__(self, log_file="logs/honeynet.json", multi_service_window=60):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(exist_ok=True)
        self.lock = threading.Lock()
        self.multi_service_window = multi_service_window
        # ip -> {service -> timestamp}
        self.ip_service_hits = defaultdict(dict)
        # IPs already flagged as coordinated, so we alert once instead of per packet
        self.alerted_ips = set()

    def log(self, honeypot_type, source_ip, source_port, event_type, details=None):
        event = {
            # UTC + offset so the Sentinel can compute event age regardless of
            # what timezone the consuming host (the Pi) is set to.
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "honeypot": honeypot_type,
            "source_ip": source_ip,
            "source_port": source_port,
            "event_type": event_type,
            "details": details or {}
        }

        self._write(event)
        self._check_multi_service(honeypot_type, source_ip)
        return event

    def _write(self, event):
        with self.lock:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        self._print_event(event)

    def _print_event(self, event):
        ts = event["timestamp"][11:19]
        hp = event["honeypot"].upper()
        src = event["source_ip"]
        etype = event["event_type"].replace("_", " ").upper()
        details = event.get("details", {})

        cred_str = ""
        if "username" in details and "password" in details:
            cred_str = f" | u={details['username']} p={details['password']}"
        elif "command" in details:
            cred_str = f" | cmd={details['command'][:40]}"

        print(f"{CYAN}[{ts}]{RESET} {YELLOW}[{hp}]{RESET} {BOLD}{src}{RESET}:{event['source_port']} → {etype}{cred_str}")

    def _check_multi_service(self, honeypot_type, source_ip):
        # SYSTEM rows are synthetic (e.g. the coordinated_scan alert we emit
        # below); they are not attacker activity and must never feed detection.
        # Counting them also caused infinite recursion: emitting a SYSTEM alert
        # re-entered this method, re-tripped the >=2 check, and recursed until
        # RecursionError tore down the SSH/FTP listener threads.
        if honeypot_type == "SYSTEM":
            return

        now = time.time()
        self.ip_service_hits[source_ip][honeypot_type] = now

        # Prune old hits
        self.ip_service_hits[source_ip] = {
            svc: t for svc, t in self.ip_service_hits[source_ip].items()
            if now - t < self.multi_service_window
        }

        services_hit = set(self.ip_service_hits[source_ip].keys())
        # Alert once per IP, not on every subsequent packet from a flagged scanner.
        if len(services_hit) >= 2 and source_ip not in self.alerted_ips:
            self.alerted_ips.add(source_ip)
            print(f"\n{RED}{BOLD}[!] COORDINATED SCAN DETECTED{RESET}")
            print(f"    {source_ip} hit {len(services_hit)} honeypot services: {', '.join(services_hit)}")
            print(f"    This indicates automated multi-service scanning.\n")
            self.log("SYSTEM", source_ip, 0, "coordinated_scan", {
                "services": list(services_hit),
                "window_seconds": self.multi_service_window
            })
