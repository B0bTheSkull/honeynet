"""Analyze HoneyNet event log and print statistics."""
import json
from collections import defaultdict
from pathlib import Path

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"


def analyze(log_file="logs/honeynet.json"):
    p = Path(log_file)
    if not p.exists():
        print(f"[!] Log file not found: {log_file}")
        return

    events = []
    with open(p) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not events:
        print("[*] No events logged yet.")
        return

    by_honeypot = defaultdict(int)
    by_event = defaultdict(int)
    by_ip = defaultdict(int)
    credentials = defaultdict(int)

    for e in events:
        hp = e.get("honeypot", "?")
        by_honeypot[hp] += 1
        by_event[e.get("event_type", "?")] += 1
        ip = e.get("source_ip", "?")
        by_ip[ip] += 1

        details = e.get("details", {})
        if "username" in details and "password" in details:
            cred = f"{details['username']}:{details['password']}"
            credentials[cred] += 1

    print(f"\n{CYAN}{'='*55}{RESET}")
    print(f"{BOLD}HoneyNet Event Analysis — {len(events)} total events{RESET}")
    print(f"{CYAN}{'='*55}{RESET}\n")

    print(f"{BOLD}By Honeypot:{RESET}")
    for hp, count in sorted(by_honeypot.items(), key=lambda x: -x[1]):
        print(f"  {YELLOW}{hp}{RESET}: {count}")

    print(f"\n{BOLD}By Event Type:{RESET}")
    for etype, count in sorted(by_event.items(), key=lambda x: -x[1]):
        print(f"  {etype}: {count}")

    print(f"\n{BOLD}Top Source IPs:{RESET}")
    for ip, count in sorted(by_ip.items(), key=lambda x: -x[1])[:15]:
        print(f"  {ip}: {count} events")

    if credentials:
        print(f"\n{BOLD}Most Common Credentials Attempted:{RESET}")
        for cred, count in sorted(credentials.items(), key=lambda x: -x[1])[:10]:
            print(f"  {RED}{cred}{RESET}: {count}x")

    if events:
        first = events[0].get("timestamp", "?")[:19].replace("T", " ")
        last = events[-1].get("timestamp", "?")[:19].replace("T", " ")
        print(f"\n{BOLD}Time range:{RESET} {first} → {last}")

    print()
