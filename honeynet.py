#!/usr/bin/env python3
"""
HoneyNet - Modular Honeypot Framework
SSH, HTTP, and FTP honeypots with centralized logging and coordinated scan detection.

⚠️  Deploy on a dedicated machine/VPS. Do NOT run on your main workstation.
"""

import argparse
import sys
import threading

from config import load_config
from logger import HoneyLogger
import analyzer as analyzer_module

RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BOLD = "\033[1m"


def banner():
    print(f"""
{CYAN}╔═══════════════════════════════════════════╗{RESET}
{CYAN}║        HoneyNet v1.0                      ║{RESET}
{CYAN}║   Modular Honeypot Framework              ║{RESET}
{CYAN}╚═══════════════════════════════════════════╝{RESET}
""")


def main():
    parser = argparse.ArgumentParser(
        description="HoneyNet — Modular honeypot framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python honeynet.py                         # start all enabled honeypots
  python honeynet.py --config config.yaml    # use custom config
  python honeynet.py --analyze               # analyze event log
  python honeynet.py --analyze --log custom.json
        """
    )
    parser.add_argument("--config", default="config.yaml", help="Config file path")
    parser.add_argument("--analyze", action="store_true", help="Analyze event log and exit")
    parser.add_argument("--log", help="Override log file path")
    args = parser.parse_args()

    cfg = load_config(args.config)
    log_file = args.log or cfg.get("log_file", "logs/honeynet.json")

    if args.analyze:
        banner()
        analyzer_module.analyze(log_file)
        return

    banner()

    logger = HoneyLogger(
        log_file=log_file,
        multi_service_window=cfg.get("alerts", {}).get("multi_service_window", 60)
    )

    honeypots_cfg = cfg.get("honeypots", {})
    threads = []

    # SSH Honeypot
    ssh_cfg = honeypots_cfg.get("ssh", {})
    if ssh_cfg.get("enabled", True):
        try:
            from honeypots.ssh_honeypot import SSHHoneypot
            hp = SSHHoneypot(
                port=ssh_cfg.get("port", 2222),
                logger=logger,
                banner=ssh_cfg.get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
            )
            t = threading.Thread(target=hp.start, daemon=True)
            t.start()
            threads.append(t)
            print(f"{GREEN}[+]{RESET} SSH honeypot listening on port {ssh_cfg.get('port', 2222)}")
        except ImportError:
            print(f"{YELLOW}[!]{RESET} paramiko not installed. Skipping SSH honeypot. (pip install paramiko)")

    # HTTP Honeypot
    http_cfg = honeypots_cfg.get("http", {})
    if http_cfg.get("enabled", True):
        try:
            from honeypots.http_honeypot import HTTPHoneypot
            hp = HTTPHoneypot(port=http_cfg.get("port", 8080), logger=logger)
            t = threading.Thread(target=hp.start, daemon=True)
            t.start()
            threads.append(t)
            print(f"{GREEN}[+]{RESET} HTTP honeypot listening on port {http_cfg.get('port', 8080)}")
        except ImportError:
            print(f"{YELLOW}[!]{RESET} Flask not installed. Skipping HTTP honeypot. (pip install flask)")

    # FTP Honeypot
    ftp_cfg = honeypots_cfg.get("ftp", {})
    if ftp_cfg.get("enabled", True):
        from honeypots.ftp_honeypot import FTPHoneypot
        hp = FTPHoneypot(
            port=ftp_cfg.get("port", 2121),
            logger=logger,
            banner=ftp_cfg.get("banner", "220 FTP Server Ready")
        )
        t = threading.Thread(target=hp.start, daemon=True)
        t.start()
        threads.append(t)
        print(f"{GREEN}[+]{RESET} FTP honeypot listening on port {ftp_cfg.get('port', 2121)}")

    if not threads:
        print("[!] No honeypots started. Check your config.")
        sys.exit(1)

    print(f"\n{CYAN}[*]{RESET} Logging to: {log_file}")
    print(f"{CYAN}[*]{RESET} Press Ctrl+C to stop\n")

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] HoneyNet stopped.")


if __name__ == "__main__":
    main()
