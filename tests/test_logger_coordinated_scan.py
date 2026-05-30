#!/usr/bin/env python3
"""Regression tests for HoneyLogger coordinated-scan detection.

Run directly (no framework needed):  python3 tests/test_logger_coordinated_scan.py

These guard the bug that took down the live VPS: emitting the synthetic
"coordinated_scan" SYSTEM event re-entered detection and recursed until
RecursionError, which propagated out of log() and killed the SSH/FTP
listener threads.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logger import HoneyLogger  # noqa: E402


def _events(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def test_coordinated_scan_does_not_recurse():
    """One IP hitting two real decoys must not raise (was RecursionError)."""
    with tempfile.TemporaryDirectory() as d:
        log = HoneyLogger(log_file=str(Path(d) / "ev.json"), multi_service_window=60)
        log.log("SSH", "1.2.3.4", 5555, "login_attempt", {"username": "root", "password": "x"})
        log.log("FTP", "1.2.3.4", 5556, "login_attempt", {"username": "root", "password": "y"})
        scans = [e for e in _events(log.log_file) if e["event_type"] == "coordinated_scan"]
        assert len(scans) == 1, f"expected exactly 1 coordinated_scan, got {len(scans)}"


def test_synthetic_system_events_not_counted_as_services():
    """The coordinated_scan SYSTEM row must not appear in the flagged services."""
    with tempfile.TemporaryDirectory() as d:
        log = HoneyLogger(log_file=str(Path(d) / "ev.json"), multi_service_window=60)
        log.log("SSH", "9.9.9.9", 1, "connection")
        log.log("HTTP", "9.9.9.9", 2, "page_probe", {"path": "/"})
        scan = [e for e in _events(log.log_file) if e["event_type"] == "coordinated_scan"][0]
        assert "SYSTEM" not in scan["details"]["services"], scan["details"]["services"]
        assert set(scan["details"]["services"]) == {"SSH", "HTTP"}


def test_repeated_hits_do_not_spam_alerts():
    """A flagged IP hammering a decoy must not emit a new alert every packet."""
    with tempfile.TemporaryDirectory() as d:
        log = HoneyLogger(log_file=str(Path(d) / "ev.json"), multi_service_window=60)
        log.log("SSH", "5.5.5.5", 1, "connection")
        log.log("FTP", "5.5.5.5", 2, "connection")
        for _ in range(50):
            log.log("SSH", "5.5.5.5", 3, "login_attempt", {"username": "a", "password": "b"})
        scans = [e for e in _events(log.log_file) if e["event_type"] == "coordinated_scan"]
        assert len(scans) == 1, f"expected 1 alert for the IP, got {len(scans)}"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception as e:
                failures += 1
                print(f"FAIL {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failures else 0)
