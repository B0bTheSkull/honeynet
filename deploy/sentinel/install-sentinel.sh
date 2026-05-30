#!/usr/bin/env bash
#
# Install the HoneyNet -> Sentinel writeup watcher on the VPS.
# Assumes HoneyNet is already deployed at /opt/honeynet and Tailscale is up.
# Run as root. Idempotent.

set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -f /etc/honeynet-sentinel.env ]]; then
  echo "[!] /etc/honeynet-sentinel.env not found."
  echo "    cp $SRC/honeynet-sentinel.env.example /etc/honeynet-sentinel.env"
  echo "    chmod 600 /etc/honeynet-sentinel.env  &&  edit in your URL + token first."
  exit 1
fi
chmod 600 /etc/honeynet-sentinel.env

mkdir -p /var/lib/honeynet-sentinel

cp "$SRC/honeynet-sentinel.service" /etc/systemd/system/honeynet-sentinel.service
cp "$SRC/honeynet-sentinel.timer"   /etc/systemd/system/honeynet-sentinel.timer
systemctl daemon-reload
systemctl enable --now honeynet-sentinel.timer

echo "[+] Sentinel watcher installed. Timer:"
systemctl status honeynet-sentinel.timer --no-pager | head -5
echo "[*] Test a single run now:  systemctl start honeynet-sentinel.service && journalctl -u honeynet-sentinel.service -n 20 --no-pager"
