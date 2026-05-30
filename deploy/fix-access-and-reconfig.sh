#!/usr/bin/env bash
#
# Recover from the 64022 lockout and switch to a lockout-proof port layout.
#
# Root cause: Ubuntu 24.04+/26.04 run sshd via systemd socket activation
# (ssh.socket), so `Port 64022` in sshd_config is ignored. The original script
# also firewalled port 22, leaving no admin path. New design keeps admin SSH on
# 22 (never touched) and puts decoys on 80/21/2222 -- no conflict, no lockout.
#
# Safe to run repeatedly (idempotent). Run as root on the VPS.

set -euo pipefail

echo "[*] Reverting the broken sshd Port 64022 change"
sed -i '/^Port 64022$/d' /etc/ssh/sshd_config || true
# Make sure socket-activated sshd is firmly on port 22
mkdir -p /etc/systemd/system/ssh.socket.d
cat > /etc/systemd/system/ssh.socket.d/override.conf <<'EOF'
[Socket]
ListenStream=
ListenStream=22
EOF
systemctl daemon-reload
systemctl restart ssh.socket 2>/dev/null || systemctl restart ssh 2>/dev/null || true

echo "[*] Rewriting firewall: admin SSH on 22, decoys on 80/21/2222"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment 'admin ssh'
ufw allow 2222/tcp comment 'honeynet ssh decoy'
ufw allow 80/tcp   comment 'honeynet http decoy'
ufw allow 21/tcp   comment 'honeynet ftp decoy'
ufw --force enable

echo "[*] Pointing decoys at real ports (http=80, ftp=21, ssh=2222)"
cat > /opt/honeynet/config.yaml <<'EOF'
log_file: "logs/honeynet.json"

honeypots:
  ssh:
    enabled: true
    port: 2222
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  http:
    enabled: true
    port: 80
  ftp:
    enabled: true
    port: 21
    banner: "220 ProFTPD Server ready"

alerts:
  multi_service_window: 60
EOF
chown honeynet:honeynet /opt/honeynet/config.yaml

systemctl restart honeynet

echo "[*] Cleaning up stray junk files in /root"
( cd /root && set -f && rm -f -- '**' 700 chmod 2>/dev/null || true )

echo
echo "[+] Done. Admin SSH on 22. Decoys: SSH 2222, HTTP 80, FTP 21."
ss -ltnp | grep -E ":(22|80|21|2222)\b" || true
