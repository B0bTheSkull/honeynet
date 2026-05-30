#!/usr/bin/env bash
#
# HoneyNet VPS bootstrap
# ----------------------
# Installs HoneyNet into /opt/honeynet, creates an unprivileged service user,
# sets up a virtualenv, installs the systemd unit, and starts the honeypots.
#
# Run as root on a FRESH, DEDICATED VPS (Ubuntu/Debian):
#     curl -fsSL <raw-url>/deploy/setup-vps.sh | sudo bash
# or copy the repo up and run:
#     sudo bash deploy/setup-vps.sh
#
# IMPORTANT: This box should do nothing else. Do not run it on a host you care
# about — the SSH decoy accepts any credentials by design.

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/B0bTheSkull/honeynet.git}"
INSTALL_DIR="/opt/honeynet"
SERVICE_USER="honeynet"

echo "[*] HoneyNet VPS setup starting"

if [[ $EUID -ne 0 ]]; then
  echo "[!] Run as root (sudo bash deploy/setup-vps.sh)"; exit 1
fi

# --- 1. Move the REAL sshd off port 22 BEFORE we touch the firewall ---------
# So you don't lock yourself out and so the decoy can later own port 22.
SSHD_CONF="/etc/ssh/sshd_config"
if grep -qiE '^[#[:space:]]*Port[[:space:]]+22([[:space:]]|$)' "$SSHD_CONF" 2>/dev/null \
   || ! grep -qiE '^[[:space:]]*Port[[:space:]]+' "$SSHD_CONF" 2>/dev/null; then
  echo "[*] Moving real sshd to port 64022 (reconnect there after this finishes!)"
  if ! grep -qiE '^[[:space:]]*Port[[:space:]]+64022' "$SSHD_CONF"; then
    echo "Port 64022" >> "$SSHD_CONF"
  fi
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  echo "[!] Real SSH now ALSO on 64022. Verify a new session works before closing this one."
fi

# --- 2. Packages ------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-venv python3-pip git ufw

# --- 3. Service user + code -------------------------------------------------
id "$SERVICE_USER" &>/dev/null || useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"

if [[ -d "$INSTALL_DIR/.git" ]]; then
  echo "[*] Updating existing checkout"
  git -C "$INSTALL_DIR" pull --ff-only
elif [[ -f "./honeynet.py" ]]; then
  echo "[*] Copying repo from current directory"
  mkdir -p "$INSTALL_DIR"
  cp -r ./* "$INSTALL_DIR"/
else
  echo "[*] Cloning $REPO_URL"
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR/logs"

# --- 4. Virtualenv + deps ---------------------------------------------------
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# --- 5. Firewall ------------------------------------------------------------
# Allow your real admin SSH (64022) + the three decoy ports. Deny the rest.
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 64022/tcp comment 'real admin ssh'
ufw allow 2222/tcp  comment 'honeynet ssh decoy'
ufw allow 8080/tcp  comment 'honeynet http decoy'
ufw allow 2121/tcp  comment 'honeynet ftp decoy'
ufw --force enable

# --- 6. systemd -------------------------------------------------------------
cp "$INSTALL_DIR/deploy/honeynet.service" /etc/systemd/system/honeynet.service
systemctl daemon-reload
systemctl enable --now honeynet.service

# --- 7. log rotation --------------------------------------------------------
if [[ -f "$INSTALL_DIR/deploy/honeynet.logrotate" ]]; then
  cp "$INSTALL_DIR/deploy/honeynet.logrotate" /etc/logrotate.d/honeynet
fi

echo
echo "[+] HoneyNet is running. Useful commands:"
echo "      systemctl status honeynet         # service health"
echo "      journalctl -u honeynet -f         # live console feed (great screenshot)"
echo "      $INSTALL_DIR/venv/bin/python $INSTALL_DIR/honeynet.py --analyze --log $INSTALL_DIR/logs/honeynet.json"
echo
echo "[!] Decoy ports: SSH 2222, HTTP 8080, FTP 2121."
echo "[!] To maximise real traffic, remap the decoys to 22/80/21 in config.yaml"
echo "    (real admin SSH is on 64022) and re-open those ports in ufw."
