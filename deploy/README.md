# Deploying HoneyNet on a real VPS

This is how you turn HoneyNet from a demo into a sensor that collects **real
attacker data** — the kind you can honestly screenshot for a writeup.

> ⚠️ Use a **fresh, dedicated, throwaway VPS**. The SSH decoy accepts any
> credentials and the box will attract real malicious traffic. It must do
> nothing else you care about.

---

## 1. Get a VPS

Any $4–6/mo cloud instance works. Cheapest options with good "background
radiation" (lots of scanners find them fast):

- **Hetzner Cloud** — CX22, ~€4/mo
- **DigitalOcean** — Basic droplet, $6/mo
- **Linode / Vultr** — $5/mo

Pick Ubuntu 22.04 or 24.04. Note the public IP and the root password / SSH key.

## 2. One-command setup

SSH into the box as root, then:

```bash
git clone https://github.com/B0bTheSkull/honeynet.git
cd honeynet
sudo bash deploy/setup-vps.sh
```

The script (`deploy/setup-vps.sh`) does all of this for you:

1. **Moves your real sshd to port 64022** so the decoy can later own port 22
   and so the firewall doesn't lock you out.
2. Installs Python, creates an unprivileged `honeynet` service user.
3. Installs the code in `/opt/honeynet` with its own virtualenv.
4. Configures **ufw**: allow `64022` (your admin SSH) + decoy ports, deny the rest.
5. Installs and starts a **systemd** service (`honeynet.service`) that
   auto-restarts and survives reboots.
6. Installs **logrotate** so the JSON log doesn't grow forever.

> After it runs, open a **new** terminal and confirm you can reconnect on the
> new admin port before closing your current session:
> `ssh -p 64022 root@YOUR_IP`

## 3. Maximise real traffic (recommended)

By default the decoys sit on 2222/8080/2121. Scanners hit `22/80/21` far more
often. Once you've confirmed admin SSH works on 64022:

```bash
sudo cp /opt/honeynet/deploy/config.vps.yaml /opt/honeynet/config.yaml
sudo chown honeynet:honeynet /opt/honeynet/config.yaml
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 21/tcp
sudo systemctl restart honeynet
```

Now the decoys answer on the real ports. You'll usually see your first
brute-force attempts **within an hour**.

## 4. Watch it work

```bash
# Live colour-coded console feed — your hero screenshot
journalctl -u honeynet -f

# Service health
systemctl status honeynet

# Aggregated stats — your "what I found" screenshot
sudo -u honeynet /opt/honeynet/venv/bin/python /opt/honeynet/honeynet.py \
    --analyze --log /opt/honeynet/logs/honeynet.json

# Raw structured events
tail -n 20 /opt/honeynet/logs/honeynet.json
```

## 5. Collect, then write up

Let it run **24–72 hours** before drawing conclusions. Then:

- Run `--analyze` for the credential / IP / event-type tables.
- (Optional) cross-reference top source IPs against
  [AbuseIPDB](https://www.abuseipdb.com/) or
  [Feodo Tracker](https://feodotracker.abuse.ch/) to show how much traffic is
  known-bad infrastructure.
- Screenshot the live feed, a COORDINATED SCAN alert, the analyzer report, and
  a few raw JSON lines.

## Screenshot checklist

| Shot | Where to get it |
|------|-----------------|
| Live event feed | `journalctl -u honeynet -f` |
| Coordinated-scan alert | watch the feed; fires when one IP hits 2+ decoys in 60s |
| Analyzer summary | `honeynet.py --analyze` |
| Raw JSON events | `tail /opt/honeynet/logs/honeynet.json` |
| Fake admin panel | browser → `http://YOUR_IP/` (or `:8080`) |
| systemd service | `systemctl status honeynet` |

## Teardown

```bash
sudo systemctl disable --now honeynet
# then destroy the VPS from your provider's dashboard
```

Don't reuse the IP for anything trustworthy afterwards — it's been advertised
as a soft target.

---

## Safety / legal notes

- Only run on infrastructure **you own**. Honeypotting your own VPS for threat
  intel is legitimate in most jurisdictions; check yours.
- The credentials you capture are ones attackers *send you*. Never reuse them
  to access anything, and never "hack back." Intelligence only.
- Keep the real admin port (64022) protected with key-only auth.
