# HoneyNet

> **Modular honeypot framework — SSH, HTTP, and FTP decoys with centralized logging and coordinated scan detection.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Educational](https://img.shields.io/badge/use-educational-orange?style=flat-square)

> ⚠️ Deploy on a dedicated VPS or isolated machine. Do not run on your primary workstation or production systems.

---

## Honeypots

| Service | Default Port | What It Captures |
|---------|-------------|-----------------|
| **SSH** | 2222 | All login credentials, shell commands typed |
| **HTTP** | 8080 | Login attempts with credentials, sensitive path probes |
| **FTP** | 2121 | Login credentials, file access attempts, commands |

All three services log to a single centralized JSON log file.

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/honeynet.git
cd honeynet
pip install -r requirements.txt
mkdir -p logs
```

---

## Usage

```bash
# Start all honeypots (uses config.yaml)
python honeynet.py

# Custom config file
python honeynet.py --config my_config.yaml

# Analyze the event log
python honeynet.py --analyze

# Analyze a specific log file
python honeynet.py --analyze --log logs/honeynet.json
```

---

## Configuration

```yaml
log_file: "logs/honeynet.json"

honeypots:
  ssh:
    enabled: true
    port: 2222
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  http:
    enabled: true
    port: 8080
  ftp:
    enabled: true
    port: 2121
    banner: "220 FTP Server Ready"

alerts:
  multi_service_window: 60  # seconds
```

---

## Example Log Output

Real-time console output (color-coded):

```
[14:32:01] [SSH] 185.220.101.45:52341 → CONNECTION
[14:32:03] [SSH] 185.220.101.45:52341 → LOGIN ATTEMPT | u=root p=123456
[14:32:04] [SSH] 185.220.101.45:52341 → SHELL COMMAND | cmd=whoami
[14:32:04] [SSH] 185.220.101.45:52341 → SHELL COMMAND | cmd=cat /etc/passwd
[14:33:01] [HTTP] 185.220.101.45:51234 → LOGIN ATTEMPT | u=admin p=password
[14:33:02] [HTTP] 185.220.101.45:51234 → SENSITIVE FILE PROBE | path=/.env

[!] COORDINATED SCAN DETECTED
    185.220.101.45 hit 2 honeypot services: SSH, HTTP
    This indicates automated multi-service scanning.
```

JSON log format:
```json
{
  "timestamp": "2024-08-22T14:32:03.841234",
  "honeypot": "SSH",
  "source_ip": "185.220.101.45",
  "source_port": 52341,
  "event_type": "login_attempt",
  "details": {
    "username": "root",
    "password": "123456",
    "method": "password"
  }
}
```

---

## Log Analysis

```bash
python honeynet.py --analyze
```

```
=======================================================
HoneyNet Event Analysis — 1,247 total events
=======================================================

By Honeypot:
  SSH: 891
  HTTP: 312
  FTP: 44

By Event Type:
  login_attempt: 847
  connection: 234
  sensitive_file_probe: 98
  shell_command: 68

Top Source IPs:
  185.220.101.45: 312 events
  91.240.118.172: 187 events
  203.0.113.88: 143 events

Most Common Credentials Attempted:
  root:123456: 47x
  admin:admin: 38x
  root:root: 31x
  ubuntu:ubuntu: 28x
  root:password: 22x
```

---

## Deployment Notes

- Run behind a firewall — only expose the honeypot ports
- Use a cloud VPS (DigitalOcean, Linode, etc.) for maximum hit rate
- SSH honeypot runs on port 2222 by default (change to 22 on a VPS where you don't need real SSH)
- The HTTP honeypot on port 8080 can be put behind nginx on port 80
- Rotate and archive logs periodically

---

## MITRE ATT&CK Coverage

HoneyNet's decoys capture attacker behavior across these techniques. Every event in `logs/honeynet.json` is real adversary activity that maps to a documented technique — useful as both training data for detection rules and as evidence for threat intel reporting.

| Honeypot Activity | Tactic | Technique |
|---|---|---|
| SSH credential attempts | Credential Access | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) |
| FTP credential attempts | Credential Access | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) |
| HTTP login attempts | Credential Access | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) |
| Shell commands typed by attacker | Execution | [T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/) |
| `whoami`, `id` | Discovery | [T1033 — System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/) |
| `cat /etc/passwd`, account enumeration | Discovery | [T1087.001 — Local Account Discovery](https://attack.mitre.org/techniques/T1087/001/) |
| HTTP sensitive file probes (`.env`, `.git`) | Discovery | [T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) |
| Coordinated multi-service scanning | Reconnaissance | [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/) |

---

## Roadmap

- [ ] Email/Slack alerting on high-value events
- [ ] Threat intel integration (check IPs against abuse.ch)
- [ ] Web dashboard for log visualization
- [ ] MySQL/Telnet honeypot modules
- [ ] GeoIP enrichment

---

## License

MIT
