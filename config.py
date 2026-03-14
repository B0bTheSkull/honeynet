"""Config loader for HoneyNet."""
import yaml
from pathlib import Path

DEFAULTS = {
    "log_file": "logs/honeynet.json",
    "honeypots": {
        "ssh": {"enabled": True, "port": 2222, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
        "http": {"enabled": True, "port": 8080, "title": "Admin Panel"},
        "ftp": {"enabled": True, "port": 2121, "banner": "220 FTP Server Ready"},
    },
    "alerts": {
        "multi_service_window": 60
    }
}


def load_config(path="config.yaml"):
    p = Path(path)
    if p.exists():
        with open(p) as f:
            user_cfg = yaml.safe_load(f) or {}
        cfg = DEFAULTS.copy()
        for k, v in user_cfg.items():
            if isinstance(v, dict) and k in cfg:
                cfg[k] = {**cfg[k], **v}
            else:
                cfg[k] = v
        return cfg
    return DEFAULTS.copy()
