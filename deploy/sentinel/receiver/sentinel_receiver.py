#!/usr/bin/env python3
"""
Sentinel receiver + dashboard — the Pi-side endpoint for HoneyNet.

Runs on the tailnet only. Three jobs:
  * POST /honeynet  — receive writeup-worthy milestone alerts (append to JSONL)
  * POST /status    — receive periodic status heartbeats from the VPS watcher;
                      geolocate the attacker IPs (ip-api.com, cached)
  * GET  /          — live HTML dashboard: server liveness, whether it's still
                      collecting, event/IP/scan stats, and a world map of where
                      the attacks come from.

All bearer-token protected except the read-only GET dashboard, which relies on
the tailnet-only bind for access control. Stdlib only.

Config via environment (systemd loads it from /etc/sentinel-receiver.env):
    SENTINEL_TOKEN    required — must match the token the VPS watcher sends
    SENTINEL_BIND     default 100.87.221.5  (the Pi's tailnet IP; never 0.0.0.0)
    SENTINEL_PORT     default 8787
    SENTINEL_PATH     default /honeynet
    SENTINEL_LOG      default ~/sentinel/honeynet-alerts.jsonl
    SENTINEL_STATUS   default ~/sentinel/status.json
    SENTINEL_GEO      default ~/sentinel/geo-cache.json
    SENTINEL_STALE    default 1800  (seconds; older heartbeat => server STALE)
"""
import hmac
import ipaddress
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock

TOKEN = os.environ.get("SENTINEL_TOKEN", "")
BIND = os.environ.get("SENTINEL_BIND", "100.87.221.5")
PORT = int(os.environ.get("SENTINEL_PORT", "8787"))
PATH = os.environ.get("SENTINEL_PATH", "/honeynet")
LOG = Path(os.environ.get("SENTINEL_LOG", str(Path.home() / "sentinel" / "honeynet-alerts.jsonl")))
STATUS_FILE = Path(os.environ.get("SENTINEL_STATUS", str(Path.home() / "sentinel" / "status.json")))
GEO_CACHE = Path(os.environ.get("SENTINEL_GEO", str(Path.home() / "sentinel" / "geo-cache.json")))
STALE_SECS = int(os.environ.get("SENTINEL_STALE", "1800"))

_geo_lock = Lock()


def _authorized(header):
    if not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[len("Bearer "):], TOKEN)


def _load_json(path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def _save_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj))
    tmp.replace(path)


def geolocate(ips):
    """Resolve IPs -> {ip: {lat,lon,country,city,isp}} using ip-api.com, cached.

    Best-effort: failures leave the IP ungeolocated. Private/reserved IPs are
    skipped. Only IPs not already cached are queried (batched, <=100/request).
    """
    with _geo_lock:
        cache = _load_json(GEO_CACHE, {})
        todo = []
        for ip in ips:
            if ip in cache:
                continue
            try:
                if not ipaddress.ip_address(ip).is_global:
                    continue
            except ValueError:
                continue
            todo.append(ip)
        todo = todo[:100]  # ip-api batch cap
        if todo:
            try:
                body = json.dumps(todo).encode()
                url = "http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,isp,query"
                req = urllib.request.Request(url, data=body, method="POST",
                                             headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    for rec in json.loads(resp.read().decode()):
                        if rec.get("status") == "success":
                            cache[rec["query"]] = {
                                "lat": rec.get("lat"), "lon": rec.get("lon"),
                                "country": rec.get("country"), "cc": rec.get("countryCode"),
                                "city": rec.get("city"), "isp": rec.get("isp"),
                            }
                        else:
                            cache[rec.get("query", "?")] = {}  # negative cache
                _save_json(GEO_CACHE, cache)
            except Exception as e:
                print(f"[sentinel-receiver] geolocate failed: {e}", file=sys.stderr)
        return cache


def build_dashboard():
    """Render the dashboard HTML from the latest stored status + geo cache."""
    status = _load_json(STATUS_FILE, {})
    stats = status.get("stats", {})
    geo = _load_json(GEO_CACHE, {})
    now = time.time()

    def age(iso):
        # Timestamps from the VPS are UTC. New ones carry an explicit offset;
        # older log entries are naive — assume UTC for those so a naive value
        # isn't reinterpreted in the Pi's local zone (which would skew age by
        # the UTC<->local offset). now (time.time()) is already UTC epoch.
        if not iso:
            return None
        try:
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return now - dt.timestamp()
        except Exception:
            return None

    hb_age = age(status.get("sent_at"))
    ev_age = age(stats.get("last_event_ts"))
    online = hb_age is not None and hb_age < STALE_SECS
    collecting = ev_age is not None and ev_age < STALE_SECS

    # Build map points from geolocated top IPs.
    points = []
    for ip, count in stats.get("top_ips", []):
        g = geo.get(ip)
        if g and g.get("lat") is not None:
            points.append({"ip": ip, "n": count, "lat": g["lat"], "lon": g["lon"],
                           "country": g.get("country") or "?", "city": g.get("city") or "",
                           "isp": g.get("isp") or ""})

    data = {
        "online": online, "collecting": collecting,
        "hb_age": hb_age, "ev_age": ev_age,
        "stats": stats, "points": points, "geo": geo,
    }
    # Embed the data blob inside a <script>. Attacker-controlled strings could
    # otherwise break out of the script context (e.g. a username containing
    # "</script>"). Encode the HTML-significant chars as \uXXXX so the JSON
    # stays inert in script context; esc() handles the later innerHTML render.
    blob = (json.dumps(data)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))
    return _HTML.replace("__DATA__", blob).replace("__STALE__", str(STALE_SECS))


_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>HoneyNet Sentinel</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
 integrity="sha384-sHL9NAb7lN7rfvG5lfHpm643Xkcjzp4jFvuavGOndn6pjVqS6ny56CAt3nsEVT4H" crossorigin="anonymous"/>
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{margin:0;background:#0b0e14;color:#cdd6f4;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
  header{display:flex;align-items:center;gap:16px;padding:16px 22px;border-bottom:1px solid #1c2230;background:#0e1320}
  header h1{font-size:18px;margin:0;letter-spacing:.5px}
  .pill{padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}
  .ok{background:#16331f;color:#7ee787;border:1px solid #2ea04326}
  .bad{background:#3a1d1d;color:#ff7b72;border:1px solid #f8514926}
  .muted{color:#7783a1}
  .wrap{padding:18px 22px;max-width:1200px;margin:0 auto}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
  .card{background:#0e1320;border:1px solid #1c2230;border-radius:10px;padding:14px 16px}
  .card .k{font-size:12px;color:#7783a1;text-transform:uppercase;letter-spacing:.5px}
  .card .v{font-size:26px;font-weight:700;margin-top:4px}
  #map{height:420px;border-radius:12px;border:1px solid #1c2230;margin-bottom:18px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
  @media(max-width:760px){.grid2{grid-template-columns:1fr}}
  table{width:100%;border-collapse:collapse;background:#0e1320;border:1px solid #1c2230;border-radius:10px;overflow:hidden}
  th,td{text-align:left;padding:7px 12px;border-bottom:1px solid #161c28;font-size:13px}
  th{color:#7783a1;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.5px}
  tr:last-child td{border-bottom:0}
  td.n{text-align:right;color:#9ece6a}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:#7783a1;margin:0 0 8px}
  .leaflet-popup-content{font:13px ui-monospace,monospace}
</style></head>
<body>
<header>
  <h1>🛰 HoneyNet Sentinel</h1>
  <span id="serverPill" class="pill"></span>
  <span id="collectPill" class="pill"></span>
  <span class="muted" id="updated"></span>
</header>
<div class="wrap">
  <div class="cards" id="cards"></div>
  <div id="map"></div>
  <div class="grid2">
    <div><h2>Top source IPs</h2><table id="ips"></table></div>
    <div>
      <h2>By honeypot</h2><table id="hp"></table>
      <h2 style="margin-top:14px">Top credentials tried</h2><table id="creds"></table>
    </div>
  </div>
</div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
 integrity="sha384-cxOPjt7s7Iz04uaHJceBmS+qpjv2JkIHNVcuOrM+YHwZOmJGBXI00mdUXEq65HTH" crossorigin="anonymous"></script>
<script>
const D = __DATA__;
const s = D.stats || {};
// Honeypot data is ATTACKER-CONTROLLED (usernames, passwords, IPs). Escape
// everything before it touches innerHTML / popup HTML to prevent stored XSS.
const esc = v => String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = n => (n==null?'—':Number(n).toLocaleString());
const ago = sec => { if(sec==null) return 'never'; sec=Math.floor(sec);
  if(sec<90) return sec+'s ago'; if(sec<5400) return Math.round(sec/60)+'m ago';
  if(sec<172800) return Math.round(sec/3600)+'h ago'; return Math.round(sec/86400)+'d ago'; };

const sp=document.getElementById('serverPill');
sp.textContent = D.online?'SERVER ONLINE':'SERVER STALE'; sp.className='pill '+(D.online?'ok':'bad');
const cp=document.getElementById('collectPill');
cp.textContent = D.collecting?'COLLECTING':'NO RECENT EVENTS'; cp.className='pill '+(D.collecting?'ok':'bad');
document.getElementById('updated').textContent = 'heartbeat '+ago(D.hb_age)+' · last event '+ago(D.ev_age);

const cards=[['Total events',fmt(s.total_events)],['Unique attacker IPs',fmt(s.unique_ips)],
  ['Coordinated scans',fmt(s.coordinated_scans)],['Mapped origins',fmt((D.points||[]).length)]];
document.getElementById('cards').innerHTML = cards.map(c=>
  `<div class="card"><div class="k">${c[0]}</div><div class="v">${c[1]}</div></div>`).join('');

// rows() HTML-escapes every cell, so attacker-controlled strings are inert.
const rows=cols=>cols.map(r=>`<tr>${r.map((c,i)=>`<td class="${i?'n':''}">${esc(c)}</td>`).join('')}</tr>`).join('');
document.getElementById('ips').innerHTML='<tr><th>IP</th><th>Country</th><th class="n">Events</th></tr>'+
  rows((s.top_ips||[]).slice(0,15).map(([ip,n])=>{const g=(D.geo||{})[ip]||{};return [ip,(g.country||'—'),fmt(n)];}));
document.getElementById('hp').innerHTML='<tr><th>Service</th><th class="n">Events</th></tr>'+
  rows(Object.entries(s.by_honeypot||{}).sort((a,b)=>b[1]-a[1]).map(([k,v])=>[k,fmt(v)]));
document.getElementById('creds').innerHTML='<tr><th>username : password</th><th class="n">Tries</th></tr>'+
  rows((s.top_credentials||[]).slice(0,8).map(([c,n])=>[c,fmt(n)]));

const map=L.map('map',{worldCopyJump:true}).setView([20,0],2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
  {attribution:'© OpenStreetMap © CARTO',subdomains:'abcd',maxZoom:19}).addTo(map);
(D.points||[]).forEach(p=>{
  const r=Math.max(5,Math.min(26,6+Math.log(p.n+1)*4));
  L.circleMarker([p.lat,p.lon],{radius:r,color:'#f85149',weight:1,fillColor:'#f85149',fillOpacity:.45})
   .bindPopup(`<b>${esc(p.ip)}</b><br>${p.city?esc(p.city)+', ':''}${esc(p.country)}<br>${fmt(p.n)} events<br><span style="color:#7783a1">${esc(p.isp)}</span>`)
   .addTo(map);
});
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "sentinel/2.0"

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _read_json(self):
        n = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(n).decode() or "{}")

    def do_POST(self):
        route = self.path.rstrip("/")
        if route not in (PATH.rstrip("/"), "/status"):
            self._json(404, {"error": "not found"})
            return
        if not _authorized(self.headers.get("Authorization")):
            self._json(401, {"error": "unauthorized"})
            return
        try:
            payload = self._read_json()
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"error": "bad json"})
            return

        if route == "/status":
            payload["received_at"] = datetime.now(timezone.utc).isoformat()
            _save_json(STATUS_FILE, payload)
            ips = [ip for ip, _ in payload.get("stats", {}).get("top_ips", [])]
            geolocate(ips)
            print(f"[sentinel-receiver] status: events={payload.get('stats',{}).get('total_events')} "
                  f"ips={payload.get('stats',{}).get('unique_ips')}", flush=True)
            self._json(200, {"ok": True})
            return

        # milestone alert
        record = {"received_at": datetime.now(timezone.utc).isoformat(), "remote": self.client_address[0], **payload}
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(record) + "\n")
        print(f"\n🛰  HONEYNET ALERT [{record['received_at'][11:19]}] "
              f"{payload.get('milestone','?')}: {payload.get('reason','')}\n", flush=True)
        self._json(200, {"ok": True})

    def do_GET(self):
        route = self.path.split("?")[0].rstrip("/")
        if route in ("", "/dashboard"):
            self._html(build_dashboard())
        elif route == "/data.json":
            self._json(200, _load_json(STATUS_FILE, {}))
        elif route == "/health":
            self._json(200, {"ok": True, "service": "sentinel-receiver"})
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, *args):
        pass  # silence default per-request stderr logging; we print our own


def main():
    if not TOKEN:
        print("[sentinel-receiver] SENTINEL_TOKEN is required", file=sys.stderr)
        sys.exit(2)
    # The tailnet IP may not be assigned yet at boot — retry the bind briefly.
    deadline = time.time() + 60
    while True:
        try:
            httpd = ThreadingHTTPServer((BIND, PORT), Handler)
            break
        except OSError as e:
            if time.time() > deadline:
                print(f"[sentinel-receiver] could not bind {BIND}:{PORT}: {e}", file=sys.stderr)
                sys.exit(1)
            time.sleep(3)
    print(f"[sentinel-receiver] listening on http://{BIND}:{PORT}/  (dashboard at /)", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
