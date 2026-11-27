#!/usr/bin/env python3
"""Mi8 unified monitoring dashboard server (Python stdlib only).

Serves one page showing BOTH the Xray gateway proxy traffic AND AdGuard Home
stats. No pip dependencies, no root needed (listens on 8080).

Endpoints:
  GET /              -> dashboard HTML (index.html, same directory)
  GET /api/proxy     -> JSON: Xray status (TCP probe of 127.0.0.1:12346,
                        since Xray runs as root and pgrep can't see it),
                        last_activity (timestamp of the newest log line),
                        outbound nodes, recent connections parsed from
                        ~/xray/gw.log (last ~30 entries)
  GET /api/traffic?sub=<url-encoded-subscription-url>
  POST /api/traffic     -> JSON body {"sub": "..."}
                     Fetches the subscription URL and reads the
                     Subscription-Userinfo response header
                     (upload/download/total/expire). Returns
                     {"ok": true, "used_bytes": N, "total_bytes": N,
                      "remaining_bytes": N, "expire": <unix-ts or null>}
                     or {"ok": false, "error": "no_userinfo"} /
                     {"ok": false, "error": "fetch_failed"}.
                     The server never logs or stores the subscription URL.
  GET /api/agh?u=<user>&p=<pass>
  POST /api/agh      -> JSON body {"u": ..., "p": ...}
                     Proxies to AGH /control/stats + /control/query_log with
                     HTTP Basic Auth using the supplied credentials, and
                     NORMALIZES the response (AGH's shapes vary: scalar
                     stats may arrive as per-interval arrays, top domains
                     as object maps or [domain, count] pairs). Returns
                     {"stats": {"total", "blocked", "blocked_pct",
                     "top_blocked": [{domain, count}],
                     "top_queried": [{domain, count}]},
                     "query_log": {"entries": [{time, client, domain,
                     "blocked": bool}]}}.
                     The server never stores any password.
                     On failure returns {"error": "agh_unreachable"} or
                     {"error": "agh_auth_failed"} with HTTP 200.
  GET /api/version   -> {"version": VERSION}
  POST /api/update   -> downloads the latest server.py + index.html from
                     the public GitHub repo (see GH_RAW_BASE below),
                     validates them (markers + valid Python), replaces
                     the live files, then restarts itself with execv.
                     Returns {"ok": true, "version": "<new>"}
                     (+ "already_latest": true if unchanged) or
                     {"ok": false, "error": "fetch_failed"} /
                     {"ok": false, "error": "download_invalid"}.

Run on the Mi8 (Termux):
  python3 ~/mi8-dashboard/server.py
Then open http://192.168.5.200:8080 in a browser on the LAN.
"""
import base64
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.3.0"

# Public GitHub repo holding the latest dashboard files (no secrets).
# The parent creates repo ZhangAnAn0106/mi8-dashboard (branch main) and
# pushes server.py + index.html there; the panel updates itself from it.
GH_RAW_BASE = "https://raw.githubusercontent.com/ZhangAnAn0106/ad-dns-rules/main/mi8-dashboard"
GH_SERVER_URL = GH_RAW_BASE + "/server.py"
GH_INDEX_URL = GH_RAW_BASE + "/index.html"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_HTML = os.path.join(BASE_DIR, "index.html")
GW_LOG = os.path.expanduser("~/xray/gw.log")
AGH_BASE = "http://127.0.0.1:18080"

NODES = [
    {"tag": "日本-AWS01", "host": "pq.aws48.yydjc.top:443", "proto": "VLESS + Reality"},
    {"tag": "日本-东京02", "host": "unamecf.xn--ghqu5fm27b67w.com:443", "proto": "VLESS + WS + TLS"},
]

# --- gw.log parsing -------------------------------------------------------

TS_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
SRC_RE = re.compile(r"from (\d+\.\d+\.\d+\.\d+):\d+")
DOMAIN_RE = re.compile(r"tcp:([A-Za-z0-9_.\-]+):\d+")
IP_RE = re.compile(r"tcp:(\d+\.\d+\.\d+\.\d+):\d+")


def parse_log_line(line):
    """Parse one gw.log line into a connection entry, or None if not useful."""
    m = TS_RE.search(line)
    ts = m.group(1) if m else ""
    src = ""
    sm = SRC_RE.search(line)
    if sm:
        src = sm.group(1)

    # Outbound tunneling lines: most informative (domain + exit node).
    if "tunneling request" in line:
        dm = DOMAIN_RE.search(line)
        domain = dm.group(1) if dm else ""
        if "pq.aws48" in line:
            route = "日本-AWS01"
        elif "unamecf" in line:
            route = "日本-东京02"
        else:
            route = "日本"
        if not domain:
            return None
        return {"time": ts, "src": src, "domain": domain, "route": route}

    # Dispatcher detour lines: domain + route.
    if "taking detour" in line:
        dm = DOMAIN_RE.search(line)
        domain = dm.group(1) if dm else ""
        if not domain:
            return None
        if "[direct]" in line:
            route = "直连"
        elif "[blocked]" in line or "blocked" in line:
            route = "拦截"
        else:
            route = "直连"
        return {"time": ts, "src": src, "domain": domain, "route": route}

    # Accepted-connection lines: source IP + route, no domain (fallback).
    if "accepted tcp:" in line and "[gateway-transparent" in line:
        im = IP_RE.search(line)
        ip = im.group(1) if im else ""
        if not ip:
            return None
        if "-> direct" in line:
            route = "直连"
        elif "-> blocked" in line:
            route = "拦截"
        else:
            route = "直连"
        return {"time": ts, "src": src, "domain": ip, "route": route}

    return None


def probe_xray():
    """Check whether the gateway Xray is listening on 127.0.0.1:12346.

    The dashboard runs as the plain Termux user while the gateway Xray
    runs as root, so a pgrep/ps check cannot see the root process and
    falsely reports it as stopped. A TCP connect probe works regardless
    of which user owns the process.
    """
    try:
        with socket.create_connection(("127.0.0.1", 12346), timeout=1):
            return True
    except OSError:
        return False


def read_proxy():
    """Return proxy status + recent connections parsed from gw.log."""
    running = probe_xray()

    entries = []
    try:
        with open(GW_LOG, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []
    except Exception:
        lines = []

    # Newest first; stop once we have enough entries.
    for line in reversed(lines[-2000:]):
        try:
            e = parse_log_line(line)
        except Exception:
            e = None
        if e is not None:
            entries.append(e)
            if len(entries) >= 30:
                break
    entries.reverse()

    counts = {"直连": 0, "日本-AWS01": 0, "日本-东京02": 0, "日本": 0, "拦截": 0}
    for e in entries:
        if e["route"] in counts:
            counts[e["route"]] += 1
    last_activity = ""
    for line in reversed(lines):
        m = TS_RE.search(line)
        if m:
            last_activity = m.group(1)
            break
    return {
        "xray_running": running,
        "nodes": NODES,
        "entries": entries,
        "counts": counts,
        "log_lines": len(lines),
        "last_activity": last_activity,
    }


# --- AGH proxy ------------------------------------------------------------

def agh_get(path, user, password):
    """GET one AGH control endpoint with Basic Auth. Returns parsed JSON."""
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    req = urllib.request.Request(
        AGH_BASE + path,
        headers={"Authorization": "Basic " + token},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)


# --- AGH response normalization -------------------------------------------
# AGH v1.0.0's /control/stats is inconsistent about shapes, and the exact
# shape varies: dns_queries / blocked_filtering are per-interval ARRAYS of
# numbers in the real response (the total is their sum), while other
# builds expose them as scalars; top_* domains come back as object maps
# (domain -> count) or as arrays of [domain, count] pairs. The old
# frontend rendered an array as a number (comma-joined garbage) and
# called .slice() on an object (empty rows). Normalize server-side into
# one clean contract so the frontend only has to display it.

def _num_or_none(v):
    """Return v if it is a finite non-bool number, else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)) and v == v and abs(v) != float("inf"):
        return v
    return None


def _sum_stat(v):
    """Sum a stat that may be a scalar, an array of numbers, or an
    object map of numbers. Returns None if nothing usable is present."""
    n = _num_or_none(v)
    if n is not None:
        return n
    if isinstance(v, list):
        total = 0
        ok = False
        for x in v:
            xn = _num_or_none(x)
            if xn is not None:
                total += xn
                ok = True
        return total if ok else None
    if isinstance(v, dict):
        total = 0
        ok = False
        for x in v.values():
            xn = _num_or_none(x)
            if xn is not None:
                total += xn
                ok = True
        return total if ok else None
    return None


def _top_domains(v):
    """Normalize top domains into [{domain, count}] sorted desc, top 10.
    Accepts an object map, an array of [domain, count] pairs, or an
    array of {domain|name, count} objects."""
    pairs = []
    if isinstance(v, dict):
        for k, c in v.items():
            cn = _num_or_none(c)
            pairs.append({"domain": str(k), "count": cn if cn is not None else 0})
    elif isinstance(v, list):
        for item in v:
            if isinstance(item, list) and len(item) >= 2:
                cn = _num_or_none(item[1])
                pairs.append({"domain": str(item[0]), "count": cn if cn is not None else 0})
            elif isinstance(item, dict):
                d = item.get("domain") or item.get("name") or item.get("key") or ""
                c = item.get("count")
                if c is None:
                    c = item.get("value")
                cn = _num_or_none(c)
                if d:
                    pairs.append({"domain": str(d), "count": cn if cn is not None else 0})
            elif isinstance(item, str) and item:
                pairs.append({"domain": item, "count": 0})
    pairs.sort(key=lambda p: p["count"], reverse=True)
    return pairs[:10]


def _fmt_qtime(raw):
    """Format a query-log time (RFC3339 string or epoch number)."""
    if isinstance(raw, str) and raw:
        s = raw.replace("T", " ").replace("Z", "+00:00")
        # Strip the timezone suffix for display: "2026-11-27 15:00:25"
        return s[:19]
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        import datetime
        ts = raw / 1000.0 if raw > 1e12 else raw
        try:
            return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""
    return ""


def _q_blocked(q):
    """True if a query-log entry was blocked by a filter."""
    if isinstance(q.get("blocked"), bool):
        return q["blocked"]
    reason = str(q.get("reason") or "").lower()
    status = str(q.get("status") or "").lower()
    if reason.startswith("filtered") or status.startswith("filtered"):
        return True
    if reason.startswith("notfiltered") or reason.startswith("rewritten"):
        return False
    if "filtered" in status:
        return True
    if status in ("allowed", "ok", "success"):
        return False
    return False


def _norm_stats(stats):
    """Normalize /control/stats into a clean dict."""
    if not isinstance(stats, dict):
        return {"total": None, "blocked": None, "blocked_pct": None,
                "top_blocked": [], "top_queried": []}
    total = _sum_stat(stats.get("dns_queries"))
    blocked = _sum_stat(stats.get("blocked_filtering"))
    pct = _num_or_none(stats.get("blocked_percentage"))
    if pct is None and total and blocked is not None and total > 0:
        pct = round(blocked / total * 100, 1)
    return {
        "total": total,
        "blocked": blocked,
        "blocked_pct": pct,
        "top_blocked": _top_domains(stats.get("top_blocked_domains")),
        "top_queried": _top_domains(stats.get("top_queried_domains")),
    }


def _norm_query_log(qlog):
    """Normalize /control/query_log into [{time, client, domain, blocked}]."""
    data = None
    if isinstance(qlog, dict):
        data = qlog.get("data") or qlog.get("entries") or qlog.get("logs")
    elif isinstance(qlog, list):
        data = qlog
    if not isinstance(data, list):
        return []
    entries = []
    for q in data[:30]:
        if not isinstance(q, dict):
            continue
        question = q.get("question") if isinstance(q.get("question"), dict) else {}
        domain = (question.get("name") or question.get("domain")
                  or q.get("domain") or q.get("name") or "")
        client = q.get("client") or q.get("client_id") or q.get("client_name") or ""
        entries.append({
            "time": _fmt_qtime(q.get("time")),
            "client": str(client),
            "domain": str(domain),
            "blocked": _q_blocked(q),
        })
    return entries


def read_agh(user, password):
    """Fetch AGH stats + recent query log, normalized. Returns a dict
    {"stats": {...}, "query_log": {"entries": [...]}} or {"error": ...}."""
    try:
        stats = agh_get("/control/stats", user, password)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"error": "agh_auth_failed"}
        return {"error": "agh_unreachable"}
    except Exception:
        return {"error": "agh_unreachable"}
    # Query log: try with limit first, fall back to the bare endpoint.
    qlog = None
    for path in ("/control/query_log?limit=30", "/control/query_log"):
        try:
            qlog = agh_get(path, user, password)
            break
        except Exception:
            continue
    if qlog is None:
        qlog = {"data": []}
    return {"stats": _norm_stats(stats), "query_log": {"entries": _norm_query_log(qlog)}}



# --- Subscription traffic ---------------------------------------------------

USERINFO_RE = re.compile(r"(\w+)\s*=\s*(\d+)")
TRAFFIC_UA = (
    "Mozilla/5.0 (Linux; Android 14; Mi 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
)


def read_traffic(sub_url):
    """Fetch a subscription URL and parse its Subscription-Userinfo header.

    Returns {"ok": True, "used_bytes": N, "total_bytes": N,
             "remaining_bytes": N, "expire": <unix-ts or null>}
    or {"ok": False, "error": "no_userinfo"} / {"ok": False, "error":
    "fetch_failed"}. The subscription URL is never logged or stored.
    """
    if not sub_url or not sub_url.startswith(("http://", "https://")):
        return {"ok": False, "error": "fetch_failed"}
    req = urllib.request.Request(sub_url, headers={"User-Agent": TRAFFIC_UA})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            header = resp.headers.get("Subscription-Userinfo") or ""
    except Exception:
        return {"ok": False, "error": "fetch_failed"}
    info = dict((k, int(v)) for k, v in USERINFO_RE.findall(header))
    total = info.get("total")
    if not total:
        return {"ok": False, "error": "no_userinfo"}
    used = info.get("upload", 0) + info.get("download", 0)
    expire = info.get("expire") or None
    return {
        "ok": True,
        "used_bytes": used,
        "total_bytes": total,
        "remaining_bytes": max(total - used, 0),
        "expire": expire,
    }


# --- Self-update ----------------------------------------------------------
# The panel updates itself from the public GitHub repo
# ZhangAnAn0106/mi8-dashboard (branch main). No secrets involved: both
# files are public. The update downloads to temp files, validates them
# (expected markers + valid Python), replaces the live files, then the
# server restarts itself with os.execv so the new code takes over.

UPDATE_UA = (
    "Mozilla/5.0 (Linux; Android 14; Mi 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
)
VERSION_RE = re.compile(r'^\s*VERSION\s*=\s*["\']([^"\']+)["\']', re.M)


def _download(url, dest):
    """Download url to dest. Returns True on success, False on any error."""
    req = urllib.request.Request(url, headers={"User-Agent": UPDATE_UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
    except Exception:
        return False
    try:
        with open(dest, "wb") as f:
            f.write(data)
    except Exception:
        return False
    return True


def _valid_server_py(path):
    """Check a downloaded server.py: non-empty, has markers, valid Python."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception:
        return False
    if not text.strip():
        return False
    if "VERSION =" not in text:
        return False
    if "mi8-dashboard" not in text and "8080" not in text:
        return False
    try:
        compile(text, path, "exec")
    except SyntaxError:
        return False
    return True


def _valid_index_html(path):
    """Check a downloaded index.html: non-empty, has expected markers."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception:
        return False
    if not text.strip():
        return False
    return "小米8" in text and "监控面板" in text


def _extract_version(path):
    """Read the VERSION = "..." line out of a downloaded server.py."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception:
        return None
    m = VERSION_RE.search(text)
    return m.group(1) if m else None


def do_update():
    """Download the latest files, validate, replace, report.

    Returns (payload, new_version_or_None). The caller must send the
    payload as the HTTP response, flush it, and then restart the process
    (os.execv) if new_version is not None — the response has to reach
    the browser before the process is replaced.
    """
    tmp_server = os.path.join(BASE_DIR, "server.py.new")
    tmp_index = os.path.join(BASE_DIR, "index.html.new")
    try:
        if not _download(GH_SERVER_URL, tmp_server):
            return {"ok": False, "error": "fetch_failed"}, None
        if not _download(GH_INDEX_URL, tmp_index):
            return {"ok": False, "error": "fetch_failed"}, None
        if not _valid_server_py(tmp_server) or not _valid_index_html(tmp_index):
            return {"ok": False, "error": "download_invalid"}, None
        new_version = _extract_version(tmp_server) or VERSION
        payload = {"ok": True, "version": new_version}
        if new_version == VERSION:
            payload["already_latest"] = True
        os.replace(tmp_server, os.path.join(BASE_DIR, "server.py"))
        os.replace(tmp_index, INDEX_HTML)
        return payload, new_version
    finally:
        for p in (tmp_server, tmp_index):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass


# --- HTTP server ----------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep the console quiet

    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self):
        try:
            with open(INDEX_HTML, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            body = b"<h1>index.html not found</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index.html"):
            self._send_html()
            return
        if self.path == "/api/version":
            self._send_json({"version": VERSION})
            return
        if self.path == "/api/proxy":
            self._send_json(read_proxy())
            return
        if self.path.startswith("/api/traffic"):
            # Subscription URL via query string: ?sub=<url-encoded>
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            sub = (qs.get("sub") or [""])[0]
            if not sub:
                self._send_json({"ok": False, "error": "fetch_failed"})
                return
            self._send_json(read_traffic(sub))
            return
        if self.path.startswith("/api/agh"):
            # Credentials via query string: ?u=admin&p=...
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            user = (qs.get("u") or [""])[0]
            password = (qs.get("p") or [""])[0]
            if not user or not password:
                self._send_json({"error": "agh_auth_failed"})
                return
            self._send_json(read_agh(user, password))
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path == "/api/update":
            payload, new_version = do_update()
            self._send_json(payload)
            try:
                self.wfile.flush()
            except Exception:
                pass
            if new_version is not None:
                # Give the response a moment to reach the browser, then
                # replace this process with the freshly downloaded code.
                try:
                    time.sleep(0.5)
                except Exception:
                    pass
                try:
                    os.execv(sys.executable,
                             [sys.executable, os.path.join(BASE_DIR, "server.py")])
                except Exception:
                    pass
            return
        if self.path == "/api/traffic":
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                data = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                data = {}
            sub = data.get("sub", "")
            if not sub:
                self._send_json({"ok": False, "error": "fetch_failed"})
                return
            self._send_json(read_traffic(sub))
            return
        if self.path == "/api/agh":
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                data = json.loads(raw.decode("utf-8") or "{}")
            except Exception:
                data = {}
            user = data.get("u", "")
            password = data.get("p", "")
            if not user or not password:
                self._send_json({"error": "agh_auth_failed"})
                return
            self._send_json(read_agh(user, password))
            return
        self.send_response(404)
        self.end_headers()


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    print("Mi8 dashboard listening on http://0.0.0.0:8080")
    print("Open http://192.168.5.200:8080 in a browser on the LAN.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
