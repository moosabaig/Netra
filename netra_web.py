"""Netra web UI - local web server that serves the scanner page and runs scans.

Run:   python netra_web.py            then open http://127.0.0.1:8765
       python netra_web.py --port 9000

Binds to 127.0.0.1 only, so the scanner is not exposed to your network.
Standard library only.
"""

import argparse
import json
import socket
import threading
import time
import uuid
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netra_core import parse_ports, parse_targets, scan_port, service_name
from netra_ssl import ssl_scan
import netra_tools

try:
    import netra_report
except ImportError:  # fpdf2 not installed
    netra_report = None

MAX_CHECKS = 2_000_000  # targets x ports cap per job


class Job:
    def __init__(self, targets, ports, timeout, workers):
        self.id = uuid.uuid4().hex[:12]
        self.targets, self.ports = targets, ports
        self.timeout, self.workers = timeout, workers
        self.total = len(targets) * len(ports)
        self.done = 0
        self.open = []          # list of dicts
        self.log = []           # list of (level, text)
        self.finished = False
        self.stopped = False
        self.started = time.time()
        self.ended = None
        self.lock = threading.Lock()
        self.stop_flag = threading.Event()

    def add_log(self, level, text):
        with self.lock:
            self.log.append((level, text))

    def run(self):
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for host in self.targets:
                if self.stop_flag.is_set():
                    break
                try:
                    ip = socket.gethostbyname(host)
                except socket.gaierror as exc:
                    self.add_log("err", f"Cannot resolve {host}: {exc}")
                    with self.lock:
                        self.done += len(self.ports)
                    continue
                self.add_log("info", f"Starting scan for {host} ({ip}) - {len(self.ports)} port(s)")

                def task(port, host=host, ip=ip):
                    if not self.stop_flag.is_set():
                        try:
                            if scan_port(ip, port, self.timeout):
                                row = {"host": host, "ip": ip, "port": port, "service": service_name(port)}
                                with self.lock:
                                    self.open.append(row)
                                self.add_log("ok", f"{host}:{port} open {row['service']}")
                        except OSError as exc:
                            self.add_log("err", f"{ip}:{port} {exc}")
                    with self.lock:
                        self.done += 1

                list(pool.map(task, self.ports))
        with self.lock:
            self.stopped = self.stop_flag.is_set()
            self.finished = True
            self.ended = time.time()
        word = "Stopped" if self.stopped else "Done"
        self.add_log("info", f"{word}: {len(self.open)} open port(s) in {self.ended - self.started:.1f}s")

    def snapshot(self, open_since, log_since):
        with self.lock:
            end = self.ended or time.time()
            return {
                "id": self.id,
                "total": self.total,
                "done": self.done,
                "open_count": len(self.open),
                "open": self.open[open_since:],
                "log": self.log[log_since:],
                "finished": self.finished,
                "stopped": self.stopped,
                "elapsed": round(end - self.started, 1),
            }


class SslJob:
    def __init__(self, host, port, sni, engine):
        self.id = uuid.uuid4().hex[:12]
        self.args = (host, port, sni)
        self.engine = engine
        self.done, self.total, self.message = 0, 1, "Starting"
        self.result = None
        self.finished = False
        self.started = time.time()
        self.ended = None
        self.stop_flag = threading.Event()

    def progress(self, done, total, message):
        self.done, self.total, self.message = done, total, message

    def run(self):
        host, port, sni = self.args
        try:
            if self.engine == "sslscan":
                self.result = netra_tools.run_sslscan(host, port, sni, progress=self.progress, stop=self.stop_flag)
            elif self.engine == "testssl":
                self.result = netra_tools.run_testssl(host, port, sni, progress=self.progress, stop=self.stop_flag)
            else:
                self.result = ssl_scan(host, port, sni, netra_tools.CONNECT_TIMEOUT,
                                       progress=self.progress, stop=self.stop_flag)
                self.result.setdefault("engine", "builtin")
        except Exception as exc:  # report, never kill the server thread silently
            self.result = {"error": f"Scan failed: {exc}"}
        self.ended = time.time()
        self.finished = True

    def snapshot(self):
        end = self.ended or time.time()
        return {"id": self.id, "engine": self.engine, "done": self.done, "total": self.total, "message": self.message,
                "finished": self.finished, "stopped": self.stop_flag.is_set(),
                "elapsed": round(end - self.started, 1),
                "result": self.result if self.finished else None}


JOBS = {}
SSL_JOBS = {}
JOBS_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "Netra/1.0"

    def log_message(self, fmt, *args):  # keep console quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _job(self, job_id):
        with JOBS_LOCK:
            return JOBS.get(job_id)

    def _send_pdf(self, build, arg, name):
        if netra_report is None:
            return self._send(501, {"error": "PDF export needs fpdf2: pip install fpdf2"})
        try:
            data = build(arg)
        except Exception as exc:
            return self._send(500, {"error": f"Could not build PDF: {exc}"})
        stamp = time.strftime("%Y%m%d_%H%M")
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="{safe}_{stamp}.pdf"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path in ("/", "/index.html"):
            return self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        if path == "/api/engines":
            return self._send(200, netra_tools.engines())
        if path.startswith("/api/scan/") and path.endswith("/pdf"):
            job = self._job(path.split("/")[3])
            if not job:
                return self._send(404, {"error": "unknown scan"})
            return self._send_pdf(lambda j: netra_report.port_scan_pdf(j), job, "netra_ports")
        if path.startswith("/api/ssl/") and path.endswith("/pdf"):
            with JOBS_LOCK:
                job = SSL_JOBS.get(path.split("/")[3])
            if not job:
                return self._send(404, {"error": "unknown scan"})
            if not job.finished or not job.result or job.result.get("error"):
                return self._send(409, {"error": "SSL scan has no results yet."})
            r = job.result
            return self._send_pdf(lambda res: netra_report.ssl_scan_pdf(res), r, f"netra_ssl_{r['host']}_{r['port']}")
        if path.startswith("/api/ssl/"):
            with JOBS_LOCK:
                job = SSL_JOBS.get(path.rsplit("/", 1)[-1])
            if not job:
                return self._send(404, {"error": "unknown scan"})
            return self._send(200, json.loads(json.dumps(job.snapshot(), default=str)))
        if path.startswith("/api/scan/"):
            job = self._job(path.rsplit("/", 1)[-1])
            if not job:
                return self._send(404, {"error": "unknown scan"})
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            try:
                o, l = int(params.get("open", 0)), int(params.get("log", 0))
            except ValueError:
                o, l = 0, 0
            return self._send(200, job.snapshot(o, l))
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/api/scan":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                targets = parse_targets(str(body.get("targets", "")))
                ports = parse_ports(str(body.get("ports", "")))
                timeout = min(max(float(body.get("timeout", 0.5)), 0.05), 10)
                workers = min(max(int(body.get("workers", 200)), 1), 1000)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                return self._send(400, {"error": f"Invalid input: {exc}"})
            if not targets:
                return self._send(400, {"error": "Enter at least one target."})
            if not ports:
                return self._send(400, {"error": "Enter at least one port."})
            if len(targets) * len(ports) > MAX_CHECKS:
                return self._send(400, {"error": "Scan too large; reduce targets or ports."})
            job = Job(targets, ports, timeout, workers)
            with JOBS_LOCK:
                JOBS[job.id] = job
            threading.Thread(target=job.run, daemon=True).start()
            return self._send(200, {"id": job.id, "total": job.total})
        if path == "/api/ssl":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                host = str(body.get("host", "")).strip()
                port = int(body.get("port", 443))
                sni = str(body.get("sni", "") or "").strip() or None
                engine = str(body.get("engine", "builtin"))
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                return self._send(400, {"error": f"Invalid input: {exc}"})
            if not host:
                return self._send(400, {"error": "Enter a host or IP."})
            if not 1 <= port <= 65535:
                return self._send(400, {"error": "Port must be 1-65535."})
            avail = netra_tools.engines()
            if engine not in avail:
                return self._send(400, {"error": f"Unknown engine: {engine}"})
            if not avail[engine]["available"]:
                return self._send(400, {"error": f"{avail[engine]['label']} is not available. {avail[engine].get('hint') or ''}"})
            job = SslJob(host, port, sni, engine)
            with JOBS_LOCK:
                SSL_JOBS[job.id] = job
            threading.Thread(target=job.run, daemon=True).start()
            return self._send(200, {"id": job.id})
        if path.startswith("/api/ssl/") and path.endswith("/stop"):
            with JOBS_LOCK:
                job = SSL_JOBS.get(path.split("/")[3])
            if not job:
                return self._send(404, {"error": "unknown scan"})
            job.stop_flag.set()
            return self._send(200, {"ok": True})
        if path.startswith("/api/scan/") and path.endswith("/stop"):
            job = self._job(path.split("/")[3])
            if not job:
                return self._send(404, {"error": "unknown scan"})
            job.stop_flag.set()
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Netra Scanner</title>
<link rel="icon" href="data:,">
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e;
    --accent: #2f81f7; --accent-h: #1f6feb; --ok: #3fb950; --err: #f85149; --warn: #d29922;
    --input: #0d1117;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg: #f6f8fa; --panel: #ffffff; --border: #d0d7de; --text: #1f2328; --muted: #59636e;
            --input: #ffffff; --ok: #1a7f37; --err: #cf222e; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font: 14px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 24px 16px 48px; }
  header { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 4px; }
  h1 { font-size: 24px; margin: 0; letter-spacing: .3px; }
  h1 span { color: var(--accent); }
  .note { color: var(--warn); font-size: 13px; margin: 0 0 18px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px; }
  label { display: block; font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase;
          letter-spacing: .5px; margin-bottom: 6px; }
  input, select { width: 100%; background: var(--input); color: var(--text); border: 1px solid var(--border);
          border-radius: 6px; padding: 9px 11px; font: inherit; }
  input:focus, select:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
  .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 14px; }
  .grid3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; margin-top: 14px; }
  .field { min-width: 0; }
  .hint { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .actions { display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap; }
  button { font: inherit; font-weight: 600; border-radius: 6px; padding: 9px 16px; cursor: pointer;
           border: 1px solid var(--border); background: var(--panel); color: var(--text); }
  button:hover:not(:disabled) { border-color: var(--muted); }
  button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  button.primary:hover:not(:disabled) { background: var(--accent-h); }
  button.danger { color: var(--err); }
  button:disabled { opacity: .45; cursor: not-allowed; }
  .spacer { flex: 1; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 12px; }
  .stat .v { font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; }
  .stat .k { font-size: 12px; color: var(--muted); }
  .bar { height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; }
  .bar > div { height: 100%; width: 0; background: var(--accent); transition: width .2s; }
  .bar.done > div { background: var(--ok); }
  table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
  th { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; cursor: pointer; user-select: none; }
  th:hover { color: var(--text); }
  td.port { font-weight: 700; color: var(--ok); }
  .empty { color: var(--muted); text-align: center; padding: 24px; }
  .tablewrap { max-height: 360px; overflow: auto; }
  table.checks td:first-child { white-space: nowrap; }
  @media (max-width: 640px) { table.checks td:first-child { white-space: normal; } }
  pre { margin: 0; max-height: 200px; overflow: auto; font: 12px/1.5 Consolas, "Cascadia Mono", monospace;
        white-space: pre-wrap; word-break: break-word; }
  .l-ok { color: var(--ok); } .l-err { color: var(--err); } .l-info { color: var(--accent); }
  h2 { font-size: 14px; margin: 0 0 10px; }
  .error { color: var(--err); margin-top: 10px; min-height: 1em; }
  .errbox { margin-top: 14px; border: 1px solid var(--err); border-left-width: 4px; border-radius: 8px;
            padding: 12px 14px; color: var(--text); }
  .errbox .t { font-weight: 700; color: var(--err); margin-bottom: 4px; }
  .errbox .h { color: var(--muted); }
  .errbox button { margin-top: 10px; }
  .tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); margin-bottom: 16px; }
  .tab { background: none; border: none; border-bottom: 2px solid transparent; border-radius: 0;
         padding: 10px 14px; color: var(--muted); }
  .tab:hover:not(:disabled) { color: var(--text); }
  .tab[aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent); }
  [hidden] { display: none !important; }
  .mini { padding: 3px 10px; font-size: 12px; }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px; font-weight: 600;
           border: 1px solid currentColor; white-space: nowrap; }
  .b-strong, .b-enabled-good, .b-ok { color: var(--ok); }
  .b-medium, .b-enabled-warn { color: var(--warn); }
  .b-weak, .b-high, .b-enabled-bad { color: var(--err); }
  .b-low { color: var(--accent); }
  .b-info, .b-disabled, .b-untested { color: var(--muted); }
  .protos { display: flex; gap: 10px; flex-wrap: wrap; }
  .proto { border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; min-width: 120px; }
  .proto .n { font-weight: 700; margin-bottom: 4px; }
  .proto .d { font-size: 12px; color: var(--muted); margin-top: 4px; word-break: break-word; }
  .findings { list-style: none; margin: 0; padding: 0; }
  .findings li { display: flex; gap: 10px; align-items: baseline; padding: 7px 0; border-bottom: 1px solid var(--border); }
  .findings li:last-child { border-bottom: none; }
  .findings .badge { min-width: 70px; text-align: center; }
  dl.cert { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; }
  dl.cert dt { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .5px; padding-top: 2px; }
  dl.cert dd { margin: 0; word-break: break-all; }
  .muted { color: var(--muted); }
  .notes { font-size: 12px; color: var(--muted); margin: 10px 0 0; padding-left: 18px; }
  .sslgrid { display: grid; grid-template-columns: 2fr 1fr 2fr 1.4fr; gap: 14px; }
  details.adv { margin-top: 12px; }
  details.adv summary { cursor: pointer; color: var(--muted); font-size: 13px; }
  .grade { font-size: 30px; font-weight: 800; line-height: 1; }
  .rawout { max-height: 420px; }
  @media (max-width: 640px) {
    .sslgrid { grid-template-columns: 1fr 1fr; }
    dl.cert { grid-template-columns: 1fr; }
    .grid, .grid3 { grid-template-columns: 1fr; }
    .stats { grid-template-columns: 1fr 1fr; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header><h1><span>Netra</span> Scanner</h1></header>
  <p class="note">Only scan hosts you own or are authorized to test.</p>

  <nav class="tabs" role="tablist">
    <button class="tab" role="tab" id="tabbtn-ports" aria-selected="true" data-tab="ports">Port Scan</button>
    <button class="tab" role="tab" id="tabbtn-ssl" aria-selected="false" data-tab="ssl">SSL/TLS Scan</button>
  </nav>

  <div id="tab-ports">

  <form class="card" id="form">
    <div class="grid">
      <div class="field">
        <label for="targets">Target IPs / hosts</label>
        <input id="targets" placeholder="192.168.1.10, 192.168.1.20, example.com" value="127.0.0.1" autocomplete="off">
        <div class="hint">Separate multiple targets with commas or spaces.</div>
      </div>
      <div class="field">
        <label for="preset">Port preset</label>
        <select id="preset">
          <option value="">Custom</option>
          <option value="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080">Common (top 20)</option>
          <option value="1-1024" selected>Well-known (1-1024)</option>
          <option value="80,443,8000,8008,8080,8443,8888">Web</option>
          <option value="1-65535">All (1-65535)</option>
        </select>
      </div>
    </div>
    <div class="grid3" style="grid-template-columns: 1fr;">
      <div class="field">
        <label for="ports">Ports</label>
        <input id="ports" value="1-1024" autocomplete="off">
        <div class="hint">e.g. 22,80,443 or 1-1024</div>
      </div>
    </div>
    <details class="adv">
      <summary>Advanced</summary>
      <div class="grid3" style="grid-template-columns: 1fr 1fr;">
        <div class="field">
          <label for="timeout">Wait per port (s)</label>
          <input id="timeout" type="number" min="0.05" max="10" step="any" value="0.5">
        </div>
        <div class="field">
          <label for="workers">Threads</label>
          <input id="workers" type="number" min="1" max="1000" step="1" value="200">
        </div>
      </div>
    </details>
    <div class="actions">
      <button type="submit" class="primary" id="start">Start scan</button>
      <button type="button" class="danger" id="stop" disabled>Stop</button>
      <button type="button" id="clear">Clear</button>
      <span class="spacer"></span>
      <button type="button" id="export">Export CSV</button>
      <button type="button" id="pdf">Download PDF</button>
    </div>
    <div class="error" id="error"></div>
  </form>

  <section class="card">
    <div class="stats">
      <div class="stat"><div class="v" id="s-done">0</div><div class="k">Checked</div></div>
      <div class="stat"><div class="v" id="s-total">0</div><div class="k">Total</div></div>
      <div class="stat"><div class="v" id="s-open">0</div><div class="k">Open</div></div>
      <div class="stat"><div class="v" id="s-time">0.0s</div><div class="k" id="s-state">Idle</div></div>
    </div>
    <div class="bar" id="bar"><div></div></div>
  </section>

  <section class="card">
    <h2>Open ports</h2>
    <div class="tablewrap">
      <table>
        <thead><tr><th data-k="host">Host</th><th data-k="ip">IP</th><th data-k="port">Port</th><th data-k="service">Service</th><th></th></tr></thead>
        <tbody id="rows"><tr><td colspan="5" class="empty">No results yet. Enter an IP and start a scan.</td></tr></tbody>
      </table>
    </div>
  </section>

  <section class="card">
    <h2>Log</h2>
    <pre id="log"></pre>
  </section>
  </div>

  <div id="tab-ssl" hidden>
    <form class="card" id="sslform">
      <div class="sslgrid">
        <div class="field">
          <label for="ssl-host">Host / IP</label>
          <input id="ssl-host" placeholder="example.com or 10.0.0.5" autocomplete="off">
        </div>
        <div class="field">
          <label for="ssl-port">Port</label>
          <input id="ssl-port" type="number" min="1" max="65535" value="443">
        </div>
        <div class="field">
          <label for="ssl-sni">SNI (optional)</label>
          <input id="ssl-sni" placeholder="defaults to host name" autocomplete="off">
        </div>
        <div class="field">
          <label for="ssl-engine">Engine</label>
          <select id="ssl-engine">
            <option value="sslscan">sslscan</option>
            <option value="testssl">testssl.sh (thorough, slow)</option>
            <option value="builtin">Netra built-in</option>
          </select>
          <div class="hint" id="ssl-engine-hint"></div>
        </div>
      </div>
      <div class="actions">
        <button type="submit" class="primary" id="ssl-start">Start SSL scan</button>
        <button type="button" class="danger" id="ssl-stop" disabled>Stop</button>
        <span class="spacer"></span>
        <button type="button" id="ssl-export" disabled>Export JSON</button>
        <button type="button" id="ssl-pdf" disabled>Download PDF</button>
      </div>
      <div class="error" id="ssl-error"></div>
    </form>

    <section class="card" id="ssl-progress" hidden>
      <div class="stats" style="grid-template-columns: 1fr auto;">
        <div class="stat"><div class="v" id="ssl-msg" style="font-size:16px">Starting...</div><div class="k" id="ssl-target"></div></div>
        <div class="stat"><div class="v" id="ssl-time">0.0s</div><div class="k">Elapsed</div></div>
      </div>
      <div class="bar" id="ssl-bar"><div></div></div>
    </section>

    <div id="ssl-results" hidden>
      <section class="card">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
          <h2>Findings <span class="muted" id="ssl-engine-used"></span></h2>
          <div id="ssl-grade-box" hidden style="text-align:right">
            <div class="grade" id="ssl-grade"></div><div class="muted" style="font-size:12px">testssl.sh grade</div>
          </div>
        </div>
        <ul class="findings" id="ssl-findings"></ul>
        <ul class="notes" id="ssl-notes"></ul>
      </section>
      <section class="card">
        <h2>Protocols</h2>
        <div class="protos" id="ssl-protos"></div>
      </section>
      <section class="card">
        <h2>Accepted cipher suites <span class="muted" id="ssl-ccount"></span></h2>
        <div class="tablewrap">
          <table>
            <thead><tr><th>Protocol</th><th>Cipher</th><th>Bits</th><th>Key exchange</th><th>Rating</th></tr></thead>
            <tbody id="ssl-ciphers"></tbody>
          </table>
        </div>
      </section>
      <section class="card" id="ssl-checks-card" hidden>
        <h2>Vulnerability checks</h2>
        <div class="tablewrap" style="max-height:none">
          <table class="checks">
            <thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead>
            <tbody id="ssl-checks"></tbody>
          </table>
        </div>
      </section>
      <section class="card">
        <h2>Certificate</h2>
        <dl class="cert" id="ssl-cert"></dl>
      </section>
      <section class="card" id="ssl-raw-card" hidden>
        <details>
          <summary style="cursor:pointer"><strong>Raw tool output</strong></summary>
          <pre class="rawout" id="ssl-raw" style="margin-top:10px"></pre>
        </details>
      </section>
    </div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
let lastJob = null, job = null, openSeen = 0, logSeen = 0, results = [], timer = null, sortKey = null, sortDesc = false;

$("preset").onchange = e => { if (e.target.value) $("ports").value = e.target.value; };
// an invalid field inside the collapsed "Advanced" section would otherwise block submit silently
$("form").addEventListener("invalid", e => {
  const d = e.target.closest("details");
  if (d) d.open = true;
}, true);
$("ports").oninput = () => { $("preset").value = ""; };

function setRunning(on) {
  $("start").disabled = on; $("stop").disabled = !on;
  ["targets", "ports", "preset", "timeout", "workers"].forEach(id => $(id).disabled = on);
}

function addLog(level, text) {
  const line = document.createElement("div");
  line.className = "l-" + level;
  line.textContent = text;
  $("log").appendChild(line);
  $("log").scrollTop = $("log").scrollHeight;
}

function renderRows() {
  const body = $("rows");
  body.innerHTML = "";
  if (!results.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No open ports found yet.</td></tr>';
    return;
  }
  let rows = results.slice();
  if (sortKey) {
    rows.sort((a, b) => {
      const x = a[sortKey], y = b[sortKey];
      const c = typeof x === "number" ? x - y : String(x).localeCompare(String(y));
      return sortDesc ? -c : c;
    });
  }
  for (const r of rows) {
    const tr = document.createElement("tr");
    for (const k of ["host", "ip", "port", "service"]) {
      const td = document.createElement("td");
      td.textContent = r[k] || (k === "service" ? "-" : "");
      if (k === "port") td.className = "port";
      tr.appendChild(td);
    }
    const act = document.createElement("td");
    const btn = document.createElement("button");
    btn.type = "button"; btn.className = "mini"; btn.textContent = "SSL scan";
    btn.title = "Run an SSL/TLS scan on this port";
    btn.onclick = () => startSslFor(r.host, r.port);
    act.appendChild(btn); tr.appendChild(act);
    body.appendChild(tr);
  }
}

document.querySelectorAll("th[data-k]").forEach(th => th.onclick = () => {
  const k = th.dataset.k;
  sortDesc = sortKey === k ? !sortDesc : false;
  sortKey = k;
  renderRows();
});

function update(s) {
  $("s-done").textContent = s.done.toLocaleString();
  $("s-total").textContent = s.total.toLocaleString();
  $("s-open").textContent = s.open_count;
  $("s-time").textContent = s.elapsed.toFixed(1) + "s";
  $("s-state").textContent = s.finished ? (s.stopped ? "Stopped" : "Done") : "Scanning...";
  $("bar").firstElementChild.style.width = (s.total ? 100 * s.done / s.total : 0) + "%";
  $("bar").classList.toggle("done", s.finished);
  if (s.open.length) { results.push(...s.open); openSeen += s.open.length; renderRows(); }
  for (const [lvl, txt] of s.log) addLog(lvl, txt);
  logSeen += s.log.length;
}

async function poll() {
  if (!job) return;
  try {
    const r = await fetch(`/api/scan/${job}?open=${openSeen}&log=${logSeen}`);
    const s = await r.json();
    if (!r.ok) throw new Error(s.error || r.statusText);
    update(s);
    if (s.finished) { setRunning(false); job = null; return; }
  } catch (e) {
    $("error").textContent = "Lost connection to server: " + e.message;
    setRunning(false); job = null; return;
  }
  timer = setTimeout(poll, 300);
}

$("form").onsubmit = async e => {
  e.preventDefault();
  $("error").textContent = "";
  results = []; openSeen = 0; logSeen = 0; renderRows();
  const payload = {
    targets: $("targets").value, ports: $("ports").value,
    timeout: parseFloat($("timeout").value), workers: parseInt($("workers").value, 10),
  };
  try {
    const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const data = await r.json();
    if (!r.ok) { $("error").textContent = data.error || "Scan failed to start."; return; }
    job = data.id; lastJob = data.id; setRunning(true); poll();
  } catch (err) {
    $("error").textContent = "Cannot reach the Netra server. Is netra_web.py running?";
  }
};

$("stop").onclick = () => { if (job) fetch(`/api/scan/${job}/stop`, { method: "POST" }); $("s-state").textContent = "Stopping..."; };

$("clear").onclick = () => {
  if (job) return;
  results = []; lastJob = null; renderRows(); $("log").innerHTML = ""; $("error").textContent = "";
  ["s-done", "s-total", "s-open"].forEach(id => $(id).textContent = "0");
  $("s-time").textContent = "0.0s"; $("s-state").textContent = "Idle";
  $("bar").firstElementChild.style.width = "0"; $("bar").classList.remove("done");
};

$("export").onclick = () => {
  if (!results.length) { $("error").textContent = "No results to export."; return; }
  const esc = v => `"${String(v).replace(/"/g, '""')}"`;
  const csv = ["host,ip,port,service", ...results.map(r => [r.host, r.ip, r.port, r.service].map(esc).join(","))].join("\r\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = "netra_results.csv";
  a.click();
  URL.revokeObjectURL(a.href);
};

// ---------------- tabs
function showTab(name) {
  for (const t of ["ports", "ssl"]) {
    $("tab-" + t).hidden = t !== name;
    $("tabbtn-" + t).setAttribute("aria-selected", String(t === name));
  }
  try { localStorage.setItem("netra-tab", name); } catch (e) {}
}
document.querySelectorAll(".tab").forEach(b => b.onclick = () => showTab(b.dataset.tab));
try { if (localStorage.getItem("netra-tab") === "ssl") showTab("ssl"); } catch (e) {}

// ---------------- SSL/TLS scan
let sslJob = null, sslResult = null, lastSslJob = null;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}

function setSslRunning(on) {
  $("ssl-start").disabled = on; $("ssl-stop").disabled = !on;
  ["ssl-host", "ssl-port", "ssl-sni", "ssl-engine"].forEach(id => $(id).disabled = on);
}

function startSslFor(host, port) {
  showTab("ssl");
  if (sslJob) return;
  $("ssl-host").value = host; $("ssl-port").value = port; $("ssl-sni").value = "";
  $("sslform").requestSubmit();
}

$("sslform").onsubmit = async e => {
  e.preventDefault();
  $("ssl-error").textContent = "";
  $("ssl-results").hidden = true; $("ssl-export").disabled = true; $("ssl-pdf").disabled = true; sslResult = null;
  const payload = { host: $("ssl-host").value, port: parseInt($("ssl-port").value, 10),
                    sni: $("ssl-sni").value, engine: $("ssl-engine").value };
  try {
    const r = await fetch("/api/ssl", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const data = await r.json();
    if (!r.ok) { $("ssl-error").textContent = data.error || "Scan failed to start."; return; }
    sslJob = data.id; lastSslJob = data.id; setSslRunning(true);
    $("ssl-progress").hidden = false;
    $("ssl-target").textContent = payload.host + ":" + payload.port;
    $("ssl-bar").classList.remove("done");
    $("ssl-bar").firstElementChild.style.width = "0";
    pollSsl();
  } catch (err) {
    $("ssl-error").textContent = "Cannot reach the Netra server. Is netra_web.py running?";
  }
};

$("ssl-stop").onclick = () => {
  if (sslJob) fetch("/api/ssl/" + sslJob + "/stop", { method: "POST" });
  $("ssl-msg").textContent = "Stopping...";
};

async function pollSsl() {
  if (!sslJob) return;
  try {
    const r = await fetch("/api/ssl/" + sslJob);
    const s = await r.json();
    if (!r.ok) throw new Error(s.error || r.statusText);
    $("ssl-msg").textContent = s.finished ? (s.stopped ? "Stopped" : "Done") : s.message;
    $("ssl-time").textContent = s.elapsed.toFixed(1) + "s";
    $("ssl-bar").firstElementChild.style.width = (s.finished ? 100 : 100 * s.done / Math.max(1, s.total)) + "%";
    if (s.finished) {
      $("ssl-bar").classList.add("done");
      setSslRunning(false); sslJob = null;
      renderSsl(s.result);
      return;
    }
  } catch (e) {
    $("ssl-error").textContent = "Lost connection to server: " + e.message;
    setSslRunning(false); sslJob = null; return;
  }
  setTimeout(pollSsl, 400);
}

function renderSsl(r) {
  if (!r || r.error) { showSslError(r); return; }
  sslResult = r; $("ssl-export").disabled = false; $("ssl-pdf").disabled = false;
  $("ssl-results").hidden = false;
  const engineNames = { builtin: "Netra built-in", sslscan: "sslscan", testssl: "testssl.sh" };
  $("ssl-engine-used").textContent = "via " + (engineNames[r.engine] || r.engine || "Netra built-in");
  $("ssl-grade-box").hidden = !r.grade;
  $("ssl-grade").textContent = r.grade || "";
  if (r.grade) $("ssl-grade").className = "grade " + (/^A/.test(r.grade) ? "b-ok" : /^[BC]/.test(r.grade) ? "b-medium" : "b-high");

  const checks = r.checks || [];
  $("ssl-checks-card").hidden = !checks.length;
  const ck = $("ssl-checks"); ck.innerHTML = "";
  for (const c of checks) {
    const tr = el("tr");
    tr.appendChild(el("td", "", c.name));
    const res = el("td");
    const label = c.severity === "ok" ? "OK" : c.severity === "info" ? "INFO" : c.severity.toUpperCase();
    res.appendChild(el("span", "badge b-" + c.severity, label));
    tr.appendChild(res);
    tr.appendChild(el("td", "", c.finding || ""));
    ck.appendChild(tr);
  }
  $("ssl-raw-card").hidden = !r.raw;
  $("ssl-raw").textContent = r.raw || "";

  const fl = $("ssl-findings"); fl.innerHTML = "";
  for (const f of r.findings) {
    const li = el("li");
    li.appendChild(el("span", "badge b-" + f.severity, f.severity.toUpperCase()));
    li.appendChild(el("span", "", f.text));
    fl.appendChild(li);
  }
  const nl = $("ssl-notes"); nl.innerHTML = "";
  for (const n of r.notes) nl.appendChild(el("li", "", n));

  const pr = $("ssl-protos"); pr.innerHTML = "";
  const tone = { "SSLv3": "bad", "TLSv1.0": "warn", "TLSv1.1": "warn", "TLSv1.2": "good", "TLSv1.3": "good" };
  for (const p of r.protocols) {
    const box = el("div", "proto");
    box.appendChild(el("div", "n", p.name));
    const cls = p.status === "enabled" ? "b-enabled-" + tone[p.name] : "b-" + p.status;
    box.appendChild(el("span", "badge " + cls, p.status));
    if (p.cipher) box.appendChild(el("div", "d", p.cipher));
    else if (p.detail) box.appendChild(el("div", "d", p.detail));
    pr.appendChild(box);
  }

  const cb = $("ssl-ciphers"); cb.innerHTML = "";
  $("ssl-ccount").textContent = "(" + r.ciphers.length + ")";
  if (!r.ciphers.length) cb.innerHTML = '<tr><td colspan="5" class="empty">No cipher suites accepted.</td></tr>';
  for (const c of r.ciphers) {
    const tr = el("tr");
    tr.appendChild(el("td", "", c.protocol));
    tr.appendChild(el("td", "", c.name + (c.negotiated_only ? " *" : "")));
    tr.appendChild(el("td", "", c.bits == null ? "-" : c.bits));
    tr.appendChild(el("td", "", c.kx || "-"));
    const rt = el("td");
    rt.appendChild(el("span", "badge b-" + c.rating, c.rating));
    if (c.reasons.length) rt.appendChild(el("span", "muted", "  " + c.reasons.join(", ")));
    tr.appendChild(rt);
    cb.appendChild(tr);
  }

  const dl = $("ssl-cert"); dl.innerHTML = "";
  const add = (k, v, cls) => { dl.appendChild(el("dt", "", k)); dl.appendChild(el("dd", cls || "", v)); };
  const c = r.certificate;
  if (c) {
    add("Subject", c.subject_full || c.subject);
    add("Alt names", c.sans.length ? c.sans.join(", ") : "-");
    add("Issuer", c.issuer_full || c.issuer);
    add("Valid from", c.not_before);
    add("Valid until", c.not_after + "  (" + c.days_left + " days left)",
        c.days_left < 0 ? "b-high" : c.days_left < 30 ? "b-medium" : "");
    if (c.key_type) add("Public key", c.key_type + ", " + c.key_bits + " bits");
    if (c.signature) add("Signature", c.signature);
    add("Self-signed", c.self_signed ? "yes" : "no", c.self_signed ? "b-medium" : "");
    add("Serial", c.serial);
    if (c.sha256) add("SHA-256", c.sha256);
  } else {
    add("Certificate", "Not available");
  }
  if (r.verify) add("Trust", r.verify.message, r.verify.ok ? "b-ok" : r.verify.ok === false ? "b-high" : "muted");
  add("Compression", r.compression || "none");
}

$("ssl-export").onclick = () => {
  if (!sslResult) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(sslResult, null, 2)], { type: "application/json" }));
  a.download = "netra_ssl_" + sslResult.host + "_" + sslResult.port + ".json";
  a.click();
  URL.revokeObjectURL(a.href);
};

// ---------------- friendly SSL errors
const COMMON_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443";

function showSslError(r) {
  const box = $("ssl-error");
  box.innerHTML = "";
  const err = el("div", "errbox");
  err.appendChild(el("div", "t", (r && r.error) || "The scan failed."));
  if (r && r.error_hint) err.appendChild(el("div", "h", r.error_hint));
  const portScanKinds = ["timeout", "refused", "not_tls", "connect"];
  if (r && r.host && portScanKinds.includes(r.error_kind)) {
    const btn = el("button", "", "Port-scan " + r.host);
    btn.type = "button";
    btn.onclick = () => portScanHost(r.host, r.port);
    err.appendChild(btn);
  }
  box.appendChild(err);
}

function portScanHost(host, port) {
  if (job) { showTab("ports"); return; }
  showTab("ports");
  $("targets").value = host;
  const list = COMMON_PORTS.split(",");
  if (port && !list.includes(String(port))) list.push(String(port));
  $("ports").value = list.join(",");
  $("preset").value = "";
  $("form").requestSubmit();
}

// ---------------- engine availability
fetch("/api/engines").then(r => r.json()).then(av => {
  for (const opt of $("ssl-engine").options) {
    const e = av[opt.value];
    if (e && !e.available) { opt.disabled = true; opt.textContent += " - not installed"; }
    if (opt.value === "testssl" && e && e.available)
      opt.textContent = e.slow ? "testssl.sh (30-60 min)" : "testssl.sh (2-3 min)";
  }
  if ($("ssl-engine").selectedOptions[0].disabled) $("ssl-engine").value = "builtin";
  const showHint = () => {
    const e = av[$("ssl-engine").value];
    $("ssl-engine-hint").textContent = (e && e.hint) || "";
  };
  $("ssl-engine").addEventListener("change", showHint);
  showHint();
}).catch(() => {});

// ---------------- PDF download
async function downloadPdf(url, errorEl, button) {
  errorEl.textContent = "";
  const label = button.textContent;
  button.disabled = true; button.textContent = "Building PDF...";
  try {
    const r = await fetch(url);
    if (!r.ok) {
      let msg = r.statusText;
      try { msg = (await r.json()).error || msg; } catch (e) {}
      throw new Error(msg);
    }
    const name = (/filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "") || [])[1] || "netra_report.pdf";
    const a = document.createElement("a");
    a.href = URL.createObjectURL(await r.blob());
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  } catch (e) {
    errorEl.textContent = "PDF download failed: " + e.message;
  } finally {
    button.textContent = label; button.disabled = false;
  }
}

$("pdf").onclick = () => {
  if (!lastJob) { $("error").textContent = "Run a scan first."; return; }
  downloadPdf("/api/scan/" + lastJob + "/pdf", $("error"), $("pdf"));
};
$("ssl-pdf").onclick = () => {
  if (lastSslJob) downloadPdf("/api/ssl/" + lastSslJob + "/pdf", $("ssl-error"), $("ssl-pdf"));
};
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="Netra local web UI")
    ap.add_argument("--port", type=int, default=8765, help="HTTP port (default 8765)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    args = ap.parse_args()

    server = None
    for port in range(args.port, args.port + 20):  # skip ports Windows has reserved/blocked
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError as exc:
            print(f"Port {port} unavailable ({exc.strerror or exc}); trying next...")
    if server is None:
        raise SystemExit("No free port found; pass one with --port")
    url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"Netra web UI running at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
