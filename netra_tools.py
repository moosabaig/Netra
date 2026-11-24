"""Drive the real sslscan and testssl.sh tools and normalise their output into
the same result shape netra_ssl.ssl_scan() returns, so the web UI and PDF
report work with any engine.

Install the tools first:  python setup_tools.py
"""

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

from netra_ssl import build_findings, friendly_error, parse_cert, preflight, verify_chain

ROOT = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(ROOT, "tools")
SHIMS = os.path.join(ROOT, "tools_shims")
CONNECT_TIMEOUT = 10          # seconds per connection (fixed; not exposed in the UI)
SSLSCAN_MAX_RUNTIME = 10 * 60  # hard cap for a whole tool run
TESTSSL_MAX_RUNTIME = 30 * 60

WIN = sys.platform == "win32"
PROTO_NAMES = {("ssl", "2"): "SSLv2", ("ssl", "3"): "SSLv3", ("tls", "1.0"): "TLSv1.0",
               ("tls", "1.1"): "TLSv1.1", ("tls", "1.2"): "TLSv1.2", ("tls", "1.3"): "TLSv1.3"}
PROTO_ORDER = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


# ---------------------------------------------------------------- tool discovery

def sslscan_path():
    for cand in (os.path.join(TOOLS, "sslscan", "sslscan.exe" if WIN else "sslscan"), shutil.which("sslscan")):
        if cand and os.path.isfile(cand):
            return cand
    return None


def testssl_path():
    cand = os.path.join(TOOLS, "testssl.sh", "testssl.sh")
    if os.path.isfile(cand):
        return cand
    return shutil.which("testssl.sh") or shutil.which("testssl")


def bash_path():
    """Git Bash on Windows (NOT System32\\bash.exe, which is WSL); plain bash elsewhere."""
    if os.environ.get("NETRA_BASH"):
        return os.environ["NETRA_BASH"]
    if not WIN:
        return shutil.which("bash")
    roots = []
    git = shutil.which("git")
    if git:
        d = os.path.dirname(os.path.abspath(git))
        for _ in range(3):
            roots.append(d)
            d = os.path.dirname(d)
    roots += [r"C:\Program Files\Git", r"C:\Program Files (x86)\Git"]
    for r in roots:
        cand = os.path.join(r, "usr", "bin", "bash.exe")
        if os.path.isfile(cand):
            return cand
    return None


_WSL_CACHE = {}


def wsl_ready():
    """True when WSL has at least one Linux distro installed (testssl.sh runs ~20x faster there)."""
    if not WIN:
        return False
    now = time.time()
    if _WSL_CACHE and now - _WSL_CACHE["at"] < 60:
        return _WSL_CACHE["ok"]
    ok = False
    if shutil.which("wsl"):
        try:
            out = subprocess.run(["wsl", "-l", "-q"], capture_output=True, timeout=15,
                                 creationflags=subprocess.CREATE_NO_WINDOW).stdout
            names = out.decode("utf-16-le", "ignore").replace("\x00", "").split()
            ok = any(n.strip() for n in names)
        except (OSError, subprocess.SubprocessError):
            ok = False
    _WSL_CACHE.update(ok=ok, at=now)
    return ok


def to_wsl_path(path):
    path = os.path.abspath(path)
    drive, rest = os.path.splitdrive(path)
    return f"/mnt/{drive[0].lower()}{rest.replace(chr(92), '/')}" if drive else path.replace("\\", "/")


def testssl_mode():
    """'wsl' (fast), 'bash' (Linux/macOS or Git Bash - slow on Windows) or None."""
    if not testssl_path():
        return None
    if wsl_ready():
        return "wsl"
    return "bash" if bash_path() else None


def engines():
    """What the UI may offer."""
    mode = testssl_mode()
    if not testssl_path():
        t_hint = "Run: python setup_tools.py"
    elif mode is None:
        t_hint = "Install Git for Windows (Git Bash) or a WSL distro"
    elif mode == "bash" and WIN:
        t_hint = "Running under Git Bash: a full scan takes 30-60 min. Install WSL (wsl --install -d Ubuntu) for 2-3 min scans."
    else:
        t_hint = None
    return {
        "builtin": {"available": True, "label": "Netra built-in"},
        "sslscan": {"available": bool(sslscan_path()), "label": "sslscan",
                    "hint": None if sslscan_path() else "Run: python setup_tools.py"},
        "testssl": {"available": mode is not None, "label": "testssl.sh", "mode": mode,
                    "slow": mode == "bash" and WIN, "hint": t_hint},
    }


# ---------------------------------------------------------------- process runner

class ToolRun:
    """Run a command, stream its output lines to `on_line`, honour stop + max runtime."""

    def __init__(self, cmd, cwd=None, env=None, on_line=None, stop=None, max_runtime=600, on_kill=None):
        self.cmd, self.cwd, self.env = cmd, cwd, env
        self.on_kill = on_kill
        self.on_line = on_line or (lambda line: None)
        self.stop = stop or threading.Event()
        self.max_runtime = max_runtime
        self.lines = []
        self.killed_reason = None

    def _kill(self, proc):
        if proc.poll() is not None:
            return
        if WIN:  # kill the whole tree (bash -> openssl children)
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            proc.kill()
        if self.on_kill:
            try:
                self.on_kill()
            except Exception:
                pass

    def run(self):
        flags = subprocess.CREATE_NO_WINDOW if WIN else 0
        proc = subprocess.Popen(self.cmd, cwd=self.cwd, env=self.env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, creationflags=flags)
        started = time.time()

        def watchdog():
            while proc.poll() is None:
                if self.stop.is_set():
                    self.killed_reason = "stopped"
                    self._kill(proc)
                elif time.time() - started > self.max_runtime:
                    self.killed_reason = f"exceeded {self.max_runtime // 60} min limit"
                    self._kill(proc)
                time.sleep(0.3)

        threading.Thread(target=watchdog, daemon=True).start()
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").rstrip()
            self.lines.append(line)
            if line.strip():
                self.on_line(line)
        proc.wait()
        return proc.returncode

    @property
    def output(self):
        return "\n".join(self.lines)


def _empty_result(host, port, sni, engine):
    return {"host": host, "port": port, "sni": sni, "ip": None, "engine": engine, "protocols": [],
            "ciphers": [], "certificate": None, "verify": None, "compression": None, "findings": [],
            "checks": [], "notes": [], "error": None, "raw": "", "grade": None}


def _resolve(result):
    """Resolve and test-connect before launching a tool, so dead ports fail fast with a clear message."""
    ip, err = preflight(result["host"], result["port"], CONNECT_TIMEOUT)
    result["ip"] = ip
    if err:
        result.update(err)
        return False
    return True


def _cipher_traits(name, protocol):
    """Key exchange label + weakness reasons derived from an OpenSSL/IANA cipher name."""
    n = name.upper().replace("_", "-")
    if protocol == "TLSv1.3" or n.startswith("TLS-AES") or n.startswith("TLS-CHACHA"):
        return "any", True, []
    if n.startswith("ECDHE") or "-ECDHE-" in n or n.startswith("TLS-ECDHE"):
        kx = "ECDHE"
    elif n.startswith("DHE") or n.startswith("EDH") or n.startswith("TLS-DHE"):
        kx = "DHE"
    elif n.startswith("ADH") or n.startswith("AECDH") or "ANON" in n:
        kx = "anon"
    else:
        kx = "RSA"
    aead = any(t in n for t in ("GCM", "CHACHA20", "CCM"))
    reasons = []
    for tok, why in (("NULL", "NULL cipher"), ("EXP", "export grade"), ("RC4", "RC4"), ("DES-CBC3", "3DES"),
                     ("3DES", "3DES"), ("MD5", "MD5"), ("IDEA", "IDEA"), ("RC2", "RC2")):
        if tok in n and why not in reasons:
            reasons.append(why)
    if kx == "anon":
        reasons.append("no authentication")
    if kx == "RSA":
        reasons.append("no forward secrecy")
    if not aead and not reasons[:1] == ["NULL cipher"]:
        reasons.append("CBC mode")
    return kx, aead, reasons


def _rating_from_reasons(reasons):
    weak = {"NULL cipher", "export grade", "RC4", "3DES", "MD5", "IDEA", "RC2", "no authentication"}
    if any(r in weak for r in reasons):
        return "weak"
    return "medium" if reasons else "strong"


def _finish(result):
    order = {p: i for i, p in enumerate(PROTO_ORDER)}
    result["protocols"].sort(key=lambda p: order.get(p["name"], 99))
    result["ciphers"].sort(key=lambda c: (-order.get(c["protocol"], 0), not c.get("preferred"), -(c["bits"] or 0)))
    findings = build_findings(result)
    findings = [f for f in findings if f["severity"] != "info"]
    for chk in result["checks"]:
        if chk["severity"] in ("high", "medium", "low") and chk.get("finding"):
            findings.append({"severity": chk["severity"], "text": f"{chk['name']}: {chk['finding']}"})
    findings += result.pop("extra_findings", [])
    seen, unique = set(), []
    for f in findings:
        if f["text"] not in seen:
            seen.add(f["text"])
            unique.append(f)
    if not unique:
        unique.append({"severity": "info", "text": "No issues found."})
    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    unique.sort(key=lambda f: rank[f["severity"]])
    result["findings"] = unique
    return result


# ---------------------------------------------------------------- sslscan

def run_sslscan(host, port=443, sni=None, progress=None, stop=None):
    sni = (sni or "").strip() or None
    result = _empty_result(host, port, sni, "sslscan")
    exe = sslscan_path()
    if not exe:
        result["error"] = "sslscan is not installed. Run: python setup_tools.py"
        return result
    if not _resolve(result):
        return result

    fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="netra_sslscan_")
    os.close(fd)
    cmd = [exe, "--no-colour", "--show-certificate", f"--connect-timeout={CONNECT_TIMEOUT}",
           f"--timeout={CONNECT_TIMEOUT}", f"--xml={xml_path}"]
    if sni:
        cmd.append(f"--sni-name={sni}")
    cmd.append(f"[{host}]:{port}" if ":" in host else f"{host}:{port}")

    report = progress or (lambda d, t, m: None)
    state = {"n": 0}

    def on_line(line):
        state["n"] += 1
        report(min(state["n"], 95), 100, line.strip()[:120])

    run = ToolRun(cmd, on_line=on_line, stop=stop, max_runtime=SSLSCAN_MAX_RUNTIME)
    report(1, 100, "Starting sslscan")
    try:
        run.run()
        result["raw"] = run.output
        if run.killed_reason:
            result["error"] = f"sslscan {run.killed_reason}"
            return result
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            result["error"] = "sslscan produced no results. " + (run.output.strip().splitlines() or [""])[-1]
            return result
    finally:
        os.unlink(xml_path)

    test = tree.getroot().find("ssltest")
    err = tree.getroot().find("error")
    if test is None:
        detail = err.text.strip() if err is not None and err.text else ""
        result.update(friendly_error("timeout" if "Timed out" in detail else "connect", host, port,
                                     CONNECT_TIMEOUT, detail=detail))
        return result
    result["sni"] = test.get("sniname") or sni

    preferred = {}
    for c in test.findall("cipher"):
        proto = c.get("sslversion")
        kx, aead, reasons = _cipher_traits(c.get("cipher", ""), proto)
        strength = c.get("strength", "")
        rating = _rating_from_reasons(reasons)
        if strength in ("weak", "null", "anonymous", "insecure"):
            rating = "weak"
        if c.get("curve"):
            kx = f"{kx} {c.get('curve')}"
        elif c.get("dhebits"):
            kx = f"{kx} {c.get('dhebits')}-bit"
        is_pref = c.get("status") == "preferred"
        if is_pref:
            preferred[proto] = c.get("cipher")
        result["ciphers"].append({"protocol": proto, "name": c.get("cipher"), "bits": int(c.get("bits") or 0),
                                  "kx": kx, "aead": aead, "rating": rating, "reasons": reasons,
                                  "preferred": is_pref})

    for p in test.findall("protocol"):
        name = PROTO_NAMES.get((p.get("type"), p.get("version")), p.get("version"))
        on = p.get("enabled") == "1"
        result["protocols"].append({"name": name, "status": "enabled" if on else "disabled",
                                    "cipher": preferred.get(name), "detail": ""})

    checks = result["checks"]
    hb = [h.get("sslversion") for h in test.findall("heartbleed") if h.get("vulnerable") == "1"]
    checks.append({"id": "heartbleed", "name": "Heartbleed (CVE-2014-0160)",
                   "severity": "high" if hb else "ok",
                   "finding": f"Vulnerable to Heartbleed on {', '.join(hb)}" if hb else "Not vulnerable"})
    reneg = test.find("renegotiation")
    if reneg is not None:
        insecure = reneg.get("supported") == "1" and reneg.get("secure") != "1"
        checks.append({"id": "renegotiation", "name": "Secure renegotiation",
                       "severity": "medium" if insecure else "ok",
                       "finding": "Insecure session renegotiation supported" if insecure else
                       ("Secure renegotiation supported" if reneg.get("supported") == "1" else "Renegotiation not supported")})
    fb = test.find("fallback")
    if fb is not None:
        ok = fb.get("supported") == "1"
        checks.append({"id": "fallback_scsv", "name": "TLS_FALLBACK_SCSV (downgrade protection)",
                       "severity": "ok" if ok else "low",
                       "finding": "Supported" if ok else "TLS_FALLBACK_SCSV not supported (downgrade possible)"})
    comp = test.find("compression")
    if comp is not None:
        on = comp.get("supported") == "1"
        result["compression"] = "supported" if on else None
        checks.append({"id": "compression", "name": "TLS compression (CRIME)", "severity": "ok" if not on else "medium",
                       "finding": "Compression disabled" if not on else "TLS compression enabled (CRIME)"})
    groups = list(dict.fromkeys(g.get("name") for g in test.findall("group")))
    if groups:
        result["notes"].append("Key exchange groups: " + ", ".join(groups))

    blob = test.find("certificates/certificate/certificate-blob")
    if blob is not None and blob.text and "BEGIN CERTIFICATE" in blob.text:
        try:
            result["certificate"] = parse_cert(ssl.PEM_cert_to_DER_cert(blob.text.strip()))
        except Exception as exc:
            result["notes"].append(f"Could not parse certificate: {exc}")

    report(97, 100, "Verifying certificate chain")
    ok, msg = verify_chain(result["ip"], port, result["sni"] or host, CONNECT_TIMEOUT)
    result["verify"] = {"ok": ok, "message": msg}

    if not any(p["status"] == "enabled" for p in result["protocols"]):
        result.update(friendly_error("not_tls", host, port))
        return result
    report(100, 100, "Done")
    return _finish(result)


# ---------------------------------------------------------------- testssl.sh

TESTSSL_PROTOS = {"SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLS1": "TLSv1.0", "TLS1_1": "TLSv1.1",
                  "TLS1_2": "TLSv1.2", "TLS1_3": "TLSv1.3"}
TESTSSL_SEVERITY = {"OK": "ok", "INFO": "info", "LOW": "low", "MEDIUM": "medium", "HIGH": "high",
                    "CRITICAL": "high", "WARN": "info", "DEBUG": "info", "FATAL": "high"}
TESTSSL_VULNS = [
    ("heartbleed", "Heartbleed (CVE-2014-0160)"), ("CCS", "CCS injection (CVE-2014-0224)"),
    ("ticketbleed", "Ticketbleed (CVE-2016-9244)"), ("opossum", "Opossum"), ("ROBOT", "ROBOT"),
    ("secure_renego", "Secure renegotiation"), ("secure_client_renego", "Client-initiated renegotiation"),
    ("CRIME_TLS", "CRIME (TLS compression)"), ("BREACH", "BREACH (HTTP compression)"),
    ("POODLE_SSL", "POODLE (SSLv3)"), ("fallback_SCSV", "TLS_FALLBACK_SCSV"), ("SWEET32", "SWEET32 (64-bit ciphers)"),
    ("FREAK", "FREAK"), ("DROWN", "DROWN"), ("LOGJAM", "LOGJAM"), ("LOGJAM-common_primes", "LOGJAM common primes"),
    ("BEAST", "BEAST"), ("BEAST_CBC_TLS1", "BEAST (CBC on TLS 1.0)"), ("LUCKY13", "LUCKY13"),
    ("winshock", "Winshock (MS14-066)"), ("RC4", "RC4"),
]
# ids shown elsewhere (grade, protocols, cert dates duplicated by cert_expirationStatus)
TESTSSL_SKIP_IDS = {"overall_grade", "final_score", "cert_notAfter", "cert_notBefore", "scanTime",
                    "engine_problem", "optimal_proto"}
TESTSSL_LABELS = {
    "security_headers": ("No security headers", {"--": "none of X-Frame-Options, CSP, X-Content-Type-Options set"}),
    "HSTS": ("HSTS", {}),
    "DNS_CAArecord": ("DNS CAA record", {"--": "not set"}),
    "cert_expirationStatus": ("Certificate expiry", {}),
    "cert_keyUsage": ("Certificate key usage", {}),
    "cert_chain_of_trust": ("Certificate chain", {}),
    "cert_trust": ("Certificate name match", {}),
    "cert_crlDistributionPoints": ("Certificate CRL", {}),
    "cert_ocspURL": ("Certificate OCSP URL", {}),
    "OCSP_stapling": ("OCSP stapling", {}),
    "FS_TLS12_sig_algs": ("TLS 1.2 signature algorithms", {}),
    "FS_TLS13_sig_algs": ("TLS 1.3 signature algorithms", {}),
    "banner_server": ("Server banner", {}),
    "cookie_secure": ("Cookie Secure flag", {}),
    "cookie_httponly": ("Cookie HttpOnly flag", {}),
}


def _testssl_text(eid, finding):
    label, rewrites = TESTSSL_LABELS.get(eid, (eid, {}))
    return f"{label}: {rewrites.get(finding.strip(), finding)}"


# testssl prints these banners in order; used to estimate progress
TESTSSL_STAGES = ["Testing protocols", "Testing cipher categories", "Testing server's cipher preferences",
                  "forward secrecy", "Testing server defaults", "Testing HTTP header", "Testing vulnerabilities",
                  "Running client simulations", "Rating"]


def _bits_for(name):
    if name.startswith("TLS_"):  # TLS 1.3: key size is in the AES_xxx part, not the SHAxxx hash
        m = re.search(r"AES_(\d+)", name)
        return int(m.group(1)) if m else 256
    try:
        from netra_ssl import _ctx
        for c in _ctx().get_ciphers():
            if c["name"] == name:
                return c.get("strength_bits")
    except Exception:
        pass
    if "AES256" in name or "CHACHA20" in name or "CAMELLIA256" in name:
        return 256
    if "AES128" in name or "CAMELLIA128" in name or "SEED" in name:
        return 128
    if "DES-CBC3" in name:
        return 112
    return None


def _bash_env():
    env = os.environ.copy()
    extra = [SHIMS]
    bash = bash_path()
    if WIN and bash:
        git_root = os.path.dirname(os.path.dirname(os.path.dirname(bash)))  # ...\Git
        extra += [os.path.join(git_root, "usr", "bin"), os.path.join(git_root, "mingw64", "bin")]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    env["TERM"] = "dumb"
    return env


def _posix(path):
    return path.replace("\\", "/")


def run_testssl(host, port=443, sni=None, progress=None, stop=None):
    sni = (sni or "").strip() or None
    result = _empty_result(host, port, sni, "testssl")
    script, mode = testssl_path(), testssl_mode()
    if not script:
        result["error"] = "testssl.sh is not installed. Run: python setup_tools.py"
        return result
    if not mode:
        result["error"] = "testssl.sh needs bash (install Git for Windows or a WSL distro)."
        return result
    conv = to_wsl_path if mode == "wsl" else _posix
    if not _resolve(result):
        return result

    fd, json_path = tempfile.mkstemp(suffix=".json", prefix="netra_testssl_")
    os.close(fd)
    os.unlink(json_path)  # testssl refuses to overwrite an existing file
    target = f"{sni or host}:{port}"
    # All check groups except client simulation (-c), which adds ~100 handshakes and is very slow
    # under Git Bash: protocols, std cipher categories, server preference, forward secrecy,
    # server defaults (certificate), HTTP headers, vulnerabilities.
    args = [conv(script), "--quiet", "--color", "0", "--warnings", "batch",
            "-p", "-s", "-P", "-f", "-S", "-h", "-U",
            "--connect-timeout", str(CONNECT_TIMEOUT), "--jsonfile", conv(json_path)]
    if mode == "wsl":  # put the hexdump shim on PATH for minimal distros that lack it
        cmd = ["wsl", "-e", "env", f"PATH={to_wsl_path(SHIMS)}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
               "bash"] + args
    else:
        cmd = [bash_path()] + args
    # scan one IP only (testssl otherwise repeats the whole scan for every DNS record);
    # with an explicit SNI, connect to the given host's IP but present `sni` as server name
    cmd += ["--ip", result["ip"] if sni else "one"]
    cmd.append(target)
    result["sni"] = sni or (None if _is_ip(host) else host)  # testssl sends the target name as SNI

    report = progress or (lambda d, t, m: None)
    stage = {"i": 0}

    def on_line(line):
        for i, banner in enumerate(TESTSSL_STAGES):
            if banner in line and i + 1 > stage["i"]:
                stage["i"] = i + 1
        pct = 5 + int(90 * stage["i"] / len(TESTSSL_STAGES))
        report(pct, 100, line.strip()[:120])

    if mode == "wsl":
        run = ToolRun(cmd, on_line=on_line, stop=stop, max_runtime=TESTSSL_MAX_RUNTIME,
                      on_kill=lambda: subprocess.run(["wsl", "-e", "pkill", "-f", "testssl.sh"],
                                                     capture_output=True, timeout=15))
        report(2, 100, "Starting testssl.sh in WSL (about 2-3 minutes)")
    else:
        run = ToolRun(cmd, cwd=os.path.dirname(script), env=_bash_env(), on_line=on_line, stop=stop,
                      max_runtime=TESTSSL_MAX_RUNTIME)
        report(2, 100, "Starting testssl.sh" + (" under Git Bash (slow: 30-60 min)" if WIN else ""))
    try:
        run.run()
        result["raw"] = run.output
        if run.killed_reason:
            result["error"] = f"testssl.sh {run.killed_reason}"
            return result
        try:
            with open(json_path, encoding="utf-8") as fh:
                entries = json.load(fh)
        except (OSError, ValueError):
            tail = [ln for ln in run.output.splitlines() if ln.strip()][-3:]
            result["error"] = "testssl.sh produced no results. " + " ".join(tail)
            return result
    finally:
        if os.path.exists(json_path):
            os.unlink(json_path)

    by_id = {}
    for e in entries:
        by_id.setdefault(e.get("id", ""), e)

    fatal = [e for e in entries if e.get("severity") == "FATAL"]
    if fatal:
        result["error"] = "testssl.sh: " + fatal[0].get("finding", "fatal error")
        return result

    # protocols
    for tid, label in TESTSSL_PROTOS.items():
        e = by_id.get(tid)
        if not e:
            continue
        text = e.get("finding", "")
        on = "offered" in text and "not offered" not in text
        result["protocols"].append({"name": label, "status": "enabled" if on else "disabled",
                                    "cipher": None, "detail": "" if on else text})

    # ciphers: testssl lists accepted suites per protocol (server order when it has one)
    for e in entries:
        eid = e.get("id", "")
        for prefix in ("cipherorder_", "supportedciphers_"):
            if eid.startswith(prefix):
                proto = {"SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLSv1": "TLSv1.0", "TLSv1_1": "TLSv1.1",
                         "TLSv1_2": "TLSv1.2", "TLSv1_3": "TLSv1.3"}.get(eid[len(prefix):])
                if not proto:
                    continue
                names = e.get("finding", "").split()
                for i, name in enumerate(names):
                    kx, aead, reasons = _cipher_traits(name, proto)
                    result["ciphers"].append({"protocol": proto, "name": name, "bits": _bits_for(name), "kx": kx,
                                              "aead": aead, "rating": _rating_from_reasons(reasons),
                                              "reasons": reasons, "preferred": i == 0 and prefix == "cipherorder_"})
                for p in result["protocols"]:
                    if p["name"] == proto and names and not p["cipher"]:
                        p["cipher"] = names[0]
    seen = set()
    result["ciphers"] = [c for c in result["ciphers"]
                         if (c["protocol"], c["name"]) not in seen and not seen.add((c["protocol"], c["name"]))]

    # vulnerability checks
    for vid, label in TESTSSL_VULNS:
        e = by_id.get(vid)
        if e:
            sev = TESTSSL_SEVERITY.get(e.get("severity", "INFO"), "info")
            text = e.get("finding", "")
            if e.get("cve"):
                text += f"  [{e['cve']}]"
            result["checks"].append({"id": vid, "name": label, "severity": sev, "finding": text})

    # other testssl findings worth surfacing (headers, cert, etc.)
    skip = {v for v, _ in TESTSSL_VULNS} | set(TESTSSL_PROTOS) | TESTSSL_SKIP_IDS
    seen_text = set()
    for e in entries:
        eid = re.sub(r"\s*<hostCert#\d+>", "", e.get("id", ""))  # same finding per served cert
        sev = TESTSSL_SEVERITY.get(e.get("severity", "INFO"), "info")
        if eid in skip or eid.startswith(("cipher", "supportedciphers", "clientsimulation", "grade_cap")):
            continue
        if sev in ("high", "medium", "low"):
            text = _testssl_text(eid, e.get("finding", ""))
            if text not in seen_text:
                seen_text.add(text)
                result.setdefault("extra_findings", []).append({"severity": sev, "text": text})
    for e in entries:
        if e.get("id", "").startswith("grade_cap_reason"):
            note = "Grade cap: " + e.get("finding", "")
            if note not in result["notes"]:
                result["notes"].append(note)

    grade = by_id.get("overall_grade")
    result["grade"] = grade.get("finding") if grade else None
    comp = by_id.get("CRIME_TLS")
    result["compression"] = "supported" if comp and comp.get("severity") not in ("OK", "INFO") else None

    # certificate details + trust via a direct handshake (consistent across engines)
    report(97, 100, "Reading certificate")
    try:
        from netra_ssl import _ctx, _handshake
        hs = _handshake(result["ip"], port, sni or (None if _is_ip(host) else host), CONNECT_TIMEOUT, _ctx())
        result["certificate"] = parse_cert(hs["der"])
    except Exception as exc:
        result["notes"].append(f"Could not read certificate: {exc}")
    ok, msg = verify_chain(result["ip"], port, sni or host, CONNECT_TIMEOUT)
    result["verify"] = {"ok": ok, "message": msg}

    if not any(p["status"] == "enabled" for p in result["protocols"]):
        result.update(friendly_error("not_tls", host, port))
        return result
    report(100, 100, "Done")
    return _finish(result)


def _is_ip(host):
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return True
    except OSError:
        return False
