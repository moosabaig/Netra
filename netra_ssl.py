"""Netra SSL/TLS scanner (sslscan-style), pure Python.

Checks which protocol versions a server accepts, enumerates accepted cipher
suites (SSLv3 - TLS 1.2), inspects the certificate, and lists findings.

CLI:
    python netra_ssl.py example.com
    python netra_ssl.py 10.0.0.5:8443 --sni intranet.local
    python netra_ssl.py example.com --json

Limitations (Python's ssl module):
  * TLS 1.3 cipher suites cannot be pinned one at a time, so only the
    suite the server negotiates is reported for TLS 1.3.
  * SSLv2 is never testable; SSLv3 / TLS 1.0 / 1.1 are only testable if the
    local OpenSSL build still supports them (reported as "untested" otherwise).

Only scan hosts you own or are authorized to test.
"""

import argparse
import datetime as dt
import errno
import ipaddress
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.x509.oid import NameOID
    HAVE_CRYPTO = True
except ImportError:  # certificate details fall back to the stdlib decoder
    HAVE_CRYPTO = False

ALL_CIPHERS = "ALL:COMPLEMENTOFALL:@SECLEVEL=0"

PROTOCOLS = [
    ("SSLv3", ssl.TLSVersion.SSLv3),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

KX_LABEL = {"kx-ecdhe": "ECDHE", "kx-dhe": "DHE", "kx-rsa": "RSA", "kx-any": "any",
            "kx-psk": "PSK", "kx-ecdhe-psk": "ECDHE-PSK", "kx-dhe-psk": "DHE-PSK",
            "kx-rsa-psk": "RSA-PSK", "kx-srp": "SRP"}
WEAK_TOKENS = ("NULL", "EXP", "RC4", "MD5", "ADH", "AECDH", "DES-CBC3", "3DES", "IDEA", "RC2", "ANON")


# ---------------------------------------------------------------- low level

def _ctx(version=None, ciphers=ALL_CIPHERS):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers(ciphers)
    if version is not None:
        ctx.minimum_version = version
        ctx.maximum_version = version
    return ctx


def local_supports(version):
    """True if the local OpenSSL can even emit a ClientHello for `version`."""
    try:
        obj = _ctx(version).wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO())
        obj.do_handshake()
    except ssl.SSLWantReadError:
        return True
    except (ssl.SSLError, ValueError):
        return False
    return True


def _handshake(ip, port, sni, timeout, ctx):
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            return {
                "version": tls.version(),
                "cipher": tls.cipher(),
                "der": tls.getpeercert(binary_form=True),
                "compression": tls.compression(),
            }


# ---------------------------------------------------------------- friendly errors

UNREACHABLE_ERRNOS = {errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065}  # 1005x = Windows WSAE*


def friendly_error(kind, host, port, timeout=None, detail=""):
    """Plain-language error + what to try next. Returned dict is merged into a scan result."""
    wait = f" within {timeout:g} seconds" if timeout else ""
    messages = {
        "dns": (f'Couldn\'t find the host "{host}".',
                "Check the spelling, or that you're connected to the network/VPN whose DNS knows this name."),
        "timeout": (f"Port {port} on {host} didn't respond{wait}.",
                    f"It is probably closed or blocked by a firewall. Run a Port Scan on {host} to see which ports are open."),
        "refused": (f"{host} refused the connection on port {port}.",
                    f"Nothing is listening on that port. Run a Port Scan on {host} to see which ports are open."),
        "unreachable": (f"Can't reach {host} from this computer.",
                        "There is no network route to it. Check that you're on the right network or VPN."),
        "not_tls": (f"Port {port} on {host} is open, but it didn't answer as SSL/TLS.",
                    "It may be plain HTTP (common on ports 80 and 8080) or another protocol. "
                    "Try port 443 or 8443, or run a Port Scan to find the HTTPS port."),
        "connect": (f"Couldn't connect to {host}:{port}" + (f" ({detail})." if detail else "."),
                    f"Run a Port Scan on {host} to check which ports are reachable."),
    }
    message, hint = messages[kind]
    return {"error": message, "error_kind": kind, "error_hint": hint}


def preflight(host, port, timeout):
    """Resolve + open one TCP connection. Returns (ip, None) or (ip_or_None, friendly_error dict)."""
    try:
        ip = socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError):
        return None, friendly_error("dns", host, port)
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
    except (socket.timeout, TimeoutError):
        return ip, friendly_error("timeout", host, port, timeout)
    except ConnectionRefusedError:
        return ip, friendly_error("refused", host, port)
    except OSError as exc:
        if exc.errno in UNREACHABLE_ERRNOS or getattr(exc, "winerror", None) in UNREACHABLE_ERRNOS:
            return ip, friendly_error("unreachable", host, port)
        return ip, friendly_error("connect", host, port, detail=_error_text(exc))
    return ip, None


def _error_text(exc):
    if isinstance(exc, ssl.SSLError):
        return exc.reason or exc.strerror or str(exc)
    if isinstance(exc, socket.timeout):
        return "timeout"
    return exc.strerror or str(exc)


# ---------------------------------------------------------------- ratings

def rate_cipher(info, protocol):
    """Return (rating, reasons) where rating is strong | medium | weak."""
    name = info["name"].upper()
    reasons = []
    if protocol == "TLSv1.3":
        return "strong", reasons
    bits = info.get("strength_bits") or 0
    if bits < 128:
        reasons.append(f"{bits}-bit encryption")
    for tok in WEAK_TOKENS:
        if tok in name:
            reasons.append(f"{tok} cipher")
    if (info.get("auth") or "") == "auth-null":
        reasons.append("no authentication")
    if reasons:
        return "weak", reasons
    if info.get("kea") == "kx-rsa":
        reasons.append("no forward secrecy")
    if not info.get("aead"):
        reasons.append("CBC mode")
    return ("medium" if reasons else "strong"), reasons


# ---------------------------------------------------------------- certificate

def _cert_with_crypto(der):
    cert = x509.load_der_x509_certificate(der)

    def cn(name):
        vals = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return vals[0].value if vals else name.rfc4514_string()

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = san_ext.get_values_for_type(x509.DNSName) + [str(i) for i in san_ext.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc, key_bits = f"EC {key.curve.name}", key.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_desc, key_bits = "DSA", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_desc, key_bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_desc, key_bits = "Ed448", 456
    else:
        key_desc, key_bits = type(key).__name__, 0

    sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    return {
        "subject": cn(cert.subject),
        "subject_full": cert.subject.rfc4514_string(),
        "issuer": cn(cert.issuer),
        "issuer_full": cert.issuer.rfc4514_string(),
        "sans": sans,
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "serial": format(cert.serial_number, "X"),
        "signature": cert.signature_algorithm_oid._name,
        "signature_hash": sig_hash,
        "key_type": key_desc,
        "key_bits": key_bits,
        "self_signed": cert.issuer == cert.subject,
        "sha256": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    }


def _cert_with_stdlib(der):
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        info = ssl._ssl._test_decode_cert(path)  # private but long-standing helper
    finally:
        os.unlink(path)

    def flat(rdns):
        return {k: v for rdn in rdns for (k, v) in rdn}

    subj, iss = flat(info.get("subject", ())), flat(info.get("issuer", ()))
    parse = lambda s: dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(s), dt.timezone.utc)
    return {
        "subject": subj.get("commonName", str(subj)),
        "subject_full": ", ".join(f"{k}={v}" for k, v in subj.items()),
        "issuer": iss.get("commonName", str(iss)),
        "issuer_full": ", ".join(f"{k}={v}" for k, v in iss.items()),
        "sans": [v for (_, v) in info.get("subjectAltName", ())],
        "not_before": parse(info["notBefore"]),
        "not_after": parse(info["notAfter"]),
        "serial": info.get("serialNumber", ""),
        "signature": "", "signature_hash": "", "key_type": "", "key_bits": 0,
        "self_signed": subj == iss,
        "sha256": "",
    }


def parse_cert(der):
    cert = _cert_with_crypto(der) if HAVE_CRYPTO else _cert_with_stdlib(der)
    now = dt.datetime.now(dt.timezone.utc)
    cert["days_left"] = (cert["not_after"] - now).days
    cert["not_yet_valid"] = cert["not_before"] > now
    cert["not_before"] = cert["not_before"].strftime("%Y-%m-%d %H:%M UTC")
    cert["not_after"] = cert["not_after"].strftime("%Y-%m-%d %H:%M UTC")
    return cert


def verify_chain(ip, port, sni, timeout):
    """Validate the chain + hostname using the OS trust store."""
    ctx = ssl.create_default_context()
    ctx.set_ciphers(ALL_CIPHERS)
    try:
        _handshake(ip, port, sni, timeout, ctx)
        return True, "Certificate chain and hostname verified"
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        return None, f"Could not verify: {_error_text(exc)}"


# ---------------------------------------------------------------- scanner

def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def ssl_scan(host, port=443, sni=None, timeout=5.0, workers=16, progress=None, stop=None):
    """Run the scan. `progress(done, total, message)` and `stop` (Event) are optional."""
    stop = stop or threading.Event()
    report = lambda d, t, m: progress and progress(d, t, m)

    host = host.strip()
    sni = (sni or "").strip() or (None if _is_ip(host) else host)
    result = {"host": host, "port": port, "sni": sni, "ip": None, "protocols": [], "ciphers": [],
              "certificate": None, "verify": None, "compression": None, "findings": [], "error": None,
              "notes": []}

    report(0, 1, f"Connecting to {host}:{port}")
    ip, err = preflight(host, port, timeout)
    result["ip"] = ip
    if err:
        result.update(err)
        return result

    # 1. protocol support
    enabled, first = [], None
    for i, (label, ver) in enumerate(PROTOCOLS):
        if stop.is_set():
            break
        report(i, len(PROTOCOLS), f"Testing {label}")
        entry = {"name": label, "status": "disabled", "cipher": None, "detail": ""}
        if not local_supports(ver):
            entry.update(status="untested", detail="not supported by local OpenSSL")
        else:
            try:
                hs = _handshake(ip, port, sni, timeout, _ctx(ver))
                entry.update(status="enabled", cipher=hs["cipher"][0])
                enabled.append(label)
                if first is None or label == "TLSv1.3" or label == "TLSv1.2":
                    first = hs
            except (OSError, ssl.SSLError) as exc:
                entry["detail"] = _error_text(exc)
        result["protocols"].append(entry)

    if not enabled:
        result.update(friendly_error("not_tls", host, port))
        return result

    # 2. cipher enumeration (pre TLS 1.3)
    catalog = [c for c in _ctx().get_ciphers()
               if c["protocol"] != "TLSv1.3" and "PSK" not in c["name"] and "SRP" not in c["name"]]
    jobs = []
    for label, ver in PROTOCOLS:
        if label not in enabled or label == "TLSv1.3":
            continue
        for c in catalog:
            if label in ("SSLv3", "TLSv1.0", "TLSv1.1") and c["protocol"] == "TLSv1.2":
                continue  # TLS 1.2-only suites
            jobs.append((label, ver, c))

    total = len(jobs) + 2
    done = [0]
    lock = threading.Lock()

    def try_cipher(job):
        label, ver, info = job
        hit = None
        if not stop.is_set():
            try:
                ctx = _ctx(ver, info["name"] + ":@SECLEVEL=0")
                hs = _handshake(ip, port, sni, timeout, ctx)
                hit = hs["cipher"]
            except (OSError, ssl.SSLError, ValueError):
                hit = None
        with lock:
            done[0] += 1
            if done[0] % 10 == 0:
                report(done[0], total, f"Enumerating ciphers ({done[0]}/{len(jobs)})")
        return job, hit

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for (label, _, info), hit in pool.map(try_cipher, jobs):
            if hit:
                rating, reasons = rate_cipher(info, label)
                result["ciphers"].append({
                    "protocol": label, "name": info["name"], "bits": hit[2] or info.get("strength_bits"),
                    "kx": KX_LABEL.get(info.get("kea"), info.get("kea") or ""),
                    "aead": bool(info.get("aead")), "rating": rating, "reasons": reasons,
                })

    for p in result["protocols"]:
        if p["name"] == "TLSv1.3" and p["status"] == "enabled":
            info = next((c for c in _ctx().get_ciphers() if c["name"] == p["cipher"]), {"name": p["cipher"]})
            result["ciphers"].append({"protocol": "TLSv1.3", "name": p["cipher"],
                                      "bits": info.get("strength_bits"), "kx": "any", "aead": True,
                                      "rating": "strong", "reasons": [], "negotiated_only": True})
            result["notes"].append("TLS 1.3: only the negotiated suite is shown (Python cannot pin TLS 1.3 suites).")

    order = {name: i for i, (name, _) in enumerate(PROTOCOLS)}
    result["ciphers"].sort(key=lambda c: (-order[c["protocol"]], -(c["bits"] or 0), c["name"]))

    # 3. certificate + trust
    report(total - 2, total, "Checking certificate")
    if first and first["der"]:
        try:
            result["certificate"] = parse_cert(first["der"])
        except Exception as exc:  # malformed certs should not kill the scan
            result["notes"].append(f"Could not parse certificate: {exc}")
    result["compression"] = first["compression"] if first else None
    ok, msg = verify_chain(ip, port, sni or host, timeout)
    result["verify"] = {"ok": ok, "message": msg}

    for p in result["protocols"]:
        if p["status"] == "untested":
            result["notes"].append(f"{p['name']} could not be tested ({p['detail']}).")

    result["findings"] = build_findings(result)
    report(total, total, "Done")
    return result


def build_findings(r):
    f = []
    add = lambda sev, text: f.append({"severity": sev, "text": text})
    status = {p["name"]: p["status"] for p in r["protocols"]}

    if status.get("SSLv3") == "enabled":
        add("high", "SSLv3 is enabled (POODLE). Disable it.")
    for old in ("TLSv1.0", "TLSv1.1"):
        if status.get(old) == "enabled":
            add("medium", f"{old} is enabled (deprecated by RFC 8996).")
    if status.get("TLSv1.3") != "enabled":
        add("low", "TLS 1.3 is not supported.")

    weak = [c for c in r["ciphers"] if c["rating"] == "weak"]
    if weak:
        names = ", ".join(sorted({c["name"] for c in weak})[:6])
        add("high", f"{len(weak)} weak cipher suite(s) accepted: {names}{'...' if len(weak) > 6 else ''}")
    nofs = {c["name"] for c in r["ciphers"] if "no forward secrecy" in c["reasons"]}
    if nofs:
        add("medium", f"{len(nofs)} cipher suite(s) without forward secrecy (static RSA key exchange).")
    cbc = {c["name"] for c in r["ciphers"] if c["rating"] != "weak" and "CBC mode" in c["reasons"]}
    if cbc:
        add("low", f"{len(cbc)} CBC-mode cipher suite(s) accepted.")

    cert = r["certificate"]
    if cert:
        if cert["days_left"] < 0:
            add("high", f"Certificate expired {-cert['days_left']} day(s) ago ({cert['not_after']}).")
        elif cert["days_left"] < 30:
            add("medium", f"Certificate expires in {cert['days_left']} day(s).")
        if cert["not_yet_valid"]:
            add("high", f"Certificate is not valid until {cert['not_before']}.")
        if cert["self_signed"]:
            add("medium", "Certificate is self-signed.")
        if cert["key_type"] == "RSA" and cert["key_bits"] and cert["key_bits"] < 2048:
            add("high", f"Weak RSA key: {cert['key_bits']} bits.")
        if cert["signature_hash"] in ("md5", "sha1"):
            add("high", f"Certificate signed with {cert['signature_hash'].upper()}.")

    v = r["verify"]
    if v and v["ok"] is False:
        add("high", f"Certificate not trusted: {v['message']}")
    if r["compression"]:
        add("medium", f"TLS compression enabled ({r['compression']}) - CRIME.")

    if not f:
        add("info", "No issues found.")
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    f.sort(key=lambda x: order[x["severity"]])
    return f


# ---------------------------------------------------------------- CLI

def _split_target(target, default_port):
    if target.startswith("["):  # [ipv6]:port
        host, _, rest = target[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if target.count(":") == 1:
        host, port = target.split(":")
        return host, int(port)
    return target, default_port


def _print_report(r):
    try:
        from termcolor import colored
    except ImportError:
        colored = lambda t, *a, **k: t
    col = {"strong": "green", "medium": "yellow", "weak": "red",
           "high": "red", "low": "cyan", "info": "white", "enabled": "green", "disabled": "white", "untested": "yellow"}

    print(f"\nTarget: {r['host']}:{r['port']}  IP: {r['ip']}  SNI: {r['sni'] or '-'}")
    if r["error"]:
        print(colored(f"[-] {r['error']}", "red"))
        return
    print("\nProtocols:")
    for p in r["protocols"]:
        print(f"  {p['name']:<8} " + colored(p["status"], col[p["status"]]))
    print("\nAccepted ciphers:")
    for c in r["ciphers"]:
        print(f"  {c['protocol']:<8} {str(c['bits']):>4} bits  {c['kx']:<6} "
              + colored(f"{c['name']:<40}", col[c["rating"]]) + (" " + ", ".join(c["reasons"]) if c["reasons"] else ""))
    cert = r["certificate"]
    if cert:
        print("\nCertificate:")
        print(f"  Subject : {cert['subject']}")
        print(f"  SANs    : {', '.join(cert['sans'][:10]) or '-'}")
        print(f"  Issuer  : {cert['issuer']}")
        print(f"  Valid   : {cert['not_before']} -> {cert['not_after']} ({cert['days_left']} days left)")
        if cert["key_type"]:
            print(f"  Key     : {cert['key_type']} {cert['key_bits']} bits, signed {cert['signature']}")
    v = r["verify"]
    print(f"  Trust   : " + colored(v["message"], "green" if v["ok"] else "red"))
    print("\nFindings:")
    for item in r["findings"]:
        print("  " + colored(f"[{item['severity'].upper():<6}]", col[item["severity"]]) + " " + item["text"])
    for n in r["notes"]:
        print(f"  note: {n}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Netra SSL/TLS scanner")
    ap.add_argument("target", help="host, host:port or [ipv6]:port")
    ap.add_argument("-p", "--port", type=int, default=443)
    ap.add_argument("--sni", help="SNI hostname (default: target host)")
    ap.add_argument("-t", "--timeout", type=float, default=5.0)
    ap.add_argument("-w", "--workers", type=int, default=16)
    ap.add_argument("--json", action="store_true", help="print raw JSON")
    args = ap.parse_args(argv)

    host, port = _split_target(args.target, args.port)
    progress = None if args.json else (lambda d, t, m: print(f"\r[*] {m:<50}", end="", flush=True))
    result = ssl_scan(host, port, args.sni, args.timeout, args.workers, progress)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("\r" + " " * 60, end="")
        _print_report(result)
    return 1 if result["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
