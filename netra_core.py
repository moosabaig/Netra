"""Netra scanning core shared by the CLI (portscanner.py) and GUI (netra_gui.py)."""

import socket


def parse_targets(text):
    """Split comma/space separated targets, drop blanks and duplicates."""
    seen, out = set(), []
    for raw in text.replace(" ", ",").split(","):
        t = raw.strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def parse_ports(text):
    """Parse '1-1024', '22,80,443', or a mix like '20-25,80,8000-8100'."""
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Port out of range 1-65535: {bad[0]}")
    return sorted(ports)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def scan_port(ip, port, timeout):
    """Return True when a TCP connection to ip:port succeeds."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port)) == 0
