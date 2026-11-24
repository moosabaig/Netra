"""Netra CLI port scanner (TCP connect scan).

Examples:
    python portscanner.py                                  # interactive prompts
    python portscanner.py 127.0.0.1 -p 1-1024
    python portscanner.py 10.0.0.5,example.com -p 22,80,443 -t 1 -w 300

Only scan hosts you own or are authorized to test.
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from netra_core import parse_ports, parse_targets, scan_port, service_name

try:
    from termcolor import colored
except ImportError:  # termcolor is optional
    def colored(text, *_args, **_kwargs):
        return text


def scan(host, ports, timeout, workers):
    """Scan one host; return a sorted list of open ports."""
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        print(colored(f"[-] Cannot resolve {host}: {exc}", "red"))
        return []

    print(colored(f"\n[*] Starting scan for {host} ({ip}) - {len(ports)} port(s)", "cyan"))
    start = time.time()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = pool.map(lambda p: (p, scan_port(ip, p, timeout)), ports)
        open_ports = []
        for port, is_open in results:
            if is_open:
                open_ports.append(port)
                svc = service_name(port)
                print(colored(f"[+] Port {port:>5} open  {svc}", "green"))
    print(f"[*] {host}: {len(open_ports)} open, {time.time() - start:.1f}s")
    return open_ports


def main(argv=None):
    ap = argparse.ArgumentParser(description="Netra TCP connect port scanner")
    ap.add_argument("targets", nargs="?", help="comma separated hosts/IPs")
    ap.add_argument("-p", "--ports", help="ports, e.g. 1-1024 or 22,80,443 (default 1-1024)")
    ap.add_argument("-t", "--timeout", type=float, default=0.5, help="seconds per port (default 0.5)")
    ap.add_argument("-w", "--workers", type=int, default=200, help="parallel connections (default 200)")
    args = ap.parse_args(argv)

    targets_text = args.targets or input("[*] Enter targets to scan (split them by ,): ")
    ports_text = args.ports
    if ports_text is None:
        ports_text = input("[*] Enter ports (e.g. 1-1024 or 22,80) [1-1024]: ").strip() or "1-1024"
        if ports_text.isdigit():  # old behaviour: a single number N means ports 1..N
            ports_text = f"1-{ports_text}"

    targets = parse_targets(targets_text)
    try:
        ports = parse_ports(ports_text)
    except ValueError as exc:
        ap.error(str(exc))
    if not targets or not ports:
        ap.error("need at least one target and one port")

    if len(targets) > 1:
        print(colored("[*] Scanning multiple targets", "green"))
    try:
        for host in targets:
            scan(host, ports, args.timeout, args.workers)
    except KeyboardInterrupt:
        print(colored("\n[!] Interrupted", "yellow"))
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
