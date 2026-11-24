"""Netra - desktop GUI for the TCP connect port scanner.

Run:  python netra_gui.py
Only uses the Python standard library (tkinter, socket, threading).
"""

import csv
import queue
import socket
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import filedialog, messagebox, ttk

from netra_core import parse_ports, parse_targets, scan_port, service_name


# ---------------------------------------------------------------- GUI

PRESETS = {
    "Common (top 20)": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
    "Well-known (1-1024)": "1-1024",
    "Web": "80,443,8000,8008,8080,8443,8888",
    "All (1-65535)": "1-65535",
}


class NetraApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Netra Port Scanner")
        self.geometry("860x620")
        self.minsize(720, 520)

        self.events = queue.Queue()
        self.stop_flag = threading.Event()
        self.worker = None
        self.total = 0
        self.done = 0
        self.open_count = 0
        self.started = 0.0

        self._build_style()
        self._build_widgets()
        self.after(100, self._drain_events)

    # -- layout ---------------------------------------------------------------

    def _build_style(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Stat.TLabel", font=("Segoe UI", 10))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))

    def _build_widgets(self):
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)

        ttk.Label(root, text="Netra Port Scanner", style="Title.TLabel").pack(anchor="w")
        ttk.Label(root, text="TCP connect scan. Only scan hosts you own or are authorized to test.",
                  foreground="#a33").pack(anchor="w", pady=(0, 8))

        # settings
        cfg = ttk.LabelFrame(root, text="Scan settings", padding=10)
        cfg.pack(fill="x")
        cfg.columnconfigure(1, weight=1)

        ttk.Label(cfg, text="Targets").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        self.targets_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(cfg, textvariable=self.targets_var).grid(row=0, column=1, columnspan=3, sticky="ew", pady=3)

        ttk.Label(cfg, text="Ports").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=3)
        self.ports_var = tk.StringVar(value="1-1024")
        ttk.Entry(cfg, textvariable=self.ports_var).grid(row=1, column=1, sticky="ew", pady=3)
        self.preset_var = tk.StringVar(value="Preset...")
        preset = ttk.Combobox(cfg, textvariable=self.preset_var, values=list(PRESETS),
                              state="readonly", width=20)
        preset.grid(row=1, column=2, columnspan=2, sticky="e", padx=(8, 0), pady=3)
        preset.bind("<<ComboboxSelected>>", lambda e: self.ports_var.set(PRESETS[self.preset_var.get()]))

        opts = ttk.Frame(cfg)
        opts.grid(row=2, column=0, columnspan=4, sticky="w", pady=(6, 0))
        ttk.Label(opts, text="Timeout (s)").pack(side="left")
        self.timeout_var = tk.DoubleVar(value=0.5)
        ttk.Spinbox(opts, from_=0.1, to=10, increment=0.1, textvariable=self.timeout_var,
                    width=6).pack(side="left", padx=(4, 16))
        ttk.Label(opts, text="Threads").pack(side="left")
        self.threads_var = tk.IntVar(value=200)
        ttk.Spinbox(opts, from_=1, to=1000, increment=10, textvariable=self.threads_var,
                    width=6).pack(side="left", padx=(4, 16))

        # controls
        bar = ttk.Frame(root)
        bar.pack(fill="x", pady=10)
        self.start_btn = ttk.Button(bar, text="Start scan", style="Accent.TButton", command=self.start_scan)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(bar, text="Clear", command=self.clear_results).pack(side="left")
        ttk.Button(bar, text="Export CSV", command=self.export_csv).pack(side="right")

        self.progress = ttk.Progressbar(root, mode="determinate")
        self.progress.pack(fill="x")
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(root, textvariable=self.status_var, style="Stat.TLabel").pack(anchor="w", pady=(4, 8))

        # results + log
        panes = ttk.PanedWindow(root, orient="vertical")
        panes.pack(fill="both", expand=True)

        table_frame = ttk.LabelFrame(panes, text="Open ports", padding=4)
        cols = ("host", "ip", "port", "service")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=10)
        for col, width in zip(cols, (220, 140, 80, 160)):
            self.tree.heading(col, text=col.title(), command=lambda c=col: self._sort_by(c, False))
            self.tree.column(col, width=width, anchor="w")
        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        panes.add(table_frame, weight=3)

        log_frame = ttk.LabelFrame(panes, text="Log", padding=4)
        self.log = tk.Text(log_frame, height=6, wrap="word", state="disabled",
                           font=("Consolas", 9), background="#111", foreground="#ddd")
        self.log.tag_configure("ok", foreground="#6c6")
        self.log.tag_configure("err", foreground="#f66")
        self.log.tag_configure("info", foreground="#8bf")
        self.log.pack(fill="both", expand=True)
        panes.add(log_frame, weight=1)

    # -- actions --------------------------------------------------------------

    def start_scan(self):
        targets = parse_targets(self.targets_var.get())
        if not targets:
            messagebox.showerror("Netra", "Enter at least one target.")
            return
        try:
            ports = parse_ports(self.ports_var.get())
            timeout = float(self.timeout_var.get())
            threads = int(self.threads_var.get())
        except (ValueError, tk.TclError) as exc:
            messagebox.showerror("Netra", f"Invalid settings: {exc}")
            return
        if not ports:
            messagebox.showerror("Netra", "Enter at least one port.")
            return

        self.stop_flag.clear()
        self.total = len(targets) * len(ports)
        self.done = 0
        self.open_count = 0
        self.started = time.time()
        self.progress.configure(maximum=self.total, value=0)
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._log(f"Scanning {len(targets)} target(s), {len(ports)} port(s) each", "info")

        self.worker = threading.Thread(target=self._run, args=(targets, ports, timeout, threads), daemon=True)
        self.worker.start()

    def stop_scan(self):
        self.stop_flag.set()
        self.status_var.set("Stopping...")

    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self.progress.configure(value=0)
        if not (self.worker and self.worker.is_alive()):
            self.status_var.set("Idle")

    def export_csv(self):
        rows = [self.tree.item(i, "values") for i in self.tree.get_children()]
        if not rows:
            messagebox.showinfo("Netra", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile="netra_results.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["host", "ip", "port", "service"])
            writer.writerows(rows)
        self._log(f"Exported {len(rows)} row(s) to {path}", "info")

    # -- background worker ----------------------------------------------------

    def _run(self, targets, ports, timeout, threads):
        with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
            for host in targets:
                if self.stop_flag.is_set():
                    break
                try:
                    ip = socket.gethostbyname(host)
                except socket.gaierror as exc:
                    self.events.put(("log", f"[-] Cannot resolve {host}: {exc}", "err"))
                    self.events.put(("skip", len(ports)))
                    continue
                self.events.put(("log", f"[*] Starting scan for {host} ({ip})", "info"))

                def task(port, host=host, ip=ip):
                    if self.stop_flag.is_set():
                        self.events.put(("tick",))
                        return
                    try:
                        if scan_port(ip, port, timeout):
                            self.events.put(("open", host, ip, port, service_name(port)))
                    except OSError as exc:
                        self.events.put(("log", f"[-] {ip}:{port} error: {exc}", "err"))
                    self.events.put(("tick",))

                list(pool.map(task, ports))
        self.events.put(("finished",))

    # -- UI event pump --------------------------------------------------------

    def _drain_events(self):
        try:
            for _ in range(2000):
                ev = self.events.get_nowait()
                kind = ev[0]
                if kind == "tick":
                    self.done += 1
                elif kind == "skip":
                    self.done += ev[1]
                elif kind == "open":
                    _, host, ip, port, svc = ev
                    self.open_count += 1
                    self.tree.insert("", "end", values=(host, ip, port, svc))
                    self._log(f"[+] {host}:{port} open {svc}", "ok")
                elif kind == "log":
                    self._log(ev[1], ev[2])
                elif kind == "finished":
                    self._on_finished()
        except queue.Empty:
            pass

        if self.worker and self.worker.is_alive():
            self.progress.configure(value=self.done)
            elapsed = time.time() - self.started
            self.status_var.set(f"Scanned {self.done}/{self.total}  |  open: {self.open_count}  |  {elapsed:.1f}s")
        self.after(100, self._drain_events)

    def _on_finished(self):
        elapsed = time.time() - self.started
        stopped = self.stop_flag.is_set()
        self.progress.configure(value=self.done)
        word = "Stopped" if stopped else "Done"
        self.status_var.set(f"{word}: {self.done}/{self.total} checked, {self.open_count} open, {elapsed:.1f}s")
        self._log(f"[*] {word} in {elapsed:.1f}s", "info")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    # -- helpers --------------------------------------------------------------

    def _log(self, msg, tag="info"):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _sort_by(self, col, desc):
        rows = [(self.tree.set(i, col), i) for i in self.tree.get_children("")]
        key = (lambda r: int(r[0])) if col == "port" else (lambda r: r[0])
        rows.sort(key=key, reverse=desc)
        for idx, (_, item) in enumerate(rows):
            self.tree.move(item, "", idx)
        self.tree.heading(col, command=lambda: self._sort_by(col, not desc))


if __name__ == "__main__":
    NetraApp().mainloop()
