"""PDF reports for Netra port scans and SSL/TLS scans (uses fpdf2: pip install fpdf2)."""

import datetime as dt

from fpdf import FPDF, FontFace
from fpdf.enums import XPos, YPos

ACCENT = (47, 129, 247)
DARK = (31, 35, 40)
MUTED = (89, 99, 110)
LINE = (208, 215, 222)
HEAD_BG = (240, 243, 246)
COLORS = {
    "high": (207, 34, 46), "weak": (207, 34, 46),
    "medium": (154, 103, 0),
    "low": (9, 105, 218),
    "info": MUTED, "disabled": MUTED, "untested": MUTED,
    "strong": (26, 127, 55), "ok": (26, 127, 55),
}
PROTO_TONE = {"SSLv3": "high", "TLSv1.0": "medium", "TLSv1.1": "medium", "TLSv1.2": "ok", "TLSv1.3": "ok"}


def _t(value):
    """Core PDF fonts are Latin-1 only; replace anything else."""
    text = "" if value is None else str(value)
    text = text.replace("—", "-").replace("–", "-").replace("→", "->")
    return text.encode("latin-1", "replace").decode("latin-1")


class Report(FPDF):
    def __init__(self, title, subtitle):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.title_text, self.subtitle = title, subtitle
        self.generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
        self.set_auto_page_break(True, margin=18)
        self.set_margins(15, 15, 15)
        self.set_title(title)
        self.set_creator("Netra Scanner")
        self.add_page()

    def header(self):
        self.set_fill_color(*ACCENT)
        self.rect(0, 0, self.w, 3, "F")
        if self.page_no() == 1:
            self.set_y(12)
            self.set_font("Helvetica", "B", 20)
            self.set_text_color(*DARK)
            self.cell(0, 9, _t(self.title_text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_font("Helvetica", "", 10)
            self.set_text_color(*MUTED)
            self.cell(0, 6, _t(f"{self.subtitle}   |   Generated {self.generated}"),
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(4)
        else:
            self.set_y(10)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 5, "Netra Scanner - only scan hosts you own or are authorized to test.")
        self.cell(0, 5, f"Page {self.page_no()}/{{nb}}", align="R")

    # -- building blocks ------------------------------------------------------

    def section(self, text):
        if self.get_y() > self.h - 40:
            self.add_page()
        self.ln(3)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*DARK)
        self.cell(0, 8, _t(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*LINE)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)

    def stats(self, items):
        """Row of big-number boxes: [(label, value), ...]."""
        width = (self.w - self.l_margin - self.r_margin) / len(items)
        y = self.get_y()
        for i, (label, value) in enumerate(items):
            x = self.l_margin + i * width
            self.set_draw_color(*LINE)
            self.rect(x + 1, y, width - 2, 18)
            self.set_xy(x + 1, y + 2)
            self.set_font("Helvetica", "B", 14)
            self.set_text_color(*DARK)
            self.cell(width - 2, 7, _t(value), align="C")
            self.set_xy(x + 1, y + 10)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*MUTED)
            self.cell(width - 2, 5, _t(label.upper()), align="C")
        self.set_xy(self.l_margin, y + 22)

    def kv(self, rows):
        self.set_font("Helvetica", "", 9.5)
        self.set_text_color(*DARK)
        with self.table(col_widths=(35, 145), first_row_as_headings=False, borders_layout="HORIZONTAL_LINES",
                        line_height=5.5, padding=1.5) as table:
            for key, value, tone in rows:
                row = table.row()
                row.cell(_t(key), style=FontFace(emphasis="B", color=MUTED))
                row.cell(_t(value), style=FontFace(color=COLORS.get(tone, DARK)) if tone else None)

    def grid(self, headings, rows, widths, tone_col=None):
        """Table; rows are lists of (text, tone-or-None)."""
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*DARK)
        head = FontFace(emphasis="B", color=MUTED, fill_color=HEAD_BG)
        with self.table(col_widths=widths, headings_style=head, borders_layout="HORIZONTAL_LINES",
                        line_height=5, padding=1.5) as table:
            hr = table.row()
            for h in headings:
                hr.cell(_t(h))
            for r in rows:
                row = table.row()
                for text, tone in r:
                    style = FontFace(color=COLORS[tone], emphasis="B") if tone in COLORS else None
                    row.cell(_t(text), style=style)

    def para(self, text, size=9, color=MUTED):
        self.set_font("Helvetica", "", size)
        self.set_text_color(*color)
        self.multi_cell(0, 4.5, _t(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _ports_summary(ports):
    if not ports:
        return "-"
    if ports == list(range(ports[0], ports[-1] + 1)):
        return f"{ports[0]}-{ports[-1]} ({len(ports)} ports)"
    shown = ", ".join(map(str, ports[:15]))
    return f"{shown}{', ...' if len(ports) > 15 else ''} ({len(ports)} ports)"


def port_scan_pdf(job):
    """`job` is a netra_web.Job."""
    snap = job.snapshot(0, 0)
    state = "Stopped" if snap["stopped"] else ("Completed" if snap["finished"] else "In progress (partial)")
    pdf = Report("Port Scan Report", ", ".join(job.targets)[:90])

    pdf.stats([("Targets", len(job.targets)), ("Ports checked", f"{snap['done']:,}"),
               ("Open ports", snap["open_count"]), ("Duration", f"{snap['elapsed']}s")])

    pdf.section("Scan details")
    pdf.kv([
        ("Targets", ", ".join(job.targets), None),
        ("Ports", _ports_summary(job.ports), None),
        ("Status", state, "ok" if snap["finished"] and not snap["stopped"] else "medium"),
        ("Started", dt.datetime.fromtimestamp(job.started).strftime("%Y-%m-%d %H:%M:%S"), None),
        ("Timeout", f"{job.timeout}s per port, {job.workers} threads", None),
    ])

    pdf.section(f"Open ports ({snap['open_count']})")
    rows = sorted(snap["open"], key=lambda r: (r["host"], r["port"]))
    if rows:
        pdf.grid(["Host", "IP", "Port", "Service"],
                 [[(r["host"], None), (r["ip"], None), (r["port"], "ok"), (r["service"] or "-", None)] for r in rows],
                 (60, 45, 25, 50))
    else:
        pdf.para("No open ports were found.")

    errors = [text for level, text in snap["log"] if level == "err"]
    if errors:
        pdf.section("Errors")
        for e in errors[:50]:
            pdf.para("- " + e, color=COLORS["high"])
    return bytes(pdf.output())


def ssl_scan_pdf(r):
    """`r` is the dict returned by netra_ssl.ssl_scan."""
    pdf = Report("SSL/TLS Scan Report", f"{r['host']}:{r['port']}")

    counts = {s: sum(1 for f in r["findings"] if f["severity"] == s) for s in ("high", "medium", "low")}
    enabled = [p["name"] for p in r["protocols"] if p["status"] == "enabled"]
    pdf.stats([("High", counts["high"]), ("Medium", counts["medium"]), ("Low", counts["low"]),
               ("Cipher suites", len(r["ciphers"]))])

    engine = {"builtin": "Netra built-in", "sslscan": "sslscan", "testssl": "testssl.sh"}.get(
        r.get("engine") or "builtin", r.get("engine"))
    pdf.section("Target")
    rows = [
        ("Host", f"{r['host']}:{r['port']}", None),
        ("IP address", r.get("ip") or "-", None),
        ("SNI", r.get("sni") or "-", None),
        ("Protocols", ", ".join(enabled) or "-", None),
        ("Scan engine", engine, None),
    ]
    if r.get("grade"):
        g = r["grade"]
        rows.append(("testssl.sh grade", g, "ok" if g.startswith("A") else "medium" if g[:1] in "BC" else "high"))
    pdf.kv(rows)

    pdf.section("Findings")
    pdf.grid(["Severity", "Finding"],
             [[(f["severity"].upper(), f["severity"]), (f["text"], None)] for f in r["findings"]],
             (25, 155))
    if r.get("notes"):
        pdf.ln(2)
        for n in r["notes"]:
            pdf.para("Note: " + n)

    pdf.section("Protocols")
    rows = []
    for p in r["protocols"]:
        tone = PROTO_TONE.get(p["name"]) if p["status"] == "enabled" else p["status"]
        rows.append([(p["name"], None), (p["status"], tone), (p.get("cipher") or p.get("detail") or "-", None)])
    pdf.grid(["Protocol", "Status", "Negotiated cipher / detail"], rows, (30, 30, 120))

    pdf.section(f"Accepted cipher suites ({len(r['ciphers'])})")
    if r["ciphers"]:
        pdf.grid(["Protocol", "Cipher", "Bits", "Kx", "Rating", "Notes"],
                 [[(c["protocol"], None), (c["name"] + (" *" if c.get("negotiated_only") else ""), None),
                   (c["bits"] if c["bits"] is not None else "-", None), (c["kx"] or "-", None),
                   (c["rating"], c["rating"]), (", ".join(c["reasons"]) or "-", None)] for c in r["ciphers"]],
                 (17, 65, 10, 23, 17, 48))
        if any(c.get("negotiated_only") for c in r["ciphers"]):
            pdf.para("* TLS 1.3: only the negotiated suite is shown.")
    else:
        pdf.para("No cipher suites accepted.")

    if r.get("checks"):
        pdf.section("Vulnerability checks")
        pdf.grid(["Check", "Result", "Detail"],
                 [[(c["name"], None),
                   ("OK" if c["severity"] == "ok" else c["severity"].upper(), c["severity"]),
                   (c.get("finding") or "-", None)] for c in r["checks"]],
                 (55, 20, 105))

    pdf.section("Certificate")
    c = r.get("certificate")
    rows = []
    if c:
        days = c["days_left"]
        rows += [
            ("Subject", c.get("subject_full") or c["subject"], None),
            ("Alt names", ", ".join(c["sans"]) or "-", None),
            ("Issuer", c.get("issuer_full") or c["issuer"], None),
            ("Valid from", c["not_before"], None),
            ("Valid until", f"{c['not_after']} ({days} days left)", "high" if days < 0 else "medium" if days < 30 else None),
        ]
        if c.get("key_type"):
            rows.append(("Public key", f"{c['key_type']}, {c['key_bits']} bits", None))
        if c.get("signature"):
            rows.append(("Signature", c["signature"], None))
        rows.append(("Self-signed", "yes" if c["self_signed"] else "no", "medium" if c["self_signed"] else None))
        rows.append(("Serial", c["serial"], None))
        if c.get("sha256"):
            rows.append(("SHA-256", c["sha256"], None))
    else:
        rows.append(("Certificate", "Not available", None))
    v = r.get("verify") or {}
    if v:
        rows.append(("Trust", v.get("message", ""), "ok" if v.get("ok") else "high" if v.get("ok") is False else None))
    rows.append(("Compression", r.get("compression") or "none", "medium" if r.get("compression") else None))
    pdf.kv(rows)
    return bytes(pdf.output())
